//! TPM2 backend — PCR0-sealed master key via tss-esapi.
//!
//! Security: Tier 1 (hardware). The master key is sealed to the TPM and bound
//! to PCR0 (firmware/BIOS measurement). Unsealing will fail if firmware changes.
//!
//! # Blob format (on-disk at `~/.config/hearth/tpm-sealed.bin`)
//! ```text
//! [ 4 bytes little-endian: public_len ]
//! [ public_len bytes:      marshalled TPM2B_PUBLIC ]
//! [ 4 bytes little-endian: private_len ]
//! [ private_len bytes:     marshalled TPM2B_PRIVATE (opaque) ]
//! ```

use std::{fs, io::Write, path::PathBuf};

use tss_esapi::{
    Context,
    attributes::{ObjectAttributesBuilder, SessionAttributesBuilder},
    constants::SessionType,
    interface_types::{
        algorithm::{HashingAlgorithm, PublicAlgorithm},
        resource_handles::Hierarchy,
        session_handles::PolicySession,
    },
    structures::{
        Digest, KeyedHashScheme, PcrSelectionListBuilder, PcrSlot, PublicBuilder,
        PublicKeyedHashParameters, SensitiveData, SymmetricDefinition,
    },
    tcti_ldr::TctiNameConf,
    traits::{Marshall, UnMarshall},
};
use zeroize::Zeroizing;

use crate::hsm::{HsmError, SecretBackend};

const SEALED_BLOB_PATH: &str = ".config/hearth/tpm-sealed.bin";
const TPM_DEVICE: &str = "/dev/tpmrm0";

/// The TCTI (transmission interface) string used to reach the TPM.
///
/// Defaults to the in-kernel resource manager, `device:/dev/tpmrm0`. Override
/// with `HEARTH_VAULT_TCTI` to point at something else -- notably
/// `swtpm:host=127.0.0.1,port=2321`, which is how tier 1 gets exercised for
/// real in CI, since no hosted runner has a TPM chip. Anything the tss2 loader
/// accepts works: `device:/dev/tpm0`, `mssim:...`, `tabrmd:...`.
///
/// This is a diagnostic/test escape hatch, not a security boundary: an attacker
/// who can set your environment can already do far worse than redirect a TCTI.
fn tcti_conf() -> String {
    match std::env::var("HEARTH_VAULT_TCTI") {
        Ok(s) if !s.trim().is_empty() => s,
        _ => format!("device:{}", TPM_DEVICE),
    }
}

/// Open a TPM2 context (see [`tcti_conf`] for which TPM).
fn open_context() -> tss_esapi::Result<Context> {
    use std::str::FromStr;
    let tcti = TctiNameConf::from_str(&tcti_conf())
        .map_err(|_| tss_esapi::Error::WrapperError(tss_esapi::WrapperErrorKind::InvalidParam))?;
    Context::new(tcti)
}

/// Build the primary storage key template (endorsement hierarchy, RSA-2048 storage parent).
fn primary_template() -> tss_esapi::Result<tss_esapi::structures::Public> {
    use tss_esapi::interface_types::key_bits::RsaKeyBits;
    use tss_esapi::structures::{
        PublicRsaParametersBuilder, RsaExponent, RsaScheme, SymmetricDefinitionObject,
    };

    let obj_attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_no_da(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(obj_attrs)
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_scheme(RsaScheme::Null)
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .with_is_signing_key(false)
                .with_is_decryption_key(true)
                .with_restricted(true)
                .build()?,
        )
        .with_rsa_unique_identifier(tss_esapi::structures::PublicKeyRsa::default())
        .build()
}

/// Build the sealed data object template (keyed hash, Null scheme, PCR0 policy).
fn sealed_template(policy_digest: Digest) -> tss_esapi::Result<tss_esapi::structures::Public> {
    let obj_attrs = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_no_da(true)
        .with_user_with_auth(false)
        // adminWithPolicy required so the PCR policy can authorize unseal
        .with_admin_with_policy(true)
        .build()?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(obj_attrs)
        .with_auth_policy(policy_digest)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(Digest::default())
        .build()
}

/// Compute the expected PCR0 policy digest (trial session — does not touch TPM state).
fn compute_pcr0_policy_digest(ctx: &mut Context) -> tss_esapi::Result<Digest> {
    let trial_session = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_256_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(tss_esapi::Error::WrapperError(
            tss_esapi::WrapperErrorKind::WrongValueFromTpm,
        ))?;

    let pcr_selection = PcrSelectionListBuilder::new()
        .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
        .build()?;

    let policy_session = PolicySession::try_from(trial_session)?;

    // policy_pcr with empty digest means "bind to current PCR0 value"
    ctx.policy_pcr(policy_session, Digest::default(), pcr_selection)?;

    let digest = ctx.policy_get_digest(policy_session)?;
    // flush trial session
    use tss_esapi::handles::SessionHandle;
    ctx.flush_context(SessionHandle::from(trial_session).into())?;
    Ok(digest)
}

/// Serialise (Public, Private) pair to bytes.
fn serialise_blob(
    public: &tss_esapi::structures::Public,
    private: &tss_esapi::structures::Private,
) -> Result<Vec<u8>, HsmError> {
    let pub_bytes = public
        .marshall()
        .map_err(|e| HsmError::SealFailed(format!("marshall public: {e}")))?;
    let priv_bytes: Vec<u8> = private.to_vec();

    let mut blob = Vec::with_capacity(4 + pub_bytes.len() + 4 + priv_bytes.len());
    blob.extend_from_slice(&(pub_bytes.len() as u32).to_le_bytes());
    blob.extend_from_slice(&pub_bytes);
    blob.extend_from_slice(&(priv_bytes.len() as u32).to_le_bytes());
    blob.extend_from_slice(&priv_bytes);
    Ok(blob)
}

/// Deserialise (Public, Private) from bytes.
fn deserialise_blob(
    data: &[u8],
) -> Result<
    (
        tss_esapi::structures::Public,
        tss_esapi::structures::Private,
    ),
    HsmError,
> {
    if data.len() < 8 {
        return Err(HsmError::UnsealFailed("blob too short".into()));
    }
    let pub_len = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if data.len() < 4 + pub_len + 4 {
        return Err(HsmError::UnsealFailed("blob truncated (public)".into()));
    }
    let pub_bytes = &data[4..4 + pub_len];
    let offset2 = 4 + pub_len;
    let priv_len = u32::from_le_bytes(data[offset2..offset2 + 4].try_into().unwrap()) as usize;
    let offset3 = offset2 + 4;
    if data.len() < offset3 + priv_len {
        return Err(HsmError::UnsealFailed("blob truncated (private)".into()));
    }
    let priv_bytes = &data[offset3..offset3 + priv_len];

    let public = tss_esapi::structures::Public::unmarshall(pub_bytes)
        .map_err(|e| HsmError::UnsealFailed(format!("unmarshall public: {e}")))?;
    let private = tss_esapi::structures::Private::try_from(priv_bytes.to_vec())
        .map_err(|e| HsmError::UnsealFailed(format!("deserialise private: {e}")))?;

    Ok((public, private))
}

/// Default path for the sealed blob.
fn blob_path() -> PathBuf {
    dirs_or_home().join(SEALED_BLOB_PATH)
}

/// Resolve home directory without pulling in an extra crate.
fn dirs_or_home() -> PathBuf {
    // Use $HOME; fall back to current dir for tests.
    std::env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("."))
}

/// Write blob with 0600 permissions.
fn write_blob(path: &std::path::Path, data: &[u8]) -> Result<(), HsmError> {
    use std::os::unix::fs::OpenOptionsExt;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    Ok(())
}

// ---------------------------------------------------------------------------

/// Tier-1 TPM2 backend — seals 32-byte master key to PCR0.
pub struct Tpm2Backend;

impl Tpm2Backend {
    pub fn new() -> Self {
        Tpm2Backend
    }

    /// Returns `true` if a TPM context can actually be opened.
    ///
    /// The device-file check is only a fast path for the default TCTI: a
    /// non-default `HEARTH_VAULT_TCTI` (a simulator on a socket, say) has no
    /// `/dev/tpmrm0` to look at, so in that case the open attempt IS the check.
    pub fn is_available() -> bool {
        let default_tcti = std::env::var_os("HEARTH_VAULT_TCTI").is_none();
        if default_tcti && !std::path::Path::new(TPM_DEVICE).exists() {
            return false;
        }
        // Try to open the context; if it fails (e.g. permission denied) we're unavailable.
        open_context().is_ok()
    }
}

impl Default for Tpm2Backend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBackend for Tpm2Backend {
    fn name(&self) -> &'static str {
        "tpm2-pcr0"
    }

    fn tier(&self) -> u8 {
        1
    }

    fn seal(&self, plaintext: &[u8], _label: &str) -> Result<Vec<u8>, HsmError> {
        let mut ctx = open_context().map_err(|e| HsmError::SealFailed(format!("open TPM: {e}")))?;

        // 1. Create primary storage key in endorsement hierarchy.
        let primary_result = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Endorsement,
                    primary_template()?,
                    None,
                    None,
                    None,
                    None,
                )
            })
            .map_err(|e| HsmError::SealFailed(format!("create_primary: {e}")))?;

        let parent_handle = primary_result.key_handle;

        // 2. Compute PCR0 policy digest via trial session.
        let policy_digest = compute_pcr0_policy_digest(&mut ctx)
            .map_err(|e| HsmError::SealFailed(format!("compute policy digest: {e}")))?;

        // 3. Build the sealed data template with that policy.
        let tmpl = sealed_template(policy_digest)
            .map_err(|e| HsmError::SealFailed(format!("sealed_template: {e}")))?;

        // 4. Create the sealed object.
        let sensitive_data = SensitiveData::try_from(plaintext.to_vec())
            .map_err(|e| HsmError::SealFailed(format!("SensitiveData: {e}")))?;

        let create_result = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create(parent_handle, tmpl, None, Some(sensitive_data), None, None)
            })
            .map_err(|e| HsmError::SealFailed(format!("create sealed object: {e}")))?;

        // 5. Serialise and persist.
        let blob = serialise_blob(&create_result.out_public, &create_result.out_private)?;
        let path = blob_path();
        write_blob(&path, &blob)?;

        // 6. Flush the transient primary key handle to avoid leaking TPM slots.
        let _ = ctx.flush_context(parent_handle.into());

        tracing::info!(path = %path.display(), "TPM2: sealed object written");
        Ok(blob)
    }

    fn unseal(&self, blob: &[u8], _label: &str) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        let mut ctx =
            open_context().map_err(|e| HsmError::UnsealFailed(format!("open TPM: {e}")))?;

        let (public, private) = deserialise_blob(blob)?;

        // 1. Re-create primary in endorsement hierarchy (deterministic).
        let primary_result = ctx
            .execute_with_nullauth_session(|ctx| {
                ctx.create_primary(
                    Hierarchy::Endorsement,
                    primary_template()?,
                    None,
                    None,
                    None,
                    None,
                )
            })
            .map_err(|e| HsmError::UnsealFailed(format!("create_primary: {e}")))?;

        let parent_handle = primary_result.key_handle;

        // 2. Load the sealed object.
        let object_handle = ctx
            .execute_with_nullauth_session(|ctx| ctx.load(parent_handle, private, public))
            .map_err(|e| HsmError::UnsealFailed(format!("load sealed object: {e}")))?;

        // 3. Start a policy session and bind it to the current PCR0 value.
        //
        // The session is SALTED with the primary key (first argument). That is
        // load-bearing, not tidiness: the attributes below turn on response
        // parameter encryption, and an unsalted, unbound session has no shared
        // secret to derive a session key from. The TPM still reports success in
        // that case and hands back a buffer of exactly the right length holding
        // bytes that decrypt to nothing -- different garbage on every call,
        // since the session nonce changes. Silent, and it looks for all the
        // world like the sealed secret rotated itself.
        let policy_session_handle = ctx
            .start_auth_session(
                Some(parent_handle),
                None,
                None,
                SessionType::Policy,
                SymmetricDefinition::AES_256_CFB,
                HashingAlgorithm::Sha256,
            )
            .map_err(|e| HsmError::UnsealFailed(format!("start_auth_session: {e}")))?
            .ok_or_else(|| HsmError::UnsealFailed("null policy session".into()))?;

        let (sess_attrs, sess_attrs_mask) = SessionAttributesBuilder::new()
            .with_decrypt(true)
            .with_encrypt(true)
            .build();
        ctx.tr_sess_set_attributes(policy_session_handle, sess_attrs, sess_attrs_mask)
            .map_err(|e| HsmError::UnsealFailed(format!("tr_sess_set_attributes: {e}")))?;

        let policy_session = PolicySession::try_from(policy_session_handle)
            .map_err(|e| HsmError::UnsealFailed(format!("PolicySession: {e}")))?;

        let pcr_selection = PcrSelectionListBuilder::new()
            .with_selection(HashingAlgorithm::Sha256, &[PcrSlot::Slot0])
            .build()
            .map_err(|e| HsmError::UnsealFailed(format!("PcrSelectionList: {e}")))?;

        ctx.policy_pcr(policy_session, Digest::default(), pcr_selection)
            .map_err(|e| HsmError::UnsealFailed(format!("policy_pcr: {e}")))?;

        // 4. Unseal under the policy session.
        let sensitive = ctx
            .execute_with_session(Some(policy_session_handle), |ctx| {
                ctx.unseal(object_handle.into())
            })
            .map_err(|e| HsmError::UnsealFailed(format!("unseal: {e}")))?;

        // 5. Flush transient handles to avoid leaking TPM slots.
        let _ = ctx.flush_context(object_handle.into());
        let _ = ctx.flush_context(parent_handle.into());

        Ok(Zeroizing::new(sensitive.to_vec()))
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: `is_available()` must not panic regardless of TPM presence.
    #[test]
    fn test_tpm2_is_available_does_not_panic() {
        let _ = Tpm2Backend::is_available();
    }

    /// Full seal/unseal round-trip.
    ///
    /// Needs a reachable TPM: either `/dev/tpmrm0` (user in the `tss` group) or
    /// a simulator via `HEARTH_VAULT_TCTI` — CI uses swtpm, since no hosted
    /// runner has a TPM chip. Set `HEARTH_VAULT_REQUIRE_TPM2=1` to turn "no TPM
    /// here" from a skip into a failure, so a CI job that was supposed to
    /// exercise tier 1 cannot quietly pass having exercised nothing.
    #[test]
    #[ignore = "requires a TPM or simulator — run with: cargo test --features tpm2 -- --include-ignored --test-threads=1"]
    fn test_tpm2_seal_unseal_roundtrip() {
        if !Tpm2Backend::is_available() {
            assert!(
                std::env::var_os("HEARTH_VAULT_REQUIRE_TPM2").is_none(),
                "HEARTH_VAULT_REQUIRE_TPM2 is set but no TPM is reachable at {} — \
                 tier 1 was NOT exercised",
                tcti_conf(),
            );
            println!("no TPM reachable at {} — skipping", tcti_conf());
            return;
        }

        // Use a temp path so we don't clobber a real deployment blob.
        let dir = tempfile::tempdir().expect("tempdir");
        // Override HOME so blob_path() points inside the temp dir.
        unsafe { std::env::set_var("HOME", dir.path()) };

        let backend = Tpm2Backend::new();
        let plaintext = b"hearth-master-key-32-bytes-here!";
        let blob = backend.seal(plaintext, "test").expect("seal failed");
        let unsealed = backend.unseal(&blob, "test").expect("unseal failed");
        assert_eq!(unsealed.as_slice(), plaintext);
    }
}
