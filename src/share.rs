//! Sharing a subset of a vault with a teammate, without a server.
//!
//! # The shape of the problem
//! Two people need the same staging database password. The ways this usually
//! goes are Slack DM, a shared `.env` in a private repo, or a password
//! manager nobody wires into their shell. All three end with the value
//! sitting somewhere in plaintext that outlives the need for it.
//!
//! # What this does
//! `share` writes a **bundle**: the selected entries, encrypted to one
//! recipient's public identity. The bundle is safe to send over any channel
//! you like — Slack, email, a PR comment — because only the holder of the
//! matching vault can open it. `receive` decrypts it straight into the
//! recipient's own vault, at tiers you chose. At no point does either side
//! print a value.
//!
//! # Identity
//! A vault's identity is an X25519 keypair *derived from its data key*
//! (`VaultStore::share_identity_seed`). Deliberately derived, not stored:
//! there is no second private key to back up, and a vault restored from a
//! backup keeps the same public key, so teammates' saved recipients keep
//! working. `change-passphrase` does not change it (the data key is
//! untouched); `init`-ing a brand new vault does.
//!
//! # What this deliberately is NOT
//! - **Not authenticated as to sender.** The bundle proves only that
//!   whoever made it knew your public key. Anyone can send you a bundle
//!   claiming to be anyone. Confirm the fingerprint out of band before you
//!   `receive`, exactly as you would an SSH host key. Signed bundles are a
//!   reasonable future addition; pretending this already does it would be
//!   worse than saying so.
//! - **Not revocable.** Once a teammate has a value, they have it. Sharing
//!   is a copy, and the only way to un-share is to rotate at the provider.
//! - **Not a sync protocol.** There is no merge, no conflict resolution, no
//!   "team vault". A bundle is a one-time, one-directional copy.
//!
//! # Tiers
//! Tier 4 (sign-only) is never shareable: that tier's whole promise is that
//! the key material never leaves the process, and a bundle is by definition
//! it leaving. `--max-tier` lets the sender hand a teammate a *weaker*
//! capability than they hold themselves — sharing a key you can `exec` with
//! as tier 4 on their side, so they can `sign` with it but never inject it.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::crypto;
use crate::sensitive::SensitiveString;
use crate::store::{TIER_MAX, TIER_SIGN_ONLY};

/// Prefix on every public identity string, so a pasted recipient is
/// self-describing and a typo'd base64 blob fails loudly rather than
/// deriving garbage.
const PUBKEY_PREFIX: &str = "hv1pub";

/// AEAD context. Bound into HKDF so a bundle key cannot be confused with
/// any other key this crate derives.
const SHARE_CONTEXT: &str = "hv1:share:v1";
const SHARE_AAD: &[u8] = b"hv1:share:v1";

/// One credential in transit.
#[derive(Serialize, Deserialize)]
struct SharedEntry {
    key: String,
    value: String,
    tier: u8,
}

#[derive(Serialize, Deserialize)]
struct Payload {
    entries: Vec<SharedEntry>,
    /// Free-text note from the sender, shown by `receive --dry-run`. Never
    /// a place for a value; it exists so "staging creds, rotate after the
    /// migration" travels with the bundle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

/// The on-the-wire bundle. Everything outside `blob` is public metadata.
#[derive(Serialize, Deserialize)]
pub struct Bundle {
    pub version: u8,
    /// b64(32) ephemeral X25519 public key.
    pub epk: String,
    /// Recipient fingerprint, so `receive` can say "this is not for you"
    /// instead of "decryption failed".
    pub to: String,
    /// b64 AEAD ciphertext of `Payload`.
    pub blob: String,
}

/// The X25519 secret for this vault. Zeroized on drop by dalek itself.
fn secret_from_seed(seed: &[u8; 32]) -> StaticSecret {
    StaticSecret::from(*seed)
}

/// This vault's public identity, as a pasteable string.
pub fn public_identity(seed: &[u8; 32]) -> String {
    let public = PublicKey::from(&secret_from_seed(seed));
    format!("{PUBKEY_PREFIX}{}", B64.encode(public.as_bytes()))
}

/// A short, human-comparable fingerprint of a public identity — the thing
/// you read aloud or paste into a channel to confirm you are sharing with
/// the person you think you are.
pub fn fingerprint(identity: &str) -> String {
    let digest = crypto::hash_blake3(identity.as_bytes());
    digest[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn parse_identity(identity: &str) -> anyhow::Result<PublicKey> {
    let encoded = identity.trim().strip_prefix(PUBKEY_PREFIX).ok_or_else(|| {
        anyhow::anyhow!("not a hearth-vault identity (expected it to start with '{PUBKEY_PREFIX}')")
    })?;
    let bytes = B64
        .decode(encoded)
        .map_err(|e| anyhow::anyhow!("malformed identity: {e}"))?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("malformed identity: wrong key length"))?;
    Ok(PublicKey::from(bytes))
}

/// HKDF over the ECDH shared secret, salted with both public keys so a
/// bundle is cryptographically bound to this exact sender/recipient pair.
fn bundle_key(
    shared: &[u8; 32],
    epk: &PublicKey,
    recipient: &PublicKey,
) -> anyhow::Result<Zeroizing<[u8; 32]>> {
    let mut salt = Vec::with_capacity(64);
    salt.extend_from_slice(epk.as_bytes());
    salt.extend_from_slice(recipient.as_bytes());
    let key = crypto::derive_shared_key(shared, &salt, SHARE_CONTEXT)
        .map_err(|e| anyhow::anyhow!("bundle key derivation failed: {e}"))?;
    Ok(Zeroizing::new(key))
}

/// Seal `entries` to `recipient_identity`.
///
/// `max_tier` caps what the recipient receives: an entry held at tier 1 and
/// shared with `--max-tier 3` lands in their vault at tier 3. Tier is only
/// ever raised (made stricter), never lowered, so sharing cannot be used to
/// launder a use-only secret into an exportable one on the far side.
pub fn seal(
    entries: &[(String, SensitiveString, u8)],
    recipient_identity: &str,
    max_tier: Option<u8>,
    note: Option<String>,
) -> anyhow::Result<Bundle> {
    let recipient = parse_identity(recipient_identity)?;

    if let Some(cap) = max_tier
        && (cap == 0 || cap > TIER_MAX)
    {
        anyhow::bail!("invalid --max-tier {cap} — must be 1..={TIER_MAX}");
    }

    let shared_entries: Vec<SharedEntry> = entries
        .iter()
        .filter(|(_, _, tier)| *tier != TIER_SIGN_ONLY)
        .map(|(key, value, tier)| SharedEntry {
            key: key.clone(),
            value: value.as_str().to_string(),
            // max() not min(): the cap makes the recipient's copy stricter.
            tier: max_tier.map_or(*tier, |cap| (*tier).max(cap)),
        })
        .collect();

    if shared_entries.is_empty() {
        anyhow::bail!(
            "nothing to share — no entries matched, or every match was tier {TIER_SIGN_ONLY} \
             (sign-only keys are never shareable: that tier means the key material does not \
              leave the process that holds it)"
        );
    }

    let payload = Payload {
        entries: shared_entries,
        note,
    };
    let plaintext = Zeroizing::new(serde_json::to_vec(&payload)?);

    // An ephemeral sender key per bundle: two bundles to the same recipient
    // share no key material, and the sender's own identity is not revealed
    // by the bundle.
    let esk_bytes: [u8; 32] = crypto::random_bytes();
    let esk = StaticSecret::from(esk_bytes);
    let epk = PublicKey::from(&esk);
    let shared = esk.diffie_hellman(&recipient);
    let key = bundle_key(shared.as_bytes(), &epk, &recipient)?;

    let blob = crypto::encrypt_aes256gcm(&key, &plaintext, SHARE_AAD)
        .map_err(|e| anyhow::anyhow!("failed to seal bundle: {e}"))?;

    Ok(Bundle {
        version: 1,
        epk: B64.encode(epk.as_bytes()),
        to: fingerprint(&format!(
            "{PUBKEY_PREFIX}{}",
            B64.encode(recipient.as_bytes())
        )),
        blob: B64.encode(blob),
    })
}

/// One decrypted entry, ready to be written into the receiving vault.
pub struct OpenedEntry {
    pub key: String,
    pub value: SensitiveString,
    pub tier: u8,
}

/// Open a bundle addressed to the vault identified by `seed`.
pub fn open(
    bundle: &Bundle,
    seed: &[u8; 32],
) -> anyhow::Result<(Vec<OpenedEntry>, Option<String>)> {
    if bundle.version != 1 {
        anyhow::bail!("unsupported bundle version {}", bundle.version);
    }

    let secret = secret_from_seed(seed);
    let our_public = PublicKey::from(&secret);
    let our_identity = public_identity(seed);

    // Checked before decrypting so the common mistake — a bundle meant for
    // someone else — produces an answer instead of an AEAD failure that
    // looks like corruption.
    if bundle.to != fingerprint(&our_identity) {
        anyhow::bail!(
            "this bundle is addressed to {} but your vault identity is {} — ask the sender to \
             re-share to your identity (`hearth-vault identity`)",
            bundle.to,
            fingerprint(&our_identity)
        );
    }

    let epk_bytes: [u8; 32] = B64
        .decode(&bundle.epk)
        .map_err(|e| anyhow::anyhow!("malformed bundle: {e}"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("malformed bundle: bad ephemeral key length"))?;
    let epk = PublicKey::from(epk_bytes);

    let shared = secret.diffie_hellman(&epk);
    let key = bundle_key(shared.as_bytes(), &epk, &our_public)?;

    let ciphertext = B64
        .decode(&bundle.blob)
        .map_err(|e| anyhow::anyhow!("malformed bundle: {e}"))?;
    let plaintext = crypto::decrypt_aes256gcm(&key, &ciphertext, SHARE_AAD)
        .map_err(|_| anyhow::anyhow!("bundle failed to decrypt — wrong recipient, or tampered"))?;

    let payload: Payload = serde_json::from_slice(&plaintext)
        .map_err(|e| anyhow::anyhow!("corrupt bundle payload: {e}"))?;

    Ok((
        payload
            .entries
            .into_iter()
            .map(|e| OpenedEntry {
                key: e.key,
                value: SensitiveString::new(e.value),
                tier: e.tier,
            })
            .collect(),
        payload.note,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries() -> Vec<(String, SensitiveString, u8)> {
        vec![
            (
                "app/db_url".to_string(),
                SensitiveString::new("postgres://u:p@h/db"), // hearth-vault:allow fixture
                3,
            ),
            (
                "app/api_key".to_string(),
                SensitiveString::new("sk-not-a-real-key"),
                1,
            ),
        ]
    }

    #[test]
    fn roundtrip_to_the_intended_recipient() {
        let recipient_seed = [9u8; 32];
        let identity = public_identity(&recipient_seed);

        let bundle = seal(&entries(), &identity, None, Some("staging".into())).unwrap();
        let (opened, note) = open(&bundle, &recipient_seed).unwrap();

        assert_eq!(opened.len(), 2);
        assert_eq!(note.as_deref(), Some("staging"));
        let db = opened.iter().find(|e| e.key == "app/db_url").unwrap();
        assert_eq!(db.value.as_str(), "postgres://u:p@h/db"); // hearth-vault:allow fixture
        assert_eq!(db.tier, 3, "tier travels with the entry");
    }

    /// The whole point: a bundle is useless to anyone but its recipient.
    #[test]
    fn a_different_vault_cannot_open_it() {
        let bundle = seal(&entries(), &public_identity(&[9u8; 32]), None, None).unwrap();
        // Deliberately not `unwrap_err()`: that would require `Debug` on
        // `OpenedEntry`, and a secret-bearing type should not gain a Debug
        // impl to satisfy a test.
        let Err(err) = open(&bundle, &[4u8; 32]) else {
            panic!("a foreign vault opened the bundle");
        };
        assert!(err.to_string().contains("addressed to"), "got: {err}");
    }

    /// Tampering must fail closed, not silently yield different entries.
    #[test]
    fn a_tampered_blob_fails_to_open() {
        let seed = [9u8; 32];
        let mut bundle = seal(&entries(), &public_identity(&seed), None, None).unwrap();
        let mut raw = B64.decode(&bundle.blob).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0xFF;
        bundle.blob = B64.encode(&raw);
        assert!(open(&bundle, &seed).is_err());
    }

    /// Sign-only keys are the one tier whose promise sharing would break.
    #[test]
    fn tier_four_keys_are_never_shared() {
        let only_signing = vec![(
            "app/signing_key".to_string(),
            SensitiveString::new("-----BEGIN PRIVATE KEY-----"), // hearth-vault:allow fixture
            TIER_SIGN_ONLY,
        )];
        let Err(err) = seal(&only_signing, &public_identity(&[9u8; 32]), None, None) else {
            panic!("a tier-4 key was sealed into a bundle");
        };
        assert!(err.to_string().contains("sign-only"), "got: {err}");
    }

    /// `--max-tier` may only make the recipient's copy stricter. If it could
    /// lower a tier, sharing would be a laundering route around `retier`'s
    /// own one-way door.
    #[test]
    fn max_tier_only_tightens() {
        let seed = [9u8; 32];
        let bundle = seal(&entries(), &public_identity(&seed), Some(3), None).unwrap();
        let (opened, _) = open(&bundle, &seed).unwrap();
        for e in &opened {
            assert!(e.tier >= 3, "{} landed at tier {}", e.key, e.tier);
        }

        // A cap looser than the entry's own tier must not loosen it.
        let bundle = seal(&entries(), &public_identity(&seed), Some(1), None).unwrap();
        let (opened, _) = open(&bundle, &seed).unwrap();
        let db = opened.iter().find(|e| e.key == "app/db_url").unwrap();
        assert_eq!(db.tier, 3, "a tier-3 entry must not become tier 1");
    }

    /// Two bundles of the same content must share no ciphertext — otherwise
    /// an observer of a channel learns when you re-shared the same secret.
    #[test]
    fn each_bundle_uses_a_fresh_ephemeral_key() {
        let identity = public_identity(&[9u8; 32]);
        let a = seal(&entries(), &identity, None, None).unwrap();
        let b = seal(&entries(), &identity, None, None).unwrap();
        assert_ne!(a.epk, b.epk);
        assert_ne!(a.blob, b.blob);
    }

    #[test]
    fn identity_is_stable_and_prefixed() {
        let id = public_identity(&[1u8; 32]);
        assert!(id.starts_with(PUBKEY_PREFIX));
        assert_eq!(id, public_identity(&[1u8; 32]));
        assert_ne!(id, public_identity(&[2u8; 32]));
    }

    #[test]
    fn a_garbage_identity_is_rejected_clearly() {
        let Err(err) = seal(&entries(), "ssh-ed25519 AAAAC3Nz", None, None) else {
            panic!("a non-hearth-vault identity was accepted");
        };
        assert!(
            err.to_string().contains("not a hearth-vault identity"),
            "got: {err}"
        );
    }
}
