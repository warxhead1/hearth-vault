//! Encrypted credential storage backed by a JSON file — format v2.
//!
//! # Key hierarchy
//! A random 256-bit **data key** encrypts the whole vault body as one AEAD
//! blob. The passphrase-derived key and the recovery-mnemonic-derived key
//! each independently *wrap* (encrypt) that data key. Consequences:
//! - entry names are not plaintext on disk — a stolen vault.json reveals no
//!   inventory.
//! - the body is a single AEAD blob, so ciphertext cannot be swapped between
//!   entries.
//! - `change_passphrase` rewraps the data key; it never touches the body.
//! - recovery derives the same data key — there is no separate decryption
//!   path to keep in sync with the passphrase path.
//!
//! # v1 migration
//! v1 vaults (`{"salt", "entries": {"<name>": {"ciphertext", "tier", ...}}}`,
//! no `version` field) are detected and migrated automatically the first
//! time they're opened with [`VaultStore::open_at_with_passphrase`]. The
//! original file is backed up to `<path>.v1.bak` (owner-only permissions)
//! before the v2 file is written. See [`migrate_v1_to_v2`] for the recovery
//! mnemonic decision.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, KdfParams};
use crate::sensitive::SensitiveString;

/// `export-env`, `export-env-file`, and `exec` refuse to emit values at this
/// tier. `sign` and `github-app-token` still work. This is the default tier
/// for newly created secrets (enforced by the CLI, not by [`VaultStore::set`]).
pub const TIER_USE_ONLY: u8 = 3;

/// Sign-only. Never printed AND never injected into a child process — the
/// value is used only inside the vault process, by `sign` and
/// `github-app-token`. For keys you want to *use* but never hand to anything
/// else, e.g. an RSA private key that drives JWT signing.
///
/// This is a strictly stronger promise than [`TIER_USE_ONLY`], which does
/// allow `exec` to place the value in a child's environment. Collapsing the
/// two is a bug: it makes the default tier un-`exec`-able and breaks the
/// `import-env` → `exec` workflow.
pub const TIER_SIGN_ONLY: u8 = 4;

/// Highest tier number a key may carry.
pub const TIER_MAX: u8 = TIER_SIGN_ONLY;

/// Reject out-of-range tiers at the store boundary.
///
/// Tier is a security boundary, so an unrecognised value must never be stored:
/// a key written at tier 0 or 99 would compare unpredictably against every
/// export/exec gate. Both `set` and `retier` route through here.
fn validate_tier(tier: u8) -> anyhow::Result<()> {
    if tier == 0 || tier > TIER_MAX {
        anyhow::bail!(
            "invalid tier {tier} — must be 1..={TIER_MAX} \
             (1/2 exportable, 3 use-only, {TIER_SIGN_ONLY} sign-only)"
        );
    }
    Ok(())
}

/// Exact AAD strings from the frozen contract. Never reuse these for
/// anything else, and never pass an empty AAD anywhere in this module except
/// the one documented v1-compat exception in [`migrate_v1_to_v2`].
const AAD_WRAP_PASSPHRASE: &[u8] = b"hv2:wrap:passphrase";
const AAD_WRAP_RECOVERY: &[u8] = b"hv2:wrap:recovery";
const AAD_VAULT: &[u8] = b"hv2:vault";

/// v1's Argon2id params were hardcoded; this is what migration must assume
/// to open an old file (the file itself carries no `kdf` section).
const V1_KDF: KdfParams = KdfParams {
    m: 65536,
    t: 3,
    p: 4,
};

// ── On-disk format v2 ────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct VaultFileV2 {
    version: u8,
    kdf: KdfParams,
    wrap: WrapSection,
    /// b64(AEAD(data_key, json(VaultBody)))
    vault: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct WrapSection {
    passphrase: WrapEntry,
    recovery: Option<WrapEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct WrapEntry {
    /// b64(32) Argon2id salt.
    salt: String,
    /// b64 AEAD ciphertext of the data key.
    blob: String,
}

#[derive(Serialize, Deserialize, Default)]
struct VaultBody {
    entries: BTreeMap<String, BodyEntry>,
}

#[derive(Serialize, Deserialize, Clone)]
struct BodyEntry {
    value: String,
    tier: u8,
    created_at: String,
    updated_at: String,
}

/// Public metadata for a stored credential (never includes the value).
#[derive(Debug, Clone)]
pub struct VaultEntry {
    pub key: String,
    pub tier: u8,
    pub created_at: String,
    pub updated_at: String,
}

/// Encrypted credential store — format v2 (single-blob body, wrapped data key).
pub struct VaultStore {
    path: PathBuf,
    kdf: KdfParams,
    wrap_passphrase: WrapEntry,
    wrap_recovery: Option<WrapEntry>,
    /// The random 256-bit key that encrypts `body`. Zeroized on drop.
    data_key: [u8; 32],
    body: VaultBody,
}

impl Drop for VaultStore {
    fn drop(&mut self) {
        self.data_key.zeroize();
        for entry in self.body.entries.values_mut() {
            entry.value.zeroize();
        }
    }
}

impl VaultStore {
    /// Default vault file location: platform data dir / `vault.json`.
    ///
    /// Linux `$XDG_DATA_HOME/hearth-vault/vault.json`, macOS
    /// `~/Library/Application Support/hearth-vault/vault.json`, Windows
    /// `%APPDATA%\hearth-vault\vault.json`. Overrides, in priority order:
    /// `$HEARTH_VAULT_HOME/vault.json`, then the platform dir. If neither
    /// exists but legacy `~/.hearth/vault.json` does, that path is returned
    /// (with a one-line log hint to run `hearth-vault migrate`).
    pub fn default_path() -> anyhow::Result<PathBuf> {
        if let Ok(dir) = std::env::var("HEARTH_VAULT_HOME") {
            return Ok(PathBuf::from(dir).join("vault.json"));
        }

        let platform_path = directories::ProjectDirs::from("", "", "hearth-vault")
            .map(|dirs| dirs.data_dir().join("vault.json"));

        if let Some(ref p) = platform_path
            && p.exists()
        {
            return Ok(p.clone());
        }

        if let Some(base) = directories::BaseDirs::new() {
            let legacy = base.home_dir().join(".hearth").join("vault.json");
            if legacy.exists() {
                tracing::info!(
                    "using legacy vault path {legacy:?} — run `hearth-vault migrate` to move it to the platform data directory"
                );
                return Ok(legacy);
            }
        }

        platform_path.ok_or_else(|| anyhow::anyhow!("could not determine platform data directory"))
    }

    /// Open or create a vault at `path` with a passphrase. If the file is a
    /// v1 file (no `version` field), it is migrated to v2 in place first —
    /// see [`migrate_v1_to_v2`].
    pub fn open_at_with_passphrase(path: PathBuf, passphrase: &str) -> anyhow::Result<Self> {
        if path.exists() {
            let contents = fs::read_to_string(&path)?;
            let probe: serde_json::Value = serde_json::from_str(&contents)
                .map_err(|e| anyhow::anyhow!("corrupt vault file: {e}"))?;
            if probe.get("version").is_none() {
                migrate_v1_to_v2(&path, passphrase)?;
            }
            Self::load_v2(path, passphrase)
        } else {
            Self::create_new(path, passphrase)
        }
    }

    fn create_new(path: PathBuf, passphrase: &str) -> anyhow::Result<Self> {
        let data_key: [u8; 32] = crypto::random_bytes();
        let kdf = KdfParams::default();
        let salt: [u8; 32] = crypto::random_bytes();
        let mut pass_key = crypto::derive_key_argon2id(passphrase.as_bytes(), &salt, kdf)
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
        let wrap_blob = crypto::encrypt_aes256gcm(&pass_key, &data_key, AAD_WRAP_PASSPHRASE)
            .map_err(|e| anyhow::anyhow!("failed to wrap data key: {e}"))?;
        pass_key.zeroize();

        let store = Self {
            path,
            kdf,
            wrap_passphrase: WrapEntry {
                salt: B64.encode(salt),
                blob: B64.encode(wrap_blob),
            },
            wrap_recovery: None,
            data_key,
            body: VaultBody::default(),
        };
        store.save()?;
        Ok(store)
    }

    fn load_v2(path: PathBuf, passphrase: &str) -> anyhow::Result<Self> {
        let contents = fs::read_to_string(&path)?;
        let file: VaultFileV2 = serde_json::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("corrupt vault file: {e}"))?;
        if file.version != 2 {
            anyhow::bail!("unsupported vault format version {}", file.version);
        }

        let salt = decode_salt(&file.wrap.passphrase.salt)?;
        let mut pass_key = crypto::derive_key_argon2id(passphrase.as_bytes(), &salt, file.kdf)
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
        let wrap_blob = B64
            .decode(&file.wrap.passphrase.blob)
            .map_err(|e| anyhow::anyhow!("invalid wrap encoding: {e}"))?;
        let data_key_bytes = crypto::decrypt_aes256gcm(&pass_key, &wrap_blob, AAD_WRAP_PASSPHRASE)
            .map_err(|_| anyhow::anyhow!("wrong passphrase — decryption failed"))?;
        pass_key.zeroize();
        let data_key = to_key(&data_key_bytes)?;

        let body = decrypt_body(&data_key, &file.vault)?;

        Ok(Self {
            path,
            kdf: file.kdf,
            wrap_passphrase: file.wrap.passphrase,
            wrap_recovery: file.wrap.recovery,
            data_key,
            body,
        })
    }

    /// Open a vault using a 24-word BIP39 recovery mnemonic. The mnemonic's
    /// checksum is validated before any decryption is attempted, so a typo
    /// produces a clear "invalid recovery phrase" error instead of silently
    /// deriving the wrong key.
    pub fn open_at_with_mnemonic(path: PathBuf, mnemonic: &str) -> anyhow::Result<Self> {
        let parsed = bip39::Mnemonic::parse_normalized(mnemonic.trim())
            .map_err(|e| anyhow::anyhow!("invalid recovery phrase: {e}"))?;
        let phrase = parsed.to_string();

        let contents = fs::read_to_string(&path)
            .map_err(|e| anyhow::anyhow!("cannot read vault file: {e}"))?;
        let file: VaultFileV2 = serde_json::from_str(&contents)
            .map_err(|e| anyhow::anyhow!("corrupt vault file: {e}"))?;
        if file.version != 2 {
            anyhow::bail!("unsupported vault format version {}", file.version);
        }
        let wrap_recovery = file.wrap.recovery.clone().ok_or_else(|| {
            anyhow::anyhow!("no recovery key configured — run `hearth-vault new-recovery-key`")
        })?;

        let salt = decode_salt(&wrap_recovery.salt)?;
        let mut rec_key = crypto::derive_key_argon2id(phrase.as_bytes(), &salt, file.kdf)
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
        let wrap_blob = B64
            .decode(&wrap_recovery.blob)
            .map_err(|e| anyhow::anyhow!("invalid wrap encoding: {e}"))?;
        let data_key_bytes = crypto::decrypt_aes256gcm(&rec_key, &wrap_blob, AAD_WRAP_RECOVERY)
            .map_err(|_| anyhow::anyhow!("invalid recovery phrase — decryption failed"))?;
        rec_key.zeroize();
        let data_key = to_key(&data_key_bytes)?;

        let body = decrypt_body(&data_key, &file.vault)?;

        Ok(Self {
            path,
            kdf: file.kdf,
            wrap_passphrase: file.wrap.passphrase,
            wrap_recovery: file.wrap.recovery,
            data_key,
            body,
        })
    }

    /// Persist the vault to disk with owner-only permissions.
    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
            // The directory is part of the containment, not just the file.
            // A warning, not a failure: an unchangeable parent is a reason to
            // tell the user, not to refuse to save their vault.
            if let Err(e) = crate::hsm::platform::restrict_dir_to_owner(parent) {
                eprintln!(
                    "warning: could not restrict permissions on {}: {e}",
                    parent.display()
                );
            }
        }

        // The serialized body is every secret in the vault, in the clear,
        // right up to the encrypt call below. Wipe it on the way out.
        let body_json = zeroize::Zeroizing::new(serde_json::to_vec(&self.body)?);
        let vault_blob = crypto::encrypt_aes256gcm(&self.data_key, &body_json, AAD_VAULT)
            .map_err(|e| anyhow::anyhow!("failed to encrypt vault body: {e}"))?;

        let file = VaultFileV2 {
            version: 2,
            kdf: self.kdf,
            wrap: WrapSection {
                passphrase: self.wrap_passphrase.clone(),
                recovery: self.wrap_recovery.clone(),
            },
            vault: B64.encode(vault_blob),
        };

        let json = serde_json::to_string_pretty(&file)?;
        // Atomic + owner-only from creation: a crash mid-save must not be
        // able to truncate the only copy of every secret you own, and the
        // file must never exist readable-by-others even for an instant.
        crate::hsm::platform::write_private(&self.path, json.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to write vault file: {e}"))?;

        Ok(())
    }

    /// Store a credential. The value is folded into the encrypted body —
    /// nothing is written until [`VaultStore::save`] is called.
    pub fn set(&mut self, key: &str, value: &SensitiveString, tier: u8) -> anyhow::Result<()> {
        validate_tier(tier)?;
        let now = Utc::now().to_rfc3339();
        let entry = if let Some(existing) = self.body.entries.get(key) {
            BodyEntry {
                value: value.as_str().to_string(),
                tier,
                created_at: existing.created_at.clone(),
                updated_at: now,
            }
        } else {
            BodyEntry {
                value: value.as_str().to_string(),
                tier,
                created_at: now.clone(),
                updated_at: now,
            }
        };
        self.body.entries.insert(key.to_string(), entry);
        Ok(())
    }

    /// Retrieve a credential's value. Not the tier-enforcement point — see
    /// [`VaultStore::tier_of`] for callers (the CLI) that must refuse to
    /// export tier-3 secrets.
    pub fn get(&self, key: &str) -> anyhow::Result<Option<SensitiveString>> {
        Ok(self
            .body
            .entries
            .get(key)
            .map(|e| SensitiveString::new(e.value.clone())))
    }

    /// The security tier of a stored key, if it exists.
    pub fn tier_of(&self, key: &str) -> Option<u8> {
        self.body.entries.get(key).map(|e| e.tier)
    }

    /// Check if a key exists in the vault.
    pub fn has(&self, key: &str) -> bool {
        self.body.entries.contains_key(key)
    }

    /// Delete a credential. Returns true if it existed.
    pub fn delete(&mut self, key: &str) -> anyhow::Result<bool> {
        if let Some(mut entry) = self.body.entries.remove(key) {
            entry.value.zeroize();
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Rename a credential, preserving its value/tier/timestamps.
    pub fn rename(&mut self, from: &str, to: &str) -> anyhow::Result<()> {
        if from == to {
            return Ok(());
        }
        if !self.body.entries.contains_key(from) {
            anyhow::bail!("no such key: {from}");
        }
        if self.body.entries.contains_key(to) {
            anyhow::bail!("target key already exists: {to}");
        }
        let entry = self
            .body
            .entries
            .remove(from)
            .expect("checked contains_key above");
        self.body.entries.insert(to.to_string(), entry);
        Ok(())
    }

    /// Change the security tier of an existing credential.
    pub fn retier(&mut self, key: &str, tier: u8) -> anyhow::Result<()> {
        validate_tier(tier)?;
        let entry = self
            .body
            .entries
            .get_mut(key)
            .ok_or_else(|| anyhow::anyhow!("no such key: {key}"))?;
        entry.tier = tier;
        entry.updated_at = Utc::now().to_rfc3339();
        Ok(())
    }

    /// True if a recovery mnemonic currently wraps the data key.
    ///
    /// False after a v1 migration, which voids the legacy phrase — the CLI
    /// uses this to tell the user whether `new-recovery-key` is replacing an
    /// existing phrase or creating the first one.
    pub fn has_recovery_key(&self) -> bool {
        self.wrap_recovery.is_some()
    }

    /// List all keys with metadata (never returns values).
    pub fn list(&self) -> Vec<VaultEntry> {
        self.body
            .entries
            .iter()
            .map(|(key, entry)| VaultEntry {
                key: key.clone(),
                tier: entry.tier,
                created_at: entry.created_at.clone(),
                updated_at: entry.updated_at.clone(),
            })
            .collect()
    }

    /// Generate a fresh 24-word BIP39 recovery mnemonic and wrap the
    /// existing data key with it. Returns the mnemonic — the caller must
    /// display it to the user; it is never stored in the clear and cannot
    /// be recovered later.
    /// Returns the phrase in a `Zeroizing<String>`: it is a second, complete
    /// key to the vault, and the caller only needs it long enough to show it
    /// to a human once.
    pub fn generate_recovery_key(&mut self) -> anyhow::Result<Zeroizing<String>> {
        let mut entropy: [u8; 32] = crypto::random_bytes();
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy)
            .map_err(|e| anyhow::anyhow!("mnemonic generation failed: {e}"))?;
        entropy.zeroize();
        let phrase = mnemonic.to_string();

        let salt: [u8; 32] = crypto::random_bytes();
        let mut rec_key = crypto::derive_key_argon2id(phrase.as_bytes(), &salt, self.kdf)
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
        let blob = crypto::encrypt_aes256gcm(&rec_key, &self.data_key, AAD_WRAP_RECOVERY)
            .map_err(|e| anyhow::anyhow!("failed to wrap data key for recovery: {e}"))?;
        rec_key.zeroize();

        self.wrap_recovery = Some(WrapEntry {
            salt: B64.encode(salt),
            blob: B64.encode(blob),
        });

        Ok(Zeroizing::new(phrase))
    }

    /// Rewrap the data key under a new passphrase. Entries are never
    /// touched — this is the whole point of the wrapped-data-key design.
    /// Does not persist; call [`VaultStore::save`] afterwards.
    pub fn change_passphrase(&mut self, new_passphrase: &str) -> anyhow::Result<()> {
        let salt: [u8; 32] = crypto::random_bytes();
        let mut pass_key = crypto::derive_key_argon2id(new_passphrase.as_bytes(), &salt, self.kdf)
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
        let blob = crypto::encrypt_aes256gcm(&pass_key, &self.data_key, AAD_WRAP_PASSPHRASE)
            .map_err(|e| anyhow::anyhow!("failed to wrap data key: {e}"))?;
        pass_key.zeroize();

        self.wrap_passphrase = WrapEntry {
            salt: B64.encode(salt),
            blob: B64.encode(blob),
        };
        Ok(())
    }

    /// Return the path to the vault file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

fn decrypt_body(data_key: &[u8; 32], vault_b64: &str) -> anyhow::Result<VaultBody> {
    let vault_blob = B64
        .decode(vault_b64)
        .map_err(|e| anyhow::anyhow!("invalid vault encoding: {e}"))?;
    let body_json = crypto::decrypt_aes256gcm(data_key, &vault_blob, AAD_VAULT)
        .map_err(|_| anyhow::anyhow!("vault body decryption failed — corrupted file"))?;
    serde_json::from_slice(&body_json).map_err(|e| anyhow::anyhow!("corrupt vault body: {e}"))
}

fn decode_salt(s: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = B64
        .decode(s)
        .map_err(|e| anyhow::anyhow!("invalid salt encoding: {e}"))?;
    to_key(&bytes)
}

fn to_key(bytes: &[u8]) -> anyhow::Result<[u8; 32]> {
    if bytes.len() != 32 {
        anyhow::bail!("expected a 32-byte key, got {} bytes", bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}

fn backup_path_for(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "vault.json".to_string());
    path.with_file_name(format!("{name}.v1.bak"))
}

// ── v1 format (migration-only) ──────────────────────────────────────────

#[derive(Deserialize)]
struct VaultFileV1 {
    salt: String,
    #[serde(default)]
    recovery_key_encrypted: Option<String>,
    entries: BTreeMap<String, EncryptedEntryV1>,
}

#[derive(Deserialize)]
struct EncryptedEntryV1 {
    ciphertext: String,
    tier: u8,
    created_at: String,
    updated_at: String,
}

/// Migrate a v1 vault file at `path` to v2 in place, backing up the
/// original to `<path>.v1.bak` (owner-only permissions) first.
///
/// # Recovery mnemonic decision
/// v1 recovery mnemonics came from a 256-word, no-checksum, non-BIP39 list,
/// wrapping the key via BLAKE3+HKDF with no salt actually used in the
/// derivation. That scheme cannot be expressed in the frozen v2 `wrap`
/// format (which is specifically `argon2id(mnemonic, salt)`), and the old
/// word list can't be validated against the new `bip39` crate either — it
/// isn't a real BIP39 wordlist. Preserving it would mean carrying a second,
/// permanently-legacy unwrap path with no way to signal which one a given
/// vault uses (the schema has no room for a format flag). That is not
/// something I can implement *correctly* within the frozen contract, so:
/// **the old recovery phrase is voided.** Migration drops it
/// (`wrap.recovery = None`) and logs a loud warning; the CLI should prompt
/// the user to run `hearth-vault new-recovery-key` for a fresh BIP39
/// mnemonic after migrating.
pub fn migrate_v1_to_v2(path: &Path, passphrase: &str) -> anyhow::Result<()> {
    let contents = fs::read_to_string(path)?;
    let v1: VaultFileV1 = serde_json::from_str(&contents)
        .map_err(|e| anyhow::anyhow!("corrupt v1 vault file: {e}"))?;

    let old_salt = decode_salt(&v1.salt)?;
    let mut old_enc_key = {
        let master_key = crypto::derive_key_argon2id(passphrase.as_bytes(), &old_salt, V1_KDF)
            .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
        crypto::derive_subkey(&master_key, "vault-credentials")
            .map_err(|e| anyhow::anyhow!("subkey derivation failed: {e}"))?
    };

    let mut entries = BTreeMap::new();
    for (name, e) in &v1.entries {
        let ct_bytes = B64
            .decode(&e.ciphertext)
            .map_err(|err| anyhow::anyhow!("invalid ciphertext for '{name}': {err}"))?;
        // v1 entries were encrypted with `cipher.encrypt(nonce, plaintext)`
        // directly — aes-gcm treats that as AAD of zero length, which is
        // exactly what an empty AAD slice reproduces here. This is the one
        // sanctioned exception to "never pass empty AAD": it is reading old
        // data written before AAD existed, not writing new data.
        let plaintext = crypto::decrypt_aes256gcm(&old_enc_key, &ct_bytes, b"").map_err(|_| {
            anyhow::anyhow!("wrong passphrase — failed to decrypt entry '{name}' during migration")
        })?;
        // to_vec copies out of the Zeroizing buffer; the original is still
        // wiped on drop, and `value` lands in BodyEntry, which is zeroized
        // when the store is dropped.
        let value = String::from_utf8(plaintext.to_vec())
            .map_err(|err| anyhow::anyhow!("entry '{name}' is not valid UTF-8: {err}"))?;
        entries.insert(
            name.clone(),
            BodyEntry {
                value,
                tier: e.tier,
                created_at: e.created_at.clone(),
                updated_at: e.updated_at.clone(),
            },
        );
    }
    old_enc_key.zeroize();

    if v1.recovery_key_encrypted.is_some() {
        tracing::warn!(
            "vault migration: the OLD recovery phrase is now VOID — v1's word list had no \
             checksum and cannot be carried forward safely into the v2 format. Run \
             `hearth-vault new-recovery-key` to create a new BIP39 recovery phrase."
        );
    }

    // Back up the v1 file BEFORE writing anything new.
    let backup_path = backup_path_for(path);
    fs::write(&backup_path, &contents)?;
    crate::hsm::platform::restrict_to_owner(&backup_path)
        .map_err(|e| anyhow::anyhow!("failed to restrict backup file permissions: {e}"))?;

    let data_key: [u8; 32] = crypto::random_bytes();
    let kdf = KdfParams::default();
    let new_salt: [u8; 32] = crypto::random_bytes();
    let mut pass_key = crypto::derive_key_argon2id(passphrase.as_bytes(), &new_salt, kdf)
        .map_err(|e| anyhow::anyhow!("key derivation failed: {e}"))?;
    let wrap_blob = crypto::encrypt_aes256gcm(&pass_key, &data_key, AAD_WRAP_PASSPHRASE)
        .map_err(|e| anyhow::anyhow!("failed to wrap data key: {e}"))?;
    pass_key.zeroize();

    let body = VaultBody { entries };
    let body_json = serde_json::to_vec(&body)?;
    let vault_blob = crypto::encrypt_aes256gcm(&data_key, &body_json, AAD_VAULT)
        .map_err(|e| anyhow::anyhow!("failed to encrypt vault body: {e}"))?;

    let file = VaultFileV2 {
        version: 2,
        kdf,
        wrap: WrapSection {
            passphrase: WrapEntry {
                salt: B64.encode(new_salt),
                blob: B64.encode(wrap_blob),
            },
            recovery: None,
        },
        vault: B64.encode(vault_blob),
    };
    let json = serde_json::to_string_pretty(&file)?;
    fs::write(path, &json)?;
    crate::hsm::platform::restrict_to_owner(path)
        .map_err(|e| anyhow::anyhow!("failed to restrict vault file permissions: {e}"))?;

    Ok(())
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_vault(passphrase: &str) -> (VaultStore, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let store = VaultStore::open_at_with_passphrase(path, passphrase).unwrap();
        (store, dir)
    }

    #[test]
    fn open_create_save_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        {
            let mut store = VaultStore::open_at_with_passphrase(path.clone(), "test-pass").unwrap();
            store
                .set("api/key", &SensitiveString::new("secret-value-123"), 2)
                .unwrap();
            store.save().unwrap();
        }

        {
            let store = VaultStore::open_at_with_passphrase(path, "test-pass").unwrap();
            let val = store.get("api/key").unwrap().unwrap();
            assert_eq!(val.as_str(), "secret-value-123");
        }
    }

    #[test]
    fn set_and_get_credential() {
        let (mut store, _dir) = temp_vault("passphrase");
        let secret = SensitiveString::new("my-api-key-42");
        store.set("kroger/client_id", &secret, 2).unwrap();
        let retrieved = store.get("kroger/client_id").unwrap().unwrap();
        assert_eq!(retrieved.as_str(), "my-api-key-42");
    }

    #[test]
    fn set_overwrites_existing() {
        let (mut store, _dir) = temp_vault("passphrase");
        store.set("key", &SensitiveString::new("old"), 2).unwrap();
        store.set("key", &SensitiveString::new("new"), 2).unwrap();
        let val = store.get("key").unwrap().unwrap();
        assert_eq!(val.as_str(), "new");
    }

    #[test]
    fn list_shows_keys_not_values() {
        let (mut store, _dir) = temp_vault("passphrase");
        store
            .set("alpha", &SensitiveString::new("val-a"), 1)
            .unwrap();
        store
            .set("beta", &SensitiveString::new("val-b"), 2)
            .unwrap();

        let entries = store.list();
        assert_eq!(entries.len(), 2);
        let keys: Vec<&str> = entries.iter().map(|e| e.key.as_str()).collect();
        assert!(keys.contains(&"alpha"));
        assert!(keys.contains(&"beta"));
    }

    #[test]
    fn has_returns_true_for_existing() {
        let (mut store, _dir) = temp_vault("passphrase");
        store
            .set("exists", &SensitiveString::new("yes"), 2)
            .unwrap();
        assert!(store.has("exists"));
        assert!(!store.has("does-not-exist"));
    }

    #[test]
    fn delete_removes_credential() {
        let (mut store, _dir) = temp_vault("passphrase");
        store
            .set("to-delete", &SensitiveString::new("bye"), 2)
            .unwrap();
        assert!(store.has("to-delete"));
        let removed = store.delete("to-delete").unwrap();
        assert!(removed);
        assert!(!store.has("to-delete"));
        assert!(store.get("to-delete").unwrap().is_none());
    }

    #[test]
    fn delete_nonexistent_returns_false() {
        let (mut store, _dir) = temp_vault("passphrase");
        let removed = store.delete("nope").unwrap();
        assert!(!removed);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        {
            let mut store =
                VaultStore::open_at_with_passphrase(path.clone(), "correct-pass").unwrap();
            store.set("key", &SensitiveString::new("value"), 2).unwrap();
            store.save().unwrap();
        }

        let result = VaultStore::open_at_with_passphrase(path, "wrong-pass");
        assert!(result.is_err());
        let err_msg = result.err().expect("should have errored").to_string();
        assert!(
            err_msg.contains("wrong passphrase") || err_msg.contains("decryption failed"),
            "unexpected error: {err_msg}"
        );
    }

    #[test]
    fn passphrase_derivation_consistent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        let mut store =
            VaultStore::open_at_with_passphrase(path.clone(), "deterministic-test").unwrap();
        store
            .set("test", &SensitiveString::new("hello"), 2)
            .unwrap();
        store.save().unwrap();

        let store2 = VaultStore::open_at_with_passphrase(path, "deterministic-test").unwrap();
        let val = store2.get("test").unwrap().unwrap();
        assert_eq!(val.as_str(), "hello");
    }

    #[test]
    fn empty_vault_initialization() {
        let (store, _dir) = temp_vault("empty-vault");
        assert!(store.list().is_empty());
        assert!(!store.has("anything"));
        assert!(store.get("anything").unwrap().is_none());
    }

    #[test]
    #[cfg(unix)]
    fn file_permissions_are_600() {
        let (store, _dir) = temp_vault("perms-test");
        store.save().unwrap();

        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(store.path()).unwrap();
        assert_eq!(meta.permissions().mode() & 0o777, 0o600);
    }

    #[test]
    fn key_naming_with_slashes() {
        let (mut store, _dir) = temp_vault("slash-test");
        store
            .set("kroger/client_id", &SensitiveString::new("abc"), 2)
            .unwrap();
        store
            .set("unifi/password", &SensitiveString::new("def"), 2)
            .unwrap();
        store
            .set("deep/nested/path/key", &SensitiveString::new("ghi"), 2)
            .unwrap();

        assert_eq!(
            store.get("kroger/client_id").unwrap().unwrap().as_str(),
            "abc"
        );
        assert_eq!(
            store.get("unifi/password").unwrap().unwrap().as_str(),
            "def"
        );
        assert_eq!(
            store.get("deep/nested/path/key").unwrap().unwrap().as_str(),
            "ghi"
        );
    }

    #[test]
    fn sensitive_string_debug_is_masked() {
        let s = SensitiveString::new("super-secret");
        let debug = format!("{:?}", s);
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("***"));
    }

    // ── New v2 coverage ──────────────────────────────────────────────────

    #[test]
    fn entry_names_are_not_plaintext_on_disk() {
        let (mut store, _dir) = temp_vault("inventory-test");
        store
            .set(
                "very-identifiable-service-name",
                &SensitiveString::new("secret"),
                2,
            )
            .unwrap();
        store.save().unwrap();

        let raw = fs::read_to_string(store.path()).unwrap();
        assert!(!raw.contains("very-identifiable-service-name"));
        assert!(!raw.contains("secret"));
    }

    #[test]
    fn wrong_recovery_phrase_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        let mnemonic = {
            let mut store = VaultStore::open_at_with_passphrase(path.clone(), "pw").unwrap();
            store.set("k", &SensitiveString::new("v"), 2).unwrap();
            let m = store.generate_recovery_key().unwrap();
            store.save().unwrap();
            m
        };
        // sanity: correct mnemonic works
        let recovered = VaultStore::open_at_with_mnemonic(path.clone(), &mnemonic).unwrap();
        assert_eq!(recovered.get("k").unwrap().unwrap().as_str(), "v");

        // corrupt one word — bip39 checksum should reject it outright
        let mut words: Vec<&str> = mnemonic.split(' ').collect();
        let last = words.len() - 1;
        words[last] = if words[last] == "abandon" {
            "ability"
        } else {
            "abandon"
        };
        let bad = words.join(" ");
        assert!(VaultStore::open_at_with_mnemonic(path, &bad).is_err());
    }

    #[test]
    fn bip39_checksum_rejects_corrupted_phrase() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let mut store = VaultStore::open_at_with_passphrase(path, "pw").unwrap();
        let mnemonic = store.generate_recovery_key().unwrap();

        // A word list of the right length but wrong checksum must fail to
        // parse at all (bip39::Mnemonic::parse_normalized checks the
        // checksum bits), independent of the vault file.
        let mut words: Vec<&str> = mnemonic.split(' ').collect();
        let last_idx = words.len() - 1;
        let original = words[last_idx];
        let replacement = if original == "zoo" { "zebra" } else { "zoo" };
        words[last_idx] = replacement;
        let corrupted = words.join(" ");
        let parsed = bip39::Mnemonic::parse_normalized(&corrupted);
        assert!(
            parsed.is_err() || parsed.unwrap().to_string() != *mnemonic,
            "corrupted phrase must not parse to the same mnemonic"
        );
    }

    #[test]
    fn change_passphrase_rewraps_without_touching_body() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");

        {
            let mut store = VaultStore::open_at_with_passphrase(path.clone(), "old-pass").unwrap();
            store
                .set("key", &SensitiveString::new("unchanged-value"), 2)
                .unwrap();
            store.change_passphrase("new-pass").unwrap();
            store.save().unwrap();
        }

        // Old passphrase no longer opens the vault.
        assert!(VaultStore::open_at_with_passphrase(path.clone(), "old-pass").is_err());

        // New passphrase does, and the entry survived untouched.
        let store = VaultStore::open_at_with_passphrase(path, "new-pass").unwrap();
        assert_eq!(
            store.get("key").unwrap().unwrap().as_str(),
            "unchanged-value"
        );
    }

    #[test]
    fn tier_of_reports_stored_tier() {
        let (mut store, _dir) = temp_vault("tier-test");
        store
            .set("secret", &SensitiveString::new("v"), TIER_USE_ONLY)
            .unwrap();
        assert_eq!(store.tier_of("secret"), Some(TIER_USE_ONLY));
        assert_eq!(store.tier_of("missing"), None);
    }

    #[test]
    fn retier_updates_tier_and_timestamp() {
        let (mut store, _dir) = temp_vault("retier-test");
        store.set("k", &SensitiveString::new("v"), 2).unwrap();
        let before = store.list()[0].updated_at.clone();
        std::thread::sleep(std::time::Duration::from_millis(2));
        store.retier("k", TIER_USE_ONLY).unwrap();
        assert_eq!(store.tier_of("k"), Some(TIER_USE_ONLY));
        assert_ne!(store.list()[0].updated_at, before);
    }

    #[test]
    fn rename_preserves_value_and_tier() {
        let (mut store, _dir) = temp_vault("rename-test");
        store
            .set("old-name", &SensitiveString::new("v"), 2)
            .unwrap();
        store.rename("old-name", "new-name").unwrap();
        assert!(!store.has("old-name"));
        assert_eq!(store.get("new-name").unwrap().unwrap().as_str(), "v");
        assert_eq!(store.tier_of("new-name"), Some(2));
    }

    #[test]
    fn rename_to_existing_key_fails() {
        let (mut store, _dir) = temp_vault("rename-conflict");
        store.set("a", &SensitiveString::new("va"), 2).unwrap();
        store.set("b", &SensitiveString::new("vb"), 2).unwrap();
        assert!(store.rename("a", "b").is_err());
    }

    #[test]
    fn v1_migration_preserves_all_entries_and_backs_up() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.json");
        let passphrase = "legacy-pass";

        // Hand-build a v1 file the same way the old code did: Argon2id(m=65536,t=3,p=4)
        // -> HKDF "vault-credentials" subkey -> per-entry AES-GCM with NO aad.
        let salt: [u8; 32] = crypto::random_bytes();
        let master = crypto::derive_key_argon2id(passphrase.as_bytes(), &salt, V1_KDF).unwrap();
        let enc_key = crypto::derive_subkey(&master, "vault-credentials").unwrap();

        let mut entries = BTreeMap::new();
        for (name, val, tier) in [
            ("alpha/key", "value-one", 1u8),
            ("beta/key", "value-two", 2u8),
        ] {
            let ct = crypto::encrypt_aes256gcm(&enc_key, val.as_bytes(), b"").unwrap();
            entries.insert(
                name.to_string(),
                EncryptedEntryV1 {
                    ciphertext: B64.encode(ct),
                    tier,
                    created_at: "2026-01-01T00:00:00Z".to_string(),
                    updated_at: "2026-01-01T00:00:00Z".to_string(),
                },
            );
        }

        let v1 = serde_json::json!({
            "salt": B64.encode(salt),
            "entries": entries.iter().map(|(k, v)| (k.clone(), serde_json::json!({
                "ciphertext": v.ciphertext,
                "tier": v.tier,
                "created_at": v.created_at,
                "updated_at": v.updated_at,
            }))).collect::<serde_json::Map<_, _>>(),
        });
        fs::write(&path, serde_json::to_string_pretty(&v1).unwrap()).unwrap();

        // open_at_with_passphrase must auto-detect and migrate.
        let store = VaultStore::open_at_with_passphrase(path.clone(), passphrase).unwrap();
        assert_eq!(
            store.get("alpha/key").unwrap().unwrap().as_str(),
            "value-one"
        );
        assert_eq!(store.tier_of("alpha/key"), Some(1));
        assert_eq!(
            store.get("beta/key").unwrap().unwrap().as_str(),
            "value-two"
        );
        assert_eq!(store.tier_of("beta/key"), Some(2));

        // Backup exists and still contains the original v1 shape.
        let backup_path = path.with_file_name("vault.json.v1.bak");
        assert!(backup_path.exists());
        let backup: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&backup_path).unwrap()).unwrap();
        assert!(backup.get("version").is_none());
        assert!(backup["entries"]["alpha/key"]["ciphertext"].is_string());

        // The migrated file on disk is now v2 and re-opens normally.
        let raw = fs::read_to_string(&path).unwrap();
        let as_json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(as_json["version"], 2);
        drop(store);
        let reopened = VaultStore::open_at_with_passphrase(path, passphrase).unwrap();
        assert_eq!(
            reopened.get("alpha/key").unwrap().unwrap().as_str(),
            "value-one"
        );
    }
}
