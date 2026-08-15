//! Cryptographic primitives for hearth-vault.
//!
//! AES-256-GCM (AEAD, every call carries associated data), Argon2id key
//! derivation with caller-supplied parameters, BLAKE3 hashing, and
//! HKDF-SHA3 sub-key derivation.

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, OsRng, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use zeroize::Zeroizing;

/// Errors from cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("encryption failed")]
    EncryptionFailed,
    #[error("decryption failed — wrong key, wrong AAD, or corrupted data")]
    DecryptionFailed,
    #[error("key derivation failed: {0}")]
    KeyDerivation(String),
    #[error("invalid data format: {0}")]
    InvalidFormat(String),
}

/// Fixed sizes.
const NONCE_SIZE: usize = 12; // AES-256-GCM nonce
const KEY_SIZE: usize = 32; // AES-256 key (256-bit)

/// Argon2id tuning parameters. Persisted alongside the vault so they can be
/// raised later without bricking existing vaults (old vaults keep the params
/// they were created with; new vaults get [`KdfParams::default`]).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m: u32,
    /// Iteration count.
    pub t: u32,
    /// Parallelism (lanes).
    pub p: u32,
}

impl KdfParams {
    /// Reject parameters that cannot have come from a vault this tool wrote.
    ///
    /// These values are read from the vault FILE, which is untrusted input:
    /// they have to be used to derive the key *before* anything can be
    /// authenticated, so a hostile or corrupt file gets to choose how much
    /// work and memory we do. `m = u32::MAX` asks Argon2 for roughly 4 TiB;
    /// `t = u32::MAX` never returns. Neither is a decryption failure -- it is
    /// a crash or a hang, in a tool other programs shell out to.
    ///
    /// The ceiling is generous (4 GiB, 64 passes, 64 lanes): far above any
    /// sane hardening choice, far below anything that takes the process out.
    /// The floor is the smallest thing Argon2 itself accepts.
    pub fn validate(&self) -> Result<(), CryptoError> {
        const MAX_M_KIB: u32 = 4 * 1024 * 1024; // 4 GiB
        const MAX_T: u32 = 64;
        const MAX_P: u32 = 64;

        if self.m < 8 || self.m > MAX_M_KIB {
            return Err(CryptoError::KeyDerivation(format!(
                "vault KDF memory parameter out of range: {} KiB (accepted: 8..={MAX_M_KIB})",
                self.m
            )));
        }
        if self.t == 0 || self.t > MAX_T {
            return Err(CryptoError::KeyDerivation(format!(
                "vault KDF iteration parameter out of range: {} (accepted: 1..={MAX_T})",
                self.t
            )));
        }
        if self.p == 0 || self.p > MAX_P {
            return Err(CryptoError::KeyDerivation(format!(
                "vault KDF parallelism parameter out of range: {} (accepted: 1..={MAX_P})",
                self.p
            )));
        }
        Ok(())
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            m: 65536,
            t: 3,
            p: 4,
        }
    }
}

// ── AES-256-GCM ────────────────────────────────────────────────────────────

/// Encrypt plaintext with AES-256-GCM under `aad`. Returns nonce || ciphertext.
pub fn encrypt_aes256gcm(
    key: &[u8; KEY_SIZE],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::EncryptionFailed)?;
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CryptoError::EncryptionFailed)?;

    let mut out = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypt nonce || ciphertext with AES-256-GCM, verifying `aad`.
///
/// The plaintext comes back in a `Zeroizing<Vec<u8>>` deliberately: every
/// decryption in this crate produces secret material -- the vault body, a
/// wrapped data key, a PEM private key -- and returning a bare `Vec<u8>`
/// meant each caller had to remember to wipe it, which several did not.
/// Wrapping it here makes forgetting impossible.
pub fn decrypt_aes256gcm(
    key: &[u8; KEY_SIZE],
    data: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if data.len() < NONCE_SIZE + 16 {
        // Minimum: nonce + GCM tag
        return Err(CryptoError::InvalidFormat("data too short".into()));
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::DecryptionFailed)?;
    let nonce = Nonce::from_slice(nonce_bytes);
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CryptoError::DecryptionFailed)
        .map(Zeroizing::new)
}

// ── Argon2id Key Derivation ────────────────────────────────────────────────

/// Derive a 256-bit key from a passphrase, salt, and explicit KDF params.
/// Params are never hardcoded here — callers read them from the on-disk
/// format so they can be raised over time without bricking old vaults.
pub fn derive_key_argon2id(
    passphrase: &[u8],
    salt: &[u8; 32],
    params: KdfParams,
) -> Result<[u8; KEY_SIZE], CryptoError> {
    // Guard here rather than at each call site: `params` reaches this
    // function straight out of the vault file, which is untrusted input, and
    // this is the one place every path funnels through.
    params.validate()?;
    let argon2_params = Params::new(params.m, params.t, params.p, Some(KEY_SIZE))
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = [0u8; KEY_SIZE];
    argon2
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(key)
}

// ── HKDF-SHA3 Sub-key Derivation ──────────────────────────────────────────

/// Derive a purpose-specific sub-key from a master key using HKDF-SHA3-256.
/// `context` should be a unique string per purpose.
pub fn derive_subkey(
    master: &[u8; KEY_SIZE],
    context: &str,
) -> Result<[u8; KEY_SIZE], CryptoError> {
    let hkdf = Hkdf::<Sha3_256>::new(None, master);
    let mut subkey = [0u8; KEY_SIZE];
    hkdf.expand(context.as_bytes(), &mut subkey)
        .map_err(|e| CryptoError::KeyDerivation(e.to_string()))?;
    Ok(subkey)
}

// ── BLAKE3 Hashing ─────────────────────────────────────────────────────────

/// Hash data with BLAKE3 (256-bit).
pub fn hash_blake3(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

// ── Secure Random ─────────────────────────────────────────────────────────

/// `N` cryptographically secure random bytes from the OS RNG.
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod kdf_bounds_tests {
    use super::*;

    /// Parameters come from the vault file, i.e. from an attacker if they can
    /// hand you a file. Absurd values must be a clean error, not a 4 TiB
    /// allocation or a call that never returns.
    #[test]
    fn hostile_kdf_params_are_rejected_before_any_work_happens() {
        let salt = [7u8; 32];
        for bad in [
            KdfParams {
                m: u32::MAX,
                t: 3,
                p: 4,
            },
            KdfParams {
                m: 65536,
                t: u32::MAX,
                p: 4,
            },
            KdfParams {
                m: 65536,
                t: 3,
                p: u32::MAX,
            },
            KdfParams { m: 0, t: 3, p: 4 },
            KdfParams {
                m: 65536,
                t: 0,
                p: 4,
            },
            KdfParams {
                m: 65536,
                t: 3,
                p: 0,
            },
        ] {
            assert!(
                derive_key_argon2id(b"passphrase", &salt, bad).is_err(),
                "accepted hostile KDF params: {bad:?}"
            );
        }
    }

    #[test]
    fn default_params_still_derive() {
        let salt = [7u8; 32];
        assert!(derive_key_argon2id(b"passphrase", &salt, KdfParams::default()).is_ok());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const AAD: &[u8] = b"test:aad";

    #[test]
    fn aes256gcm_roundtrip() {
        let key = [42u8; KEY_SIZE];
        let plaintext = b"sensitive device config data";
        let encrypted = encrypt_aes256gcm(&key, plaintext, AAD).unwrap();
        assert_ne!(&encrypted, plaintext);
        let decrypted = decrypt_aes256gcm(&key, &encrypted, AAD).unwrap();
        assert_eq!(decrypted.as_slice(), plaintext);
    }

    #[test]
    fn aes256gcm_wrong_key_fails() {
        let key1 = [42u8; KEY_SIZE];
        let key2 = [99u8; KEY_SIZE];
        let encrypted = encrypt_aes256gcm(&key1, b"secret", AAD).unwrap();
        assert!(decrypt_aes256gcm(&key2, &encrypted, AAD).is_err());
    }

    #[test]
    fn aes256gcm_tampered_data_fails() {
        let key = [42u8; KEY_SIZE];
        let mut encrypted = encrypt_aes256gcm(&key, b"secret", AAD).unwrap();
        // Flip a bit in the ciphertext (after nonce)
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0x01;
        assert!(decrypt_aes256gcm(&key, &encrypted, AAD).is_err());
    }

    #[test]
    fn aes256gcm_too_short_fails() {
        let key = [42u8; KEY_SIZE];
        assert!(decrypt_aes256gcm(&key, &[0u8; 10], AAD).is_err());
    }

    #[test]
    fn aes256gcm_wrong_aad_fails() {
        // This is the security fix: AAD is now bound into every ciphertext.
        // A blob encrypted under one context must not decrypt under another,
        // even with the correct key.
        let key = [7u8; KEY_SIZE];
        let encrypted = encrypt_aes256gcm(&key, b"payload", b"context-a").unwrap();
        assert!(decrypt_aes256gcm(&key, &encrypted, b"context-b").is_err());
        assert!(decrypt_aes256gcm(&key, &encrypted, b"").is_err());
        assert_eq!(
            decrypt_aes256gcm(&key, &encrypted, b"context-a")
                .unwrap()
                .as_slice(),
            b"payload"
        );
    }

    #[test]
    fn argon2id_derive_and_verify() {
        let passphrase = b"correct horse battery staple";
        let salt = [3u8; 32];
        let params = KdfParams::default();
        let key1 = derive_key_argon2id(passphrase, &salt, params).unwrap();
        let key2 = derive_key_argon2id(passphrase, &salt, params).unwrap();
        assert_eq!(key1, key2);
    }

    #[test]
    fn argon2id_different_passphrase_different_key() {
        let salt = [3u8; 32];
        let params = KdfParams::default();
        let key1 = derive_key_argon2id(b"password1", &salt, params).unwrap();
        let key2 = derive_key_argon2id(b"password2", &salt, params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn argon2id_different_salt_different_key() {
        let params = KdfParams::default();
        let key1 = derive_key_argon2id(b"same-password", &[1u8; 32], params).unwrap();
        let key2 = derive_key_argon2id(b"same-password", &[2u8; 32], params).unwrap();
        assert_ne!(key1, key2);
    }

    #[test]
    fn argon2id_params_roundtrip_via_serde() {
        // KDF params must round-trip through the on-disk JSON format so a
        // vault's stored params (not the code default) drive derivation.
        let params = KdfParams {
            m: 19456,
            t: 2,
            p: 1,
        };
        let json = serde_json::to_string(&params).unwrap();
        let back: KdfParams = serde_json::from_str(&json).unwrap();
        assert_eq!(params, back);

        let salt = [9u8; 32];
        let key_default = derive_key_argon2id(b"pw", &salt, KdfParams::default()).unwrap();
        let key_custom = derive_key_argon2id(b"pw", &salt, back).unwrap();
        assert_ne!(
            key_default, key_custom,
            "different persisted params must derive a different key"
        );
    }

    #[test]
    fn kdf_params_default_matches_v1() {
        let d = KdfParams::default();
        assert_eq!(d.m, 65536);
        assert_eq!(d.t, 3);
        assert_eq!(d.p, 4);
    }

    #[test]
    fn hkdf_subkey_derivation() {
        let master = [42u8; KEY_SIZE];
        let sub1 = derive_subkey(&master, "config-encryption").unwrap();
        let sub2 = derive_subkey(&master, "db-columns").unwrap();
        assert_ne!(sub1, sub2);
        // Same context -> same key (deterministic)
        let sub1b = derive_subkey(&master, "config-encryption").unwrap();
        assert_eq!(sub1, sub1b);
    }

    #[test]
    fn blake3_hash_deterministic() {
        let h1 = hash_blake3(b"hello world");
        let h2 = hash_blake3(b"hello world");
        assert_eq!(h1, h2);
        let h3 = hash_blake3(b"hello World");
        assert_ne!(h1, h3);
    }

    #[test]
    fn random_bytes_unique_and_sized() {
        let r1 = random_bytes::<32>();
        let r2 = random_bytes::<32>();
        assert_ne!(r1, r2);
        assert_eq!(r1.len(), 32);
    }
}
