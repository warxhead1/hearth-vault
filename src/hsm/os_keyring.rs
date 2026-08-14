//! OS keyring backend — Linux (libsecret/kernel-keyring), macOS (Keychain), Windows (DPAPI).
//! Uses the `keyring` crate which abstracts all three.
//! Security: Tier 2. Protected by OS credential storage, not extractable by file copy.

use crate::hsm::{HsmError, SecretBackend};
use keyring::Entry;
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "hearth-vault";

pub struct OsKeyringBackend;

impl OsKeyringBackend {
    pub fn new() -> Self {
        OsKeyringBackend
    }

    /// Returns true if the OS keyring is functional.
    ///
    /// This is a read-only probe against a name that (almost certainly)
    /// doesn't exist: a `NoEntry` error still proves the keyring service
    /// itself is reachable. This deliberately avoids the old
    /// create-then-delete probe, which on macOS could trigger a Keychain
    /// access prompt and on Linux forced a D-Bus round trip through the
    /// secret-service daemon for a write it immediately threw away.
    pub fn is_available() -> bool {
        let Ok(entry) = Entry::new(SERVICE_NAME, "hearth-vault-availability-probe") else {
            return false;
        };
        match entry.get_password() {
            // Service reachable, no such entry — exactly what we expect.
            Ok(_) | Err(keyring::Error::NoEntry) => true,
            // Anything else (no backend, platform failure, access denied at
            // the service level, ...) means the keyring is not usable.
            Err(_) => false,
        }
    }
}

impl Default for OsKeyringBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBackend for OsKeyringBackend {
    fn seal(&self, plaintext: &[u8], label: &str) -> Result<Vec<u8>, HsmError> {
        // Encode as hex for keyring storage (keyring stores strings)
        let hex: String = plaintext.iter().map(|b| format!("{b:02x}")).collect();
        let entry =
            Entry::new(SERVICE_NAME, label).map_err(|e| HsmError::SealFailed(e.to_string()))?;
        entry
            .set_password(&hex)
            .map_err(|e| HsmError::SealFailed(e.to_string()))?;
        // Blob = label bytes (actual secret lives in keyring)
        Ok(label.as_bytes().to_vec())
    }

    fn unseal(&self, blob: &[u8], label: &str) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        let stored_label = std::str::from_utf8(blob).unwrap_or(label);
        let entry = Entry::new(SERVICE_NAME, stored_label)
            .map_err(|e| HsmError::UnsealFailed(e.to_string()))?;
        let hex = entry
            .get_password()
            .map_err(|e| HsmError::UnsealFailed(format!("keyring read failed: {e}")))?;
        let bytes = hex_decode(&hex)
            .map_err(|_| HsmError::UnsealFailed("invalid hex in keyring".into()))?;
        Ok(Zeroizing::new(bytes))
    }

    fn name(&self) -> &'static str {
        "os-keyring"
    }
    fn tier(&self) -> u8 {
        2
    }
}

fn hex_decode(hex: &str) -> Result<Vec<u8>, ()> {
    if hex.len() % 2 != 0 {
        return Err(());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hsm::SecretBackend;

    #[test]
    #[ignore = "requires OS keyring — run with: cargo test --features os-keyring -- --ignored"]
    fn test_os_keyring_roundtrip() {
        if !OsKeyringBackend::is_available() {
            println!("OS keyring not available — skipping");
            return;
        }
        let backend = OsKeyringBackend::new();
        let secret = b"tier2-test-secret";
        let blob = backend.seal(secret, "hearth-test").expect("seal");
        let unsealed = backend.unseal(&blob, "hearth-test").expect("unseal");
        assert_eq!(&*unsealed, secret);
    }

    #[test]
    fn test_hex_decode_roundtrip() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, "deadbeef");
        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("a").is_err()); // odd length
    }
}
