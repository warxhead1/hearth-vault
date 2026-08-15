//! OS keyring backend — tier 2. The secret lives in the platform credential
//! store rather than in the vault file, so copying the file does not carry it.
//!
//! Via the `keyring` crate, with the native backend selected per target in
//! Cargo.toml (keyring ships NO backend by default and silently falls back to
//! an in-memory mock, which would make this tier a no-op — see the comment
//! there):
//!
//! - **Linux** — Secret Service over D-Bus (`async-secret-service`/zbus, pure
//!   Rust). Needs a running secret-service daemon; absent one, this backend
//!   reports unavailable and the caller falls back to a lower tier.
//! - **macOS** — Keychain (`apple-native`), the user's default keychain.
//! - **Windows** — Credential Manager (`windows-native`).
//!
//! Every call here is time-bounded; see [`with_deadline`] for why that is not
//! optional.

use crate::hsm::{HsmError, SecretBackend};
use keyring::Entry;
use std::sync::mpsc;
use std::time::Duration;
use zeroize::Zeroizing;

const SERVICE_NAME: &str = "hearth-vault";

/// How long an availability probe may take. A probe is a read of an entry
/// that does not exist; it should never prompt, so it should be quick.
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Default budget for a real keyring read/write. Generous on purpose: on
/// macOS the first access to an item pops a Keychain dialog, and a human
/// needs time to click it. Override with `HEARTH_VAULT_KEYRING_TIMEOUT_SECS`.
const DEFAULT_OP_TIMEOUT_SECS: u64 = 30;

fn op_timeout() -> Duration {
    match std::env::var("HEARTH_VAULT_KEYRING_TIMEOUT_SECS") {
        Ok(v) => match v.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => Duration::from_secs(secs),
            _ => Duration::from_secs(DEFAULT_OP_TIMEOUT_SECS),
        },
        Err(_) => Duration::from_secs(DEFAULT_OP_TIMEOUT_SECS),
    }
}

/// Run a blocking keyring call with a deadline, yielding `None` if it does
/// not answer in time.
///
/// Every call into the OS keyring can block indefinitely, and not
/// hypothetically: writing to a LOCKED Linux Secret Service collection makes
/// the daemon raise an unlock prompt and wait for a prompter that an SSH
/// session, a CI job, or an agent tool call does not have. Measured on a
/// locked desktop keyring, `is_available()` answered in 28ms and the
/// subsequent write never returned at all. A tool whose whole purpose is to
/// be safe to invoke from an agent must not be able to wedge that agent, so
/// every keyring operation gets a deadline and a real error instead.
///
/// ponytail: the worker thread is detached and may outlive the deadline,
/// still parked on the OS call. Harmless for a short-lived CLI; revisit if
/// this backend is ever driven from a long-lived process.
fn with_deadline<T, F>(budget: Duration, f: F) -> Option<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(budget).ok()
}

fn timeout_error(op: &str) -> String {
    format!(
        "the OS keyring did not respond within {}s during {op}. \
         This usually means the keyring is locked and is waiting on an \
         unlock prompt that nothing here can answer — unlock it \
         (Linux: `secret-tool`/your keyring UI; macOS: Keychain Access), or \
         use a different tier. Raise the budget with \
         HEARTH_VAULT_KEYRING_TIMEOUT_SECS.",
        op_timeout().as_secs()
    )
}

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
    ///
    /// The probe is time-bounded because it can otherwise block forever: on
    /// a Linux desktop whose keyring is LOCKED, the Secret Service call sits
    /// waiting on an unlock prompt that nothing in an SSH session, a CI job,
    /// or an agent tool call will ever answer. Hanging the CLI is strictly
    /// worse than reporting "unavailable" and falling back to a tier that
    /// works, so a probe that does not answer promptly counts as a no.
    /// Note this proves the keyring *service* is reachable, not that it is
    /// unlocked: a locked collection answers reads of a missing entry
    /// immediately and still blocks on writes. `seal` carries its own
    /// deadline for exactly that reason.
    pub fn is_available() -> bool {
        with_deadline(PROBE_TIMEOUT, || {
            match Entry::new(SERVICE_NAME, "hearth-vault-availability-probe") {
                // Service reachable, no such entry — exactly what we expect.
                Ok(entry) => matches!(entry.get_password(), Ok(_) | Err(keyring::Error::NoEntry)),
                // Anything else (no backend, platform failure, access denied
                // at the service level, ...) means the keyring is not usable.
                Err(_) => false,
            }
        })
        .unwrap_or(false)
    }
}

impl Default for OsKeyringBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBackend for OsKeyringBackend {
    fn seal(&self, plaintext: &[u8], label: &str) -> Result<Vec<u8>, HsmError> {
        // Encode as hex for keyring storage (keyring stores strings). This
        // string IS the master key in the clear; it is moved into the worker
        // closure, so it is wrapped rather than left to an ordinary drop.
        let hex = Zeroizing::new(
            plaintext
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        );
        let owned_label = label.to_string();
        with_deadline(op_timeout(), move || {
            let entry = Entry::new(SERVICE_NAME, &owned_label).map_err(|e| e.to_string())?;
            entry.set_password(&hex).map_err(|e| e.to_string())
        })
        .ok_or_else(|| HsmError::SealFailed(timeout_error("write")))?
        .map_err(HsmError::SealFailed)?;
        // Blob = label bytes (actual secret lives in keyring)
        Ok(label.as_bytes().to_vec())
    }

    fn unseal(&self, blob: &[u8], label: &str) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        let stored_label = std::str::from_utf8(blob).unwrap_or(label).to_string();
        let hex = Zeroizing::new(
            with_deadline(op_timeout(), move || {
                let entry = Entry::new(SERVICE_NAME, &stored_label).map_err(|e| e.to_string())?;
                entry
                    .get_password()
                    .map_err(|e| format!("keyring read failed: {e}"))
            })
            .ok_or_else(|| HsmError::UnsealFailed(timeout_error("read")))?
            .map_err(HsmError::UnsealFailed)?,
        );
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

    /// Seal with one backend instance, unseal with another.
    ///
    /// Using two instances is the point, not incidental: `keyring`'s
    /// in-memory `mock` store -- which it silently substitutes when no
    /// platform backend feature is enabled -- hands out a fresh empty
    /// credential per `Entry`, so a mock passes a single-instance roundtrip
    /// and fails this one. That is precisely how the missing `apple-native`
    /// feature was caught. This test is the only thing standing between a
    /// tier-2 secret and a store that quietly forgets it.
    #[test]
    #[ignore = "requires OS keyring — run with: cargo test --features os-keyring -- --ignored"]
    fn test_os_keyring_roundtrip() {
        if !OsKeyringBackend::is_available() {
            // On platforms whose keyring must work (macOS/Windows CI), a
            // skip here would be a false pass -- the exact failure mode this
            // test exists to prevent. Let CI demand that it really ran.
            assert!(
                std::env::var_os("HEARTH_VAULT_REQUIRE_KEYRING").is_none(),
                "HEARTH_VAULT_REQUIRE_KEYRING is set but the OS keyring reports unavailable"
            );
            println!("OS keyring not available — skipping");
            return;
        }
        let secret = b"tier2-test-secret";
        let blob = OsKeyringBackend::new()
            .seal(secret, "hearth-test")
            .expect("seal");
        let unsealed = OsKeyringBackend::new()
            .unseal(&blob, "hearth-test")
            .expect("unseal");
        assert_eq!(&*unsealed, secret);
    }

    /// The whole point of the deadline: a call that never returns must not
    /// become a process that never returns.
    #[test]
    fn with_deadline_gives_up_on_a_call_that_never_answers() {
        let start = std::time::Instant::now();
        let result = with_deadline(Duration::from_millis(50), || {
            std::thread::sleep(Duration::from_secs(60));
            "should never be seen"
        });
        assert!(result.is_none(), "a hung call must not produce a value");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "with_deadline waited {:?}, so it did not enforce its deadline",
            start.elapsed()
        );
    }

    #[test]
    fn with_deadline_passes_through_a_prompt_answer() {
        assert_eq!(with_deadline(Duration::from_secs(5), || 42), Some(42));
    }

    #[test]
    #[serial_test::serial]
    fn op_timeout_honours_the_env_override_and_rejects_nonsense() {
        // SAFETY: guarded by #[serial], so no other test reads env concurrently.
        unsafe {
            std::env::set_var("HEARTH_VAULT_KEYRING_TIMEOUT_SECS", "7");
            assert_eq!(op_timeout(), Duration::from_secs(7));

            // A malformed or zero budget must fall back to the default
            // rather than becoming an instant-timeout that breaks every
            // legitimate keyring write.
            for bad in ["0", "-1", "abc", ""] {
                std::env::set_var("HEARTH_VAULT_KEYRING_TIMEOUT_SECS", bad);
                assert_eq!(
                    op_timeout(),
                    Duration::from_secs(DEFAULT_OP_TIMEOUT_SECS),
                    "{bad:?} should fall back to the default"
                );
            }
            std::env::remove_var("HEARTH_VAULT_KEYRING_TIMEOUT_SECS");
        }
        assert_eq!(op_timeout(), Duration::from_secs(DEFAULT_OP_TIMEOUT_SECS));
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
