//! Hardware-backed secrets for hearth-vault.
//!
//! # Backend priority (highest available wins)
//! - Tier 1: TPM2 (Linux, PCR0-sealed) — `tpm2` feature (opt-in, Linux-only)
//! - Tier 2: OS keyring (Linux kernel keyring / Windows DPAPI / macOS Keychain) — `os-keyring` feature
//!
//! There is deliberately no software tier. A backend exists here for exactly
//! one job: sealing the vault passphrase to disk so it can be recovered
//! *without* the passphrase. A "software backend" would have to key that seal
//! off the passphrase it is protecting, which protects nothing — you would
//! need the secret to recover the secret. The previous implementation hid
//! that circularity by keying off a `HEARTH_CONFIG_KEY` environment variable,
//! i.e. a second master secret sitting in the process environment, readable
//! from `/proc/<pid>/environ` and inherited by every child. Both are gone.
//!
//! Headless Linux root services may use the explicit `systemd-creds` backend.
//! It is host-bound OS protection, not hardware: root compromise can decrypt
//! it, and systemd warns when its host key is not itself on encrypted media.
//! Interactive users without a hardware/keyring backend still type a
//! passphrase. The vault contents remain Argon2id + AES-256-GCM encrypted at
//! rest either way.

use zeroize::Zeroizing;

pub mod platform;

#[cfg(all(feature = "tpm2", target_os = "linux"))]
pub mod tpm2;

#[cfg(feature = "os-keyring")]
pub mod os_keyring;

#[cfg(target_os = "linux")]
pub mod systemd_creds;

/// Error type for HSM operations.
#[derive(Debug, thiserror::Error)]
pub enum HsmError {
    #[error("backend unavailable: {0}")]
    Unavailable(String),
    #[error("seal failed: {0}")]
    SealFailed(String),
    #[error("unseal failed — wrong backend, wrong machine, or PCR mismatch: {0}")]
    UnsealFailed(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Platform-agnostic secret sealing interface.
///
/// # Label semantics
/// The `label` parameter is advisory — backends use it as a key name for
/// storage, not as cryptographic domain separation. Do not rely on labels to
/// isolate one sealed blob from another across untrusted contexts.
pub trait SecretBackend: Send + Sync {
    /// Seal plaintext bytes. Returns an opaque blob suitable for storing on disk.
    fn seal(&self, plaintext: &[u8], label: &str) -> Result<Vec<u8>, HsmError>;
    /// Unseal a previously sealed blob. Returns zeroizing plaintext.
    fn unseal(&self, blob: &[u8], label: &str) -> Result<Zeroizing<Vec<u8>>, HsmError>;
    /// Human-readable backend name.
    fn name(&self) -> &'static str;
    /// Security tier: 1=hardware, 2=OS-protected, 3=software.
    fn tier(&self) -> u8;
}

#[cfg(feature = "os-keyring")]
pub use os_keyring::OsKeyringBackend;

/// Platform-appropriate advice for upgrading out of the Tier-3 software
/// fallback. The old message ("install tpm2-tools, add user to tss group")
/// is Linux-only and actively wrong on macOS/Windows.
fn tier3_advice() -> &'static str {
    if cfg!(target_os = "linux") {
        "Install tpm2-tools and add your user to the `tss` group for Tier-1 \
         hardware protection, or check that the OS keyring / D-Bus secret \
         service is reachable for Tier-2."
    } else if cfg!(target_os = "macos") {
        "Tier-2 protection should come from the macOS Keychain automatically; \
         if this warning persists, check Keychain Access permissions for this \
         binary."
    } else if cfg!(target_os = "windows") {
        "Tier-2 protection should come from Windows Credential Manager (DPAPI) \
         automatically; if this warning persists, confirm the `os-keyring` \
         feature was compiled into this build."
    } else {
        "No hardware or OS-keyring backend is available on this platform."
    }
}

/// Resolve a specific backend by name, for the CLI's `--backend {tpm2,keyring}`
/// flag. Lets a user in a degraded environment (WSL, container, CI) pin the
/// backend instead of relying on auto-detection.
pub fn backend_named(name: &str) -> anyhow::Result<Box<dyn SecretBackend>> {
    match name {
        "tpm2" => tpm2_backend(),
        "keyring" => keyring_backend(),
        "systemd-creds" => systemd_creds_backend(),
        other => {
            anyhow::bail!(
                "unknown backend '{other}' — expected one of: tpm2, keyring, systemd-creds"
            )
        }
    }
}

fn systemd_creds_backend() -> anyhow::Result<Box<dyn SecretBackend>> {
    #[cfg(target_os = "linux")]
    {
        if !systemd_creds::SystemdCredsBackend::is_available() {
            anyhow::bail!(
                "systemd-creds backend requested but unavailable — install systemd-creds and run as the service owner"
            );
        }
        Ok(Box::new(systemd_creds::SystemdCredsBackend::new()))
    }
    #[cfg(not(target_os = "linux"))]
    {
        anyhow::bail!("systemd-creds backend is Linux-only")
    }
}

fn tpm2_backend() -> anyhow::Result<Box<dyn SecretBackend>> {
    #[cfg(all(feature = "tpm2", target_os = "linux"))]
    {
        if !tpm2::Tpm2Backend::is_available() {
            anyhow::bail!(
                "tpm2 backend requested but unavailable — is /dev/tpmrm0 present and is this \
                 user in the `tss` group?"
            );
        }
        Ok(Box::new(tpm2::Tpm2Backend::new()))
    }
    #[cfg(not(all(feature = "tpm2", target_os = "linux")))]
    {
        anyhow::bail!(
            "tpm2 backend requested but this build lacks the `tpm2` feature (Linux-only; \
             rebuild with `--features tpm2` and install tpm2-tools / libtss2-dev)"
        )
    }
}

fn keyring_backend() -> anyhow::Result<Box<dyn SecretBackend>> {
    #[cfg(feature = "os-keyring")]
    {
        if !os_keyring::OsKeyringBackend::is_available() {
            anyhow::bail!("keyring backend requested but the OS keyring service is not reachable");
        }
        Ok(Box::new(os_keyring::OsKeyringBackend::new()))
    }
    #[cfg(not(feature = "os-keyring"))]
    {
        anyhow::bail!("keyring backend requested but this build lacks the `os-keyring` feature")
    }
}

/// Auto-detect and return the highest available security tier backend.
///
/// Headless root services may fall back to host-bound systemd credentials;
/// ordinary users still fail closed rather than reading a second master
/// secret from the process environment.
pub fn detect_backend() -> anyhow::Result<Box<dyn SecretBackend>> {
    #[cfg(all(feature = "tpm2", target_os = "linux"))]
    if tpm2::Tpm2Backend::is_available() {
        tracing::info!("HSM: using Tier-1 TPM2 backend (PCR0-sealed)");
        return Ok(Box::new(tpm2::Tpm2Backend::new()));
    }

    #[cfg(feature = "os-keyring")]
    if os_keyring::OsKeyringBackend::is_available() {
        tracing::info!("HSM: using Tier-2 OS keyring backend");
        return Ok(Box::new(os_keyring::OsKeyringBackend::new()));
    }

    #[cfg(target_os = "linux")]
    if systemd_creds::SystemdCredsBackend::is_available() {
        tracing::info!("HSM: using Tier-2 systemd credential backend");
        return Ok(Box::new(systemd_creds::SystemdCredsBackend::new()));
    }

    anyhow::bail!(
        "no hardware-backed secret store is available on this machine, so the vault \
         passphrase cannot be sealed for automatic unlock. Enter your passphrase \
         interactively, or set HEARTH_VAULT_PASSPHRASE for non-interactive use. {}",
        tier3_advice()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_backend_never_panics_and_reports_a_hardware_tier() {
        // On this box a Tier-1/Tier-2 backend may or may not be reachable;
        // either outcome is fine. What must never happen is a panic, and it
        // must never silently read HEARTH_CONFIG_KEY out of the environment
        // (that env var no longer exists anywhere in this codebase).
        match detect_backend() {
            Ok(b) => {
                // Only hardware-backed tiers exist now — a returned backend is
                // never a software fallback.
                assert!(b.tier() == 1 || b.tier() == 2);
                assert!(!b.name().is_empty());
            }
            Err(e) => {
                // The failure must tell the user what to do instead.
                let msg = e.to_string();
                assert!(msg.contains("passphrase"), "unhelpful error: {msg}");
            }
        }
    }

    #[test]
    fn test_backend_named_rejects_software_and_unknown_names() {
        // There is deliberately no software backend: it would have to key the
        // passphrase seal off the passphrase it protects. Asking for one by
        // name is an error, not a degraded success.
        assert!(backend_named("software").is_err());
        assert!(backend_named("bogus").is_err());
    }
}
