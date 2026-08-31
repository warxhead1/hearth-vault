//! Linux host-bound sealing through `systemd-creds`.
//!
//! This backend is intended for headless system services on machines without
//! a TPM or Secret Service. `systemd-creds --with-key=host` encrypts with a
//! root-owned host key under `/var/lib/systemd/credential.secret`; the clear
//! value exists only in this process and the short-lived helper pipes. It is
//! OS-protected rather than hardware-backed: root or a full host compromise
//! can recover it, and moving the encrypted blob to another host will fail.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use zeroize::Zeroizing;

use super::{HsmError, SecretBackend};

pub struct SystemdCredsBackend;

impl SystemdCredsBackend {
    pub fn new() -> Self {
        Self
    }

    fn program() -> PathBuf {
        // Integration tests need a hermetic helper. Release builds do not
        // compile this override at all; production always executes the
        // trusted absolute system path instead of searching root's PATH.
        #[cfg(debug_assertions)]
        if let Some(path) = std::env::var_os("HEARTH_VAULT_TEST_SYSTEMD_CREDS") {
            return PathBuf::from(path);
        }
        PathBuf::from("/usr/bin/systemd-creds")
    }

    fn test_override_active() -> bool {
        #[cfg(debug_assertions)]
        {
            std::env::var_os("HEARTH_VAULT_TEST_SYSTEMD_CREDS").is_some()
        }
        #[cfg(not(debug_assertions))]
        false
    }

    pub fn is_available() -> bool {
        cfg!(target_os = "linux")
            && (Self::test_override_active() || unsafe { libc::geteuid() } == 0)
            && Path::new(&Self::program()).is_file()
            && Command::new(Self::program())
                .arg("--version")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| status.success())
    }

    fn run(&self, action: &str, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        let mut command = Command::new(Self::program());
        command
            .arg(action)
            .arg("--name=hearth-vault")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if action == "encrypt" {
            command.arg("--with-key=host");
        }
        command.arg("-").arg("-");

        let mut child = command.spawn().map_err(|e| {
            if action == "encrypt" {
                HsmError::SealFailed(format!("start systemd-creds: {e}"))
            } else {
                HsmError::UnsealFailed(format!("start systemd-creds: {e}"))
            }
        })?;
        child
            .stdin
            .take()
            .ok_or_else(|| HsmError::Io(std::io::Error::other("systemd-creds stdin missing")))?
            .write_all(input)?;
        let output = child.wait_with_output()?;
        if !output.status.success() {
            let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let detail = if detail.is_empty() {
                format!("systemd-creds exited {}", output.status)
            } else {
                detail
            };
            return Err(if action == "encrypt" {
                HsmError::SealFailed(detail)
            } else {
                HsmError::UnsealFailed(detail)
            });
        }
        Ok(Zeroizing::new(output.stdout))
    }
}

impl Default for SystemdCredsBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretBackend for SystemdCredsBackend {
    fn seal(&self, plaintext: &[u8], _label: &str) -> Result<Vec<u8>, HsmError> {
        Ok(self.run("encrypt", plaintext)?.to_vec())
    }

    fn unseal(&self, blob: &[u8], _label: &str) -> Result<Zeroizing<Vec<u8>>, HsmError> {
        self.run("decrypt", blob)
    }

    fn name(&self) -> &'static str {
        "systemd-creds-host"
    }

    fn tier(&self) -> u8 {
        2
    }
}
