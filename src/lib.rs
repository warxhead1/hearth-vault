//! hearth-vault: a secrets vault built so coding agents can use your keys
//! without ever seeing them.

/// Unix-only: `AF_UNIX` is not exposed by std on Windows, and the agent's
/// reason to exist (amortising Argon2id) is already covered there by the
/// keyring auto-unseal path.
#[cfg(unix)]
pub mod agent;
pub mod crypto;
pub mod hsm;
pub mod redact;
pub mod scan;
pub mod sensitive;
pub mod share;
pub mod store;

pub use sensitive::SensitiveString;
pub use store::{RotationState, TIER_MAX, TIER_SIGN_ONLY, TIER_USE_ONLY, VaultEntry, VaultStore};
