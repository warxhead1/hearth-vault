//! hearth-vault: a secrets vault built so coding agents can use your keys
//! without ever seeing them.

pub mod crypto;
pub mod hsm;
pub mod scan;
pub mod sensitive;
pub mod store;

pub use sensitive::SensitiveString;
pub use store::{TIER_MAX, TIER_SIGN_ONLY, TIER_USE_ONLY, VaultEntry, VaultStore};
