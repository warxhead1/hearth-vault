//! [`SensitiveString`]: a string that never leaks in Debug/Display output and
//! is zeroized when dropped. This is the only type carried over from the
//! vendored file — `EncryptedField`/`ColumnCrypto` needed DB machinery that
//! is not part of this crate.

use serde::Serialize;
use zeroize::Zeroize;

/// A string that is zeroized when dropped and never revealed via Debug/Display.
#[derive(Clone)]
pub struct SensitiveString {
    inner: String,
}

impl SensitiveString {
    /// Create a new sensitive string.
    pub fn new(s: impl Into<String>) -> Self {
        Self { inner: s.into() }
    }

    /// Access the sensitive value.
    pub fn as_str(&self) -> &str {
        &self.inner
    }

    /// Consume and return the inner value. Caller takes ownership of
    /// zeroize responsibility.
    pub fn into_inner(self) -> String {
        // Move out without triggering Drop's zeroize.
        let mut this = std::mem::ManuallyDrop::new(self);
        // SAFETY: We are taking ownership of the String before ManuallyDrop
        // prevents the Drop impl from running. The ManuallyDrop wrapper
        // itself is just a newtype and doesn't affect memory layout.
        std::mem::take(&mut this.inner)
    }

    /// Returns true if the inner string is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Returns the length in bytes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }
}

impl Drop for SensitiveString {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SensitiveString(***)")
    }
}

impl std::fmt::Display for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "***")
    }
}

impl PartialEq for SensitiveString {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl Eq for SensitiveString {}

impl From<String> for SensitiveString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl From<&str> for SensitiveString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

// Serialize as plaintext — callers that need this on the wire/at rest are
// responsible for encrypting the envelope around it (see store.rs, which
// never serializes a SensitiveString directly: it unwraps to a plain String
// before folding it into the encrypted VaultBody).
impl Serialize for SensitiveString {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.inner.serialize(serializer)
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sensitive_string_debug_does_not_leak() {
        let s = SensitiveString::new("super-secret-api-key");
        let debug = format!("{:?}", s);
        assert!(!debug.contains("super-secret-api-key"));
        assert!(debug.contains("***"));
    }

    #[test]
    fn sensitive_string_display_does_not_leak() {
        let s = SensitiveString::new("password123");
        let display = format!("{}", s);
        assert!(!display.contains("password123"));
        assert_eq!(display, "***");
    }

    #[test]
    fn sensitive_string_access() {
        let s = SensitiveString::new("my-secret");
        assert_eq!(s.as_str(), "my-secret");
        assert_eq!(s.len(), 9);
        assert!(!s.is_empty());
    }

    #[test]
    fn sensitive_string_empty() {
        let s = SensitiveString::new("");
        assert!(s.is_empty());
        assert_eq!(s.len(), 0);
    }

    #[test]
    fn sensitive_string_equality() {
        let a = SensitiveString::new("same");
        let b = SensitiveString::new("same");
        let c = SensitiveString::new("different");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn sensitive_string_from_conversions() {
        let s: SensitiveString = "hello".into();
        assert_eq!(s.as_str(), "hello");
        let s2: SensitiveString = String::from("world").into();
        assert_eq!(s2.as_str(), "world");
    }

    #[test]
    fn sensitive_string_serde_roundtrip() {
        let s = SensitiveString::new("secret-value");
        let json = serde_json::to_string(&s).unwrap();
        // Serializes as a plain string; encryption happens at the store boundary.
        assert_eq!(json, "\"secret-value\"");
    }

    #[test]
    fn sensitive_string_into_inner() {
        let s = SensitiveString::new("take-ownership");
        let inner = s.into_inner();
        assert_eq!(inner, "take-ownership");
    }

    #[test]
    fn sensitive_string_zeroize_on_drop() {
        // We can't directly assert on memory contents post-free, but we
        // verify the Drop impl runs without panicking.
        let s = SensitiveString::new("will-be-zeroized");
        assert_eq!(s.as_str(), "will-be-zeroized");
        drop(s);
    }
}
