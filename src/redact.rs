//! Streaming output redaction for `exec --redact`.
//!
//! Every secret injected into a child's environment can, in principle, come
//! straight back out on that child's stdout or stderr (an API echoing a
//! request body, a script that `printf`s what it just exported, a stack
//! trace with an interpolated DSN). Vault injection never leaked the value
//! in either of two real 2026-08-30 incidents; the CHILD's OWN OUTPUT did.
//! This module is the last line of defence: it scrubs every occurrence of
//! every injected secret value (and, where it differs, that value's
//! URL-percent-encoded form) out of a byte stream before it ever reaches a
//! terminal, log file, or agent transcript.
//!
//! Design constraints (see `exec --redact` docs for the user-facing story):
//! - **Opt-in only.** Existing consumers capture exec's passthrough output
//!   verbatim (e.g. `VAR="$(hearth-vault exec ... sh -c 'printf %s "$VAR"')"`
//!   in tachyonac-engine's deploy scripts); redaction must never engage
//!   unless asked for.
//! - **Streaming-safe.** A value split across two `read()` calls must still
//!   be caught. We hold back the last `(longest pattern length - 1)` bytes
//!   of every processed chunk as `carry`, so a match whose completion needs
//!   the next chunk is never flushed early — and never lost.
//! - **Longest-match-wins.** If one secret value is a substring of another
//!   (e.g. a short token that is itself a prefix of a longer one), the
//!   longer match must win outright, never get shredded into two replacements
//!   glued around a false-positive short match. `MatchKind::LeftmostLongest`
//!   gives us this for free within one buffer; the carry-buffer logic below
//!   extends the same guarantee across a chunk boundary.
//! - **Binary-safe.** Operates on raw bytes; child output is not assumed to
//!   be valid UTF-8.
//! - **No secret material in the redactor's own errors/panics.** There are
//!   none of either in this module — it is pure byte-slicing, infallible.

use std::sync::Arc;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

/// Secret values shorter than this are excluded from redaction: short values
/// collide too easily with ordinary output (a 4-byte secret might just be an
/// HTTP status code that happens to match). Documented user-facing floor —
/// keep in sync with `exec --redact`'s help text.
pub const MIN_REDACTABLE_LEN: usize = 8;

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";

/// RFC 3986 "unreserved" percent-encoding: alnum plus `-_.~` pass through
/// unescaped, everything else becomes `%XX` (uppercase hex). This is the
/// form a DSN password typically takes once it's embedded in a URL, and it's
/// usually different from the raw value for any password containing `@`,
/// `:`, `/`, `+`, spaces, etc.
fn percent_encode(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b);
        } else {
            out.push(b'%');
            out.push(HEX_UPPER[(b >> 4) as usize]);
            out.push(HEX_UPPER[(b & 0x0f) as usize]);
        }
    }
    out
}

/// Builds the redaction pattern set for one `exec` invocation and hands out
/// independent [`RedactStream`]s (one per output stream — stdout and
/// stderr each need their own carry buffer, but share the same compiled
/// matcher and replacement table).
#[derive(Clone)]
pub struct Redactor {
    ac: Arc<AhoCorasick>,
    replacements: Arc<Vec<Vec<u8>>>,
    /// Bytes to hold back at the tail of every non-final chunk: the longest
    /// pattern's length minus one. Zero when there is nothing to redact.
    hold_back: usize,
}

impl Redactor {
    /// `secrets` is `(env_var_name, value_bytes)` for every key injected for
    /// this invocation. Values shorter than [`MIN_REDACTABLE_LEN`] bytes are
    /// silently skipped (see module docs). The replacement text for a match
    /// is always `<vault:ENV_VAR_NAME>`.
    pub fn new<'a>(secrets: impl IntoIterator<Item = (&'a str, &'a [u8])>) -> Self {
        let mut patterns: Vec<Vec<u8>> = Vec::new();
        let mut replacements: Vec<Vec<u8>> = Vec::new();

        for (name, value) in secrets {
            if value.len() < MIN_REDACTABLE_LEN {
                continue;
            }
            let placeholder = format!("<vault:{name}>").into_bytes();

            patterns.push(value.to_vec());
            replacements.push(placeholder.clone());

            let encoded = percent_encode(value);
            if encoded != value {
                patterns.push(encoded);
                replacements.push(placeholder);
            }
        }

        let hold_back = patterns
            .iter()
            .map(Vec::len)
            .max()
            .unwrap_or(0)
            .saturating_sub(1);

        // LeftmostLongest: at any position where more than one pattern
        // could match, the longest one wins outright rather than the first
        // one tried — this is what keeps a substring secret from shredding
        // a longer one that contains it.
        let ac = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&patterns)
            .expect("pattern set is a plain list of byte strings; cannot fail to build");

        Self {
            ac: Arc::new(ac),
            replacements: Arc::new(replacements),
            hold_back,
        }
    }

    /// True when this redactor has nothing to redact (e.g. every injected
    /// value was below the length floor). Callers can skip the piped-output
    /// machinery entirely in that case.
    pub fn is_empty(&self) -> bool {
        self.replacements.is_empty()
    }

    /// A fresh, independent stream processor sharing this redactor's
    /// compiled matcher. Each output stream (stdout, stderr) needs its own,
    /// since each carries its own carry buffer.
    pub fn stream(&self) -> RedactStream {
        RedactStream {
            ac: Arc::clone(&self.ac),
            replacements: Arc::clone(&self.replacements),
            hold_back: self.hold_back,
            carry: Vec::new(),
        }
    }
}

/// Per-stream incremental redactor. Feed it chunks in order via
/// [`RedactStream::process`]; call it one final time with `eof: true` (an
/// empty chunk is fine) to flush whatever is still held in the carry buffer.
pub struct RedactStream {
    ac: Arc<AhoCorasick>,
    replacements: Arc<Vec<Vec<u8>>>,
    hold_back: usize,
    carry: Vec<u8>,
}

impl RedactStream {
    /// Feed the next chunk of raw child output. Returns the bytes that are
    /// now safe to forward to the real output stream — anything that might
    /// still be the unfinished prefix of a longer match is held back
    /// internally until the next call (or until `eof: true` forces a final
    /// flush).
    pub fn process(&mut self, chunk: &[u8], eof: bool) -> Vec<u8> {
        let mut buf = std::mem::take(&mut self.carry);
        buf.extend_from_slice(chunk);

        // At EOF nothing more is coming, so there is no reason to withhold
        // a tail — flush everything.
        let hold_back = if eof { 0 } else { self.hold_back };
        let safe_len = buf.len().saturating_sub(hold_back);

        let mut out = Vec::with_capacity(buf.len());
        let mut cursor = 0usize;
        // Matches are LeftmostLongest and therefore non-overlapping and
        // strictly increasing in position.
        for m in self.ac.find_iter(&buf) {
            if m.end() > safe_len {
                // This match (or, if EOF, nothing — since safe_len ==
                // buf.len() at EOF, this branch is unreachable there) lands
                // in the withheld tail. Stop applying matches; everything
                // from its start onward goes back into carry so a longer
                // continuation across the next chunk boundary still wins.
                let carry_from = cursor.max(m.start()).min(safe_len);
                out.extend_from_slice(&buf[cursor..carry_from]);
                self.carry = buf[carry_from..].to_vec();
                return out;
            }
            out.extend_from_slice(&buf[cursor..m.start()]);
            out.extend_from_slice(&self.replacements[m.pattern()]);
            cursor = m.end();
        }

        out.extend_from_slice(&buf[cursor..safe_len]);
        self.carry = buf[safe_len..].to_vec();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redactor(secrets: &[(&str, &str)]) -> Redactor {
        Redactor::new(secrets.iter().map(|(n, v)| (*n, v.as_bytes())))
    }

    /// 1. A value split exactly across a chunk boundary is still redacted.
    #[test]
    fn value_split_across_chunk_boundary_is_redacted() {
        let secret = "correct-horse-battery-staple-42"; // fixture, not real
        let r = redactor(&[("DB_PASSWORD", secret)]);
        let mut s = r.stream();

        let mid = secret.len() / 2;
        let (first, second) = secret.split_at(mid);
        let prefix = b"before=";
        let suffix = b"=after";

        let mut out = Vec::new();
        out.extend(s.process(&[prefix.as_slice(), first.as_bytes()].concat(), false));
        out.extend(s.process(&[second.as_bytes(), suffix.as_slice()].concat(), true));

        let out = String::from_utf8(out).unwrap();
        assert!(
            !out.contains(secret),
            "raw secret leaked across chunk boundary: {out}"
        );
        assert_eq!(out, "before=<vault:DB_PASSWORD>=after");
    }

    /// Case 2: two secrets where one is a byte-for-byte substring of the
    /// other — the longer one must win, not get shredded around the short
    /// match.
    #[test]
    fn substring_secret_does_not_shred_the_longer_one() {
        let short = "tok_abcdefgh"; // fixture
        let long = "tok_abcdefgh_extended_suffix_value"; // fixture, contains `short` as a prefix
        assert!(long.contains(short));

        let r = redactor(&[("SHORT_TOKEN", short), ("LONG_TOKEN", long)]);
        let mut s = r.stream();

        let out = s.process(format!("x={long}&y=1").as_bytes(), true);
        let out = String::from_utf8(out).unwrap();

        assert!(!out.contains(short), "short pattern leaked: {out}");
        assert!(!out.contains(long), "long secret leaked: {out}");
        assert_eq!(out, "x=<vault:LONG_TOKEN>&y=1");
    }

    /// 3. The URL-percent-encoded form of a value is matched too.
    #[test]
    fn percent_encoded_form_in_a_url_is_redacted() {
        let raw = "p@ss:w/ord+123"; // fixture DSN-style password with reserved chars
        let encoded = percent_encode(raw.as_bytes());
        assert_ne!(
            encoded,
            raw.as_bytes(),
            "fixture must actually need encoding"
        );

        let r = redactor(&[("DATABASE_PASSWORD", raw)]);
        let mut s = r.stream();

        let mut url = b"postgres://user:".to_vec();
        url.extend_from_slice(&encoded);
        url.extend_from_slice(b"@host:5432/db\n");

        let out = s.process(&url, true);
        let out = String::from_utf8(out).unwrap();

        assert!(!out.contains(raw), "raw password leaked: {out}");
        assert!(
            out.contains("<vault:DATABASE_PASSWORD>"),
            "expected placeholder not found: {out}"
        );
    }

    /// Case 4: multi-megabyte throughput sanity — a streaming matcher should
    /// not blow up quadratically. This is a smoke test on wall-clock
    /// behavior, not a strict benchmark; it just needs to finish fast.
    #[test]
    fn multi_megabyte_stream_has_no_quadratic_blowup() {
        let secret = "quadratic-blowup-canary-fixture-value"; // fixture
        let r = redactor(&[("CANARY", secret)]);
        let mut s = r.stream();

        let filler = "x".repeat(8192);
        let chunks = 512; // ~4 MiB of filler plus scattered secrets
        let start = std::time::Instant::now();
        let mut redacted_count = 0usize;
        for i in 0..chunks {
            let mut chunk = filler.clone().into_bytes();
            if i % 37 == 0 {
                chunk.extend_from_slice(secret.as_bytes());
                redacted_count += 1;
            }
            let out = s.process(&chunk, false);
            assert!(
                !String::from_utf8_lossy(&out).contains(secret),
                "secret leaked mid-stream"
            );
        }
        let out = s.process(&[], true);
        assert!(!String::from_utf8_lossy(&out).contains(secret));

        let elapsed = start.elapsed();
        assert!(
            elapsed.as_secs() < 5,
            "streaming ~4MiB took suspiciously long ({elapsed:?}); check for quadratic behavior"
        );
        assert!(
            redacted_count > 0,
            "test fixture produced no secret occurrences"
        );
    }

    /// Case 5: a value that ends exactly at end-of-stream is still flushed
    /// and redacted by the final `eof: true` call, not silently dropped.
    #[test]
    fn carry_buffer_flushes_at_eof_when_value_ends_the_stream() {
        let secret = "trailing-value-ends-the-stream-fixture"; // fixture
        let r = redactor(&[("API_KEY", secret)]);
        let mut s = r.stream();

        let mut out = Vec::new();
        out.extend(s.process(b"prefix=", false));
        // The secret itself is the very last thing written before EOF.
        out.extend(s.process(secret.as_bytes(), true));

        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains(secret), "secret leaked at EOF: {out}");
        assert_eq!(out, "prefix=<vault:API_KEY>");
    }

    /// Values below the length floor are never redacted (and never crash
    /// pattern construction with an empty-pattern edge case).
    #[test]
    fn short_values_below_floor_are_skipped() {
        let r = redactor(&[("TINY", "short")]); // 5 bytes < MIN_REDACTABLE_LEN
        assert!(r.is_empty());
        let mut s = r.stream();
        let out = s.process(b"contains short in it", true);
        assert_eq!(out, b"contains short in it");
    }

    /// No injected secrets at all still yields a working (no-op) stream.
    #[test]
    fn empty_secret_set_is_a_no_op() {
        let r = redactor(&[]);
        assert!(r.is_empty());
        let mut s = r.stream();
        assert_eq!(s.process(b"hello world", true), b"hello world");
    }
}
