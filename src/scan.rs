//! Gitleaks-style secret scanner: find credentials a user doesn't know are
//! lying around their repo, so they can migrate them into the vault with
//! `hearth-vault scan --adopt` instead.
//!
//! # Output is always redacted
//! Every [`Finding`] this module produces carries only a [`redact`]ed
//! preview of the matched value — never the raw secret. That is a hard
//! invariant, not a convenience: it is why `hearth-vault scan` is exempt
//! from the CLI's non-TTY refusal policy (see `main.rs`'s `refuse_if_non_tty`
//! doc comment) — nothing this module emits is a usable credential, so
//! there is nothing for that guard to protect against. Do not add a code
//! path that prints `secret_str` (or any substring longer than the redacted
//! preview) anywhere, including `--json` output, error messages, or `note!`
//! logging — doing so would silently invalidate that exemption.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;

/// One detection rule: a name, a human description, a regex pattern, and an
/// optional minimum Shannon-entropy gate applied to the matched value (or
/// its `secret` capture group, if the pattern defines one).
///
/// Patterns that need to isolate the candidate secret from surrounding
/// syntax (e.g. `key = "value"`) should use a named capture group called
/// `secret`; [`scan_path`] prefers that group over the whole match when
/// present. A pattern may additionally define a `keyname` capture group
/// (used only by the generic-assignment rule) to recover the variable name
/// being assigned, which feeds `suggested_key` derivation.
pub struct Rule {
    pub id: &'static str,
    pub description: &'static str,
    pub pattern: &'static str,
    pub min_entropy: Option<f64>,
}

/// The rule table. Gitleaks-style: match on the *shape* of the secret
/// itself, not on suggestive variable names. Two rules at the end
/// (`generic-assignment` and the `generic-high-entropy-*` pair) are
/// deliberately broad safety nets and are entropy-gated (plus, for the two
/// high-entropy rules, a "must contain a digit" heuristic applied in
/// [`scan_path`]) specifically so they don't fire on every placeholder or
/// English sentence.
pub const RULES: &[Rule] = &[
    Rule {
        id: "aws-access-key",
        description: "AWS access key ID",
        pattern: r"(A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}",
        min_entropy: None,
    },
    Rule {
        id: "github-token",
        description: "GitHub personal/app/oauth/refresh token",
        pattern: r"gh[oprsu]_[0-9A-Za-z]{36}",
        min_entropy: None,
    },
    Rule {
        id: "github-fine-grained-pat",
        description: "GitHub fine-grained personal access token",
        pattern: r"github_pat_[0-9A-Za-z_]{82}",
        min_entropy: None,
    },
    Rule {
        id: "gitlab-token",
        description: "GitLab personal access token",
        pattern: r"glpat-[0-9A-Za-z_\-]{20}",
        min_entropy: None,
    },
    Rule {
        id: "slack-token",
        description: "Slack API token",
        pattern: r"xox[baprs]-[0-9A-Za-z-]{10,}",
        min_entropy: None,
    },
    Rule {
        id: "slack-webhook",
        description: "Slack incoming webhook URL",
        pattern: r"hooks\.slack\.com/services/[A-Za-z0-9/]+",
        min_entropy: None,
    },
    Rule {
        id: "stripe-key",
        description: "Stripe secret or restricted API key",
        pattern: r"(sk|rk)_(live|test)_[0-9A-Za-z]{24,}",
        min_entropy: None,
    },
    // NOTE: anthropic-key MUST precede openai-key. `sk-ant-…` also matches
    // openai's broader `sk-…` pattern, and the de-duplicator in `scan_path`
    // awards each span to the first rule that claims it. The `regex` crate
    // has no lookahead, so rule ORDER is the only mechanism enforcing
    // "most specific wins" — keep specific prefixes above general ones.
    Rule {
        id: "anthropic-key",
        description: "Anthropic API key",
        pattern: r"sk-ant-[A-Za-z0-9_-]{20,}",
        min_entropy: None,
    },
    Rule {
        id: "openai-key",
        description: "OpenAI API key",
        pattern: r"sk-(proj-)?[A-Za-z0-9_-]{20,}",
        min_entropy: None,
    },
    Rule {
        id: "google-api-key",
        description: "Google API key",
        pattern: r"AIza[0-9A-Za-z_-]{35}",
        min_entropy: None,
    },
    Rule {
        id: "gcp-service-account",
        description: "GCP service-account JSON key file",
        pattern: r#""type"\s*:\s*"service_account""#,
        min_entropy: None,
    },
    Rule {
        id: "sendgrid-key",
        description: "SendGrid API key",
        pattern: r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
        min_entropy: None,
    },
    Rule {
        id: "twilio-api-key",
        description: "Twilio API key",
        pattern: r"SK[0-9a-fA-F]{32}",
        min_entropy: None,
    },
    Rule {
        id: "twilio-account-sid",
        description: "Twilio account SID",
        pattern: r"AC[0-9a-f]{32}",
        min_entropy: None,
    },
    Rule {
        id: "npm-token",
        description: "npm access token",
        pattern: r"npm_[A-Za-z0-9]{36}",
        min_entropy: None,
    },
    Rule {
        id: "pypi-token",
        description: "PyPI API token",
        pattern: r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}",
        min_entropy: None,
    },
    Rule {
        id: "digitalocean-token",
        description: "DigitalOcean personal access token",
        pattern: r"dop_v1_[a-f0-9]{64}",
        min_entropy: None,
    },
    Rule {
        id: "hashicorp-vault-token",
        description: "HashiCorp Vault service token",
        pattern: r"hvs\.[A-Za-z0-9_-]{20,}",
        min_entropy: None,
    },
    Rule {
        id: "telegram-bot-token",
        description: "Telegram bot token",
        pattern: r"\d{8,10}:[A-Za-z0-9_-]{35}",
        min_entropy: None,
    },
    Rule {
        id: "jwt",
        description: "JSON Web Token",
        pattern: r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        min_entropy: None,
    },
    Rule {
        id: "private-key",
        description: "PEM-encoded private key block",
        pattern: r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        min_entropy: None,
    },
    Rule {
        id: "connection-string-credentials",
        description: "Connection string with inline credentials",
        pattern: r"(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp|ftp)://[^:\s]+:(?P<secret>[^@\s]+)@",
        min_entropy: None,
    },
    Rule {
        id: "generic-assignment",
        description: "Suspicious key/secret/token/password assignment (entropy-gated)",
        // Quoted values, any file. The trailing `[a-z0-9_-]*` lets the
        // keyword match inside a longer name: `aws_secret_access_key`,
        // `STRIPE_API_KEY_LIVE`.
        pattern: r#"(?i)(?P<keyname>api[_-]?key|secret|token|password|passwd|pwd|credential|auth)[a-z0-9_-]*["']?\s*[:=]\s*["'](?P<secret>[^"'\r\n]{8,})["']"#,
        // 3.5, not the dotenv rule's 3.2: quoted assignments are everywhere in
        // source code, so this threshold buys precision. Lowering it to 3.2
        // starts flagging test fixture strings in this very repository.
        min_entropy: Some(3.5),
    },
    Rule {
        // UNQUOTED values -- `DB_PASSWORD=S3cure!Passw0rd`. This is the shape
        // a dotenv file actually uses, and requiring quotes made the scanner
        // silently clean on the single most important input it has.
        //
        // Restricted to dotenv-style files (see DOTENV_ONLY_RULE): in source
        // code a bare `token = something` is an ordinary assignment, and
        // letting this loose on .rs/.py/.js produced ~60 false positives on
        // this repository alone. A real secret in source is a string literal,
        // which generic-assignment above already covers.
        id: "dotenv-assignment",
        description: "Unquoted secret assignment in an env file (entropy-gated)",
        pattern: r#"(?i)(?P<keyname>api[_-]?key|secret|token|password|passwd|pwd|credential|auth)[a-z0-9_-]*\s*[:=]\s*(?P<secret>[^"'\s#][^\s#]{7,})"#,
        min_entropy: Some(3.2),
    },
    Rule {
        id: "generic-high-entropy-base64",
        description: "High-entropy base64-ish string (possible secret)",
        pattern: r"\b[A-Za-z0-9+/_-]{20,}={0,2}\b",
        min_entropy: Some(4.5),
    },
    Rule {
        id: "generic-high-entropy-hex",
        description: "High-entropy hex string (possible secret)",
        pattern: r"\b[a-fA-F0-9]{32,}\b",
        min_entropy: Some(3.0),
    },
];

struct Compiled {
    rule: &'static Rule,
    regex: Regex,
}

static COMPILED_RULES: LazyLock<Vec<Compiled>> = LazyLock::new(|| {
    RULES
        .iter()
        .map(|rule| Compiled {
            rule,
            regex: Regex::new(rule.pattern)
                .unwrap_or_else(|e| panic!("invalid built-in rule pattern '{}': {e}", rule.id)),
        })
        .collect()
});

/// A single detected secret. `redacted` never contains more than the first
/// four characters of the real value — see the module-level doc comment.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub rule_id: String,
    pub path: PathBuf,
    pub line_number: usize,
    pub redacted: String,
    pub suggested_key: String,
}

// ── Entropy ──────────────────────────────────────────────────────────────

/// Shannon entropy of `s`, in bits per byte. Empty input is 0.0.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

// ── Placeholder / false-positive suppression ────────────────────────────

const PLACEHOLDER_SUBSTRINGS: &[&str] = &[
    "changeme",
    "change_me",
    "change-me",
    "your-key-here",
    "your_key_here",
    "yourkeyhere",
    "example",
    "dummy",
    "sample",
    "redacted",
    "placeholder",
    "insert-key-here",
    "insert_key_here",
    "replace_with",
    "replace-with",
    "fixme",
    "todo",
    "fakekey",
    "fake_key",
];

/// True when `s` contains a run of `min_run` or more consecutive identical
/// characters anywhere in it.
fn has_long_repeat_run(s: &str, min_run: usize) -> bool {
    let mut last: Option<char> = None;
    let mut run = 0usize;
    for c in s.chars() {
        if Some(c) == last {
            run += 1;
        } else {
            last = Some(c);
            run = 1;
        }
        if run >= min_run {
            return true;
        }
    }
    false
}

/// True when `value` looks like an obvious placeholder rather than a real
/// secret: known filler words, `<...>`/`${...}` template holes, `%s`/`{}`
/// format holes, or a string made of a single repeated character (e.g.
/// `xxxxxxxxxxxx` or `0000000000000000`).
pub fn is_placeholder(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() {
        return true;
    }
    let lower = v.to_ascii_lowercase();
    if PLACEHOLDER_SUBSTRINGS.iter().any(|p| lower.contains(p)) {
        return true;
    }
    if (v.starts_with('<') && v.ends_with('>')) || (v.starts_with("${") && v.ends_with('}')) {
        return true;
    }
    if v == "%s" || v == "{}" {
        return true;
    }
    // A long run of the same character anywhere in the value (e.g. the
    // fixed prefix of a real rule plus "XXXXXXXXXXXXXXXX", or a placeholder
    // like "00000000000000000000") carries ~zero entropy over that run and
    // is the single most common shape a placeholder value takes, even when
    // it isn't a full-string match against the known filler words above.
    if has_long_repeat_run(&lower, 6) {
        return true;
    }
    false
}

/// True when `line` ends with an explicit scanner-suppression comment.
fn line_has_allow_comment(line: &str) -> bool {
    line.contains("hearth-vault:allow") || line.contains("gitleaks:allow")
}

// ── Walker ───────────────────────────────────────────────────────────────

const SKIP_DIRS: &[&str] = &[
    ".git",
    "target",
    "node_modules",
    "vendor",
    "dist",
    "build",
    ".venv",
    "__pycache__",
];

const SKIP_FILE_NAMES: &[&str] = &[
    "Cargo.lock",
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "composer.lock",
    "Gemfile.lock",
    "poetry.lock",
    "Pipfile.lock",
    "Podfile.lock",
    "mix.lock",
    "flake.lock",
];

const MAX_SCAN_FILE_SIZE: u64 = 1024 * 1024; // 1 MiB

/// Dot-directories we DO descend into, because people really do hardcode
/// credentials in CI definitions.
const SCAN_DOT_DIRS: &[&str] = &[".github", ".gitlab", ".circleci", ".config"];

fn should_skip_dir(name: &str) -> bool {
    if SKIP_DIRS.contains(&name) {
        return true;
    }
    // Skip dot-directories wholesale rather than maintaining a blocklist of
    // every tool that plants one (.claude, .cache, .idea, .terraform, .tox,
    // .next, .gradle, …). Without this, running `scan` in a repo that has any
    // agent worktree or tool cache buries the user's real findings under
    // hundreds of hits in files they do not own — and a noisy scanner gets
    // uninstalled. `.env` files are FILES, not directories, so this never
    // hides the main target.
    name.starts_with('.') && !SCAN_DOT_DIRS.contains(&name)
}

fn should_skip_file(name: &str) -> bool {
    SKIP_FILE_NAMES.contains(&name) || name.ends_with(".lock")
}

/// Best-effort binary sniff: a NUL byte in the first 8 KiB means "don't try
/// to scan this as text."
fn looks_binary(path: &Path) -> bool {
    let Ok(mut f) = fs::File::open(path) else {
        return true;
    };
    let mut buf = [0u8; 8192];
    let n = f.read(&mut buf).unwrap_or(0);
    buf[..n].contains(&0)
}

/// Recursively collect scan-eligible file paths under `root`, skipping the
/// directories/files noted in the module docs. Does not implement
/// `.gitignore` parsing — the skip list above is the whole story.
fn collect_files(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let path = entry.path();

            if file_type.is_dir() {
                if !should_skip_dir(&name_str) {
                    stack.push(path);
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            if should_skip_file(&name_str) {
                continue;
            }
            if let Ok(meta) = entry.metadata()
                && meta.len() > MAX_SCAN_FILE_SIZE
            {
                // Say so. A silent skip reads exactly like a clean file, and
                // "No secrets found" over an unread 4 MiB .env.backup is the
                // worst answer this tool can give.
                eprintln!(
                    "  skipped (larger than {} MiB): {}",
                    MAX_SCAN_FILE_SIZE / (1024 * 1024),
                    path.display()
                );
                continue;
            }
            if looks_binary(&path) {
                continue;
            }
            out.push(path);
        }
    }

    out
}

// ── Redaction / suggested key ───────────────────────────────────────────

/// Redact `secret` to at most its first 4 characters plus a length marker.
/// Never returns anything from which the full value can be reconstructed.
fn redact(secret: &str) -> String {
    let char_count = secret.chars().count();
    let visible = if char_count > 4 { 4 } else { 0 };
    let prefix: String = secret.chars().take(visible).collect();
    format!("{prefix}\u{2026}({char_count} chars)")
}

/// Best-effort "service" name for a suggested vault key, taken from the
/// scanned file's parent directory (falling back to "app" at the scan
/// root, where there is no meaningful parent to name it after).
fn service_name_from_path(path: &Path) -> String {
    path.parent()
        .and_then(|p| p.file_name())
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .filter(|s| !s.is_empty() && s != ".")
        .unwrap_or_else(|| "app".to_string())
}

fn suggested_key_for(rule_id: &str, path: &Path, keyname: Option<&str>) -> String {
    match rule_id {
        "aws-access-key" => "aws/access_key_id".to_string(),
        "github-token" => "github/token".to_string(),
        "github-fine-grained-pat" => "github/token".to_string(),
        "gitlab-token" => "gitlab/token".to_string(),
        "slack-token" => "slack/token".to_string(),
        "slack-webhook" => "slack/webhook_url".to_string(),
        "stripe-key" => "stripe/api_key".to_string(),
        "openai-key" => "openai/api_key".to_string(),
        "anthropic-key" => "anthropic/api_key".to_string(),
        "google-api-key" => "google/api_key".to_string(),
        "gcp-service-account" => "gcp/service_account_json".to_string(),
        "sendgrid-key" => "sendgrid/api_key".to_string(),
        "twilio-api-key" => "twilio/api_key".to_string(),
        "twilio-account-sid" => "twilio/account_sid".to_string(),
        "npm-token" => "npm/token".to_string(),
        "pypi-token" => "pypi/token".to_string(),
        "digitalocean-token" => "digitalocean/token".to_string(),
        "hashicorp-vault-token" => "vault/token".to_string(),
        "telegram-bot-token" => "telegram/bot_token".to_string(),
        "jwt" => "jwt/token".to_string(),
        "private-key" => "keys/private_key".to_string(),
        "connection-string-credentials" => {
            format!("{}/db_password", service_name_from_path(path))
        }
        "generic-assignment" => {
            let field = keyname
                .unwrap_or("value")
                .to_ascii_lowercase()
                .replace(['-', ' '], "_");
            format!("{}/{field}", service_name_from_path(path))
        }
        _ => format!("{}/secret", service_name_from_path(path)),
    }
}

/// The candidate secret text — the `secret` named group when the pattern
/// defines one, else the whole match — plus the byte range it occupies in the
/// line, so overlapping rule matches can be de-duplicated.
fn extract_with_span<'a>(caps: &regex::Captures<'a>) -> (&'a str, (usize, usize)) {
    match caps.name("secret").or_else(|| caps.get(0)) {
        Some(m) => (m.as_str(), (m.start(), m.end())),
        None => ("", (0, 0)),
    }
}

/// The one rule that only applies to dotenv-style files. See its entry in
/// `RULES` for why it cannot be let loose on source code.
const DOTENV_ONLY_RULE: &str = "dotenv-assignment";

/// Is this a file whose convention is `KEY=value` with unquoted values?
///
/// Covers `.env`, `.env.local`, `.env.production`, `prod.env`, `.envrc`, and
/// the `environment` file systemd units use. Deliberately narrow: widening it
/// re-admits the false positives that made the unquoted rule unusable.
fn is_dotenv_style(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower == "environment"
        || lower == ".envrc"
        || lower == ".env"
        || lower.starts_with(".env.")
        || lower.ends_with(".env")
}

// ── Public entry point ───────────────────────────────────────────────────

/// Scan every eligible file under `root` (or `root` itself, if it's a
/// single file) for secret-shaped strings. See the module docs for the
/// redaction guarantee on the results.
pub fn scan_path(root: &Path) -> anyhow::Result<Vec<Finding>> {
    let files = if root.is_file() {
        vec![root.to_path_buf()]
    } else {
        collect_files(root)
    };

    let mut findings = Vec::new();

    for file in files {
        let Ok(content) = fs::read_to_string(&file) else {
            continue;
        };

        for (idx, line) in content.lines().enumerate() {
            if line_has_allow_comment(line) {
                continue;
            }

            // Byte ranges on this line already attributed to a rule. RULES is
            // ordered most-specific first, so the first rule to claim a span
            // wins and broader rules silently yield. Without this, one
            // `sk-ant-…` key is reported three times — once as an Anthropic
            // key, once as an OpenAI key (the prefixes overlap), and once by
            // the high-entropy safety net. Triplicated findings make the
            // report look broken and bury the real count.
            // A byte map rather than a list of ranges: the list version was
            // O(matches^2) -- every candidate compared against every span
            // already claimed -- so one pathological line with tens of
            // thousands of secret-shaped tokens turned a scan into a hang.
            // Marking and testing bytes is linear in the matched text.
            let mut claimed = vec![false; line.len()];
            let len_guard = claimed.len();

            for compiled in COMPILED_RULES.iter() {
                if compiled.rule.id == DOTENV_ONLY_RULE && !is_dotenv_style(&file) {
                    continue;
                }
                for caps in compiled.regex.captures_iter(line) {
                    let (secret_str, span) = extract_with_span(&caps);
                    let keyname = caps.name("keyname").map(|m| m.as_str());
                    if claimed[span.0..span.1.min(claimed.len())]
                        .iter()
                        .any(|&taken| taken)
                    {
                        continue;
                    }
                    if secret_str.is_empty() || is_placeholder(secret_str) {
                        continue;
                    }
                    if let Some(min_e) = compiled.rule.min_entropy
                        && shannon_entropy(secret_str) < min_e
                    {
                        continue;
                    }
                    // Extra false-positive brake on the two broad
                    // high-entropy safety-net rules: a real API-key-shaped
                    // secret almost always mixes letters and digits, while
                    // prose, hashes-of-hashes, and long identifiers often
                    // don't. Named rules above (AWS, GitHub, ...) are exempt
                    // — their shape alone is already specific enough.
                    if compiled.rule.id.starts_with("generic-high-entropy")
                        && !secret_str.chars().any(|c| c.is_ascii_digit())
                    {
                        continue;
                    }

                    for taken in &mut claimed[span.0..span.1.min(len_guard)] {
                        *taken = true;
                    }
                    findings.push(Finding {
                        rule_id: compiled.rule.id.to_string(),
                        path: file.clone(),
                        line_number: idx + 1,
                        redacted: redact(secret_str),
                        suggested_key: suggested_key_for(compiled.rule.id, &file, keyname),
                    });
                }
            }
        }
    }

    Ok(findings)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// Build a syntactically secret-shaped string at runtime from parts, so
    /// no real-looking credential literal sits in this source file for a
    /// scanner (this one included) to trip over.
    fn join(parts: &[&str]) -> String {
        parts.concat()
    }

    /// A mixed-case alphanumeric string of exactly `n` characters, built by
    /// cycling a 32-symbol charset — high enough entropy to clear every
    /// entropy gate, non-repeating so it never trips the repeat-run
    /// placeholder heuristic, and exact-length-safe for rules that use a
    /// fixed `{n}` (not `{n,}`) regex quantifier.
    fn alnum_of_len(n: usize) -> String {
        const CHARSET: &[u8] = b"aB3xQ9zK7mN2pR8wT1yU5vC4dF6gH0jL"; // hearth-vault:allow gitleaks:allow
        (0..n).map(|i| CHARSET[i % CHARSET.len()] as char).collect()
    }

    /// Same idea as [`alnum_of_len`] but restricted to uppercase letters and
    /// digits, for rules whose character class excludes lowercase (e.g. AWS
    /// access key IDs).
    fn upper_of_len(n: usize) -> String {
        const CHARSET: &[u8] = b"AB3XQ9ZK7MN2PR8WT1YU5VC4DF6GH0JL"; // hearth-vault:allow gitleaks:allow
        (0..n).map(|i| CHARSET[i % CHARSET.len()] as char).collect()
    }

    /// Same idea again, restricted to hex digits, for rules whose character
    /// class is `[0-9a-f]`/`[0-9a-fA-F]` (Twilio, DigitalOcean).
    fn hex_of_len(n: usize) -> String {
        const CHARSET: &[u8] = b"0123456789abcdef";
        // Step by a value coprime with 16 so consecutive characters never
        // repeat (would otherwise trip the repeat-run placeholder check).
        (0..n)
            .map(|i| CHARSET[(i * 7) % CHARSET.len()] as char)
            .collect()
    }

    fn find_rule<'a>(findings: &'a [Finding], rule_id: &str) -> Option<&'a Finding> {
        findings.iter().find(|f| f.rule_id == rule_id)
    }

    fn scan_str(content: &str, filename: &str) -> Vec<Finding> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(filename);
        fs::write(&path, content).unwrap();
        scan_path(&path).unwrap()
    }

    // ── Entropy ──────────────────────────────────────────────────────

    #[test]
    fn entropy_of_empty_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn entropy_of_repeated_char_is_zero() {
        assert_eq!(shannon_entropy("aaaaaaaaaaaa"), 0.0);
    }

    #[test]
    fn entropy_of_varied_string_is_higher_than_repeated() {
        let low = shannon_entropy("aaaaaaaaaaaaaaaa");
        let high = shannon_entropy("aB3xQ9zK7mN2pR8w");
        assert!(high > low, "high={high} low={low}");
    }

    // ── Placeholder suppressor ──────────────────────────────────────

    #[test]
    fn placeholder_detects_known_fillers() {
        assert!(is_placeholder("changeme"));
        assert!(is_placeholder("your-key-here"));
        assert!(is_placeholder("REDACTED"));
        assert!(is_placeholder("example-value"));
        assert!(is_placeholder("dummy_token"));
    }

    #[test]
    fn placeholder_detects_template_holes() {
        assert!(is_placeholder("<your-token>"));
        assert!(is_placeholder("${SECRET_VALUE}"));
        assert!(is_placeholder("%s"));
        assert!(is_placeholder("{}"));
    }

    #[test]
    fn placeholder_detects_repeated_char_runs() {
        assert!(is_placeholder("xxxxxxxxxxxxxxxx"));
        assert!(is_placeholder("0000000000000000"));
    }

    #[test]
    fn placeholder_does_not_flag_real_looking_secret() {
        assert!(!is_placeholder("aB3xQ9zK7mN2pR8wT1yU"));
    }

    // ── Walker skip list ─────────────────────────────────────────────

    /// A repo containing agent worktrees or tool caches must not bury the
    /// user's real findings under hits from files they do not own.
    #[test]
    fn walker_skips_dot_directories_but_still_scans_dot_env_and_ci_configs() {
        let dir = tempfile::tempdir().unwrap();
        let secret = join(&["AKIA", "1234567890ABCDEF"]);

        for hidden in [".claude", ".cache", ".idea", ".terraform"] {
            let sub = dir.path().join(hidden);
            fs::create_dir_all(&sub).unwrap();
            fs::write(sub.join("f.txt"), format!("k={secret}")).unwrap();
        }
        // .env is a FILE, so dot-directory skipping must never hide it.
        fs::write(dir.path().join(".env"), format!("AWS_KEY={secret}")).unwrap();
        // CI configs are a real place credentials get hardcoded.
        let gh = dir.path().join(".github/workflows");
        fs::create_dir_all(&gh).unwrap();
        fs::write(gh.join("ci.yml"), format!("key: {secret}")).unwrap();

        let found = scan_path(dir.path()).unwrap();
        let paths: Vec<String> = found
            .iter()
            .map(|f| f.path.to_string_lossy().replace('\\', "/"))
            .collect();

        assert!(
            paths.iter().any(|p| p.ends_with("/.env")),
            "must still scan .env, got {paths:?}"
        );
        assert!(
            paths.iter().any(|p| p.ends_with("ci.yml")),
            "must still scan CI configs, got {paths:?}"
        );
        for hidden in [".claude", ".cache", ".idea", ".terraform"] {
            assert!(
                !paths.iter().any(|p| p.contains(&format!("/{hidden}/"))),
                "must skip {hidden}, got {paths:?}"
            );
        }
    }

    /// Overlapping rules must not triplicate one secret.
    #[test]
    fn overlapping_rules_report_each_secret_once() {
        let dir = tempfile::tempdir().unwrap();
        // `sk-ant-…` matches the Anthropic rule, the broader OpenAI `sk-…`
        // rule, and the high-entropy safety net.
        let secret = join(&["sk-ant-", "api03-", &alnum_of_len(40)]);
        let file = dir.path().join("config.js");
        fs::write(&file, format!("const k = \"{secret}\";")).unwrap();

        let found = scan_path(dir.path()).unwrap();
        assert_eq!(
            found.len(),
            1,
            "expected one finding, got {}: {:?}",
            found.len(),
            found.iter().map(|f| &f.rule_id).collect::<Vec<_>>()
        );
        assert_eq!(
            found[0].rule_id, "anthropic-key",
            "the most specific rule must win"
        );
    }

    #[test]
    fn walker_skips_dot_git_and_target_and_node_modules() {
        let dir = tempfile::tempdir().unwrap();
        let secret = join(&["gh", "p_", &alnum_of_len(36)]);
        for sub in [".git", "target", "node_modules", "vendor"] {
            let subdir = dir.path().join(sub);
            fs::create_dir_all(&subdir).unwrap();
            fs::write(subdir.join("file.txt"), format!("token={secret}")).unwrap();
        }
        // A file at the top level should still be found.
        fs::write(dir.path().join("real.txt"), format!("token={secret}")).unwrap();

        let findings = scan_path(dir.path()).unwrap();
        assert!(
            findings.iter().all(|f| f.path.ends_with("real.txt")),
            "expected only real.txt to be scanned, got {:?}",
            findings.iter().map(|f| &f.path).collect::<Vec<_>>()
        );
        assert!(!findings.is_empty());
    }

    #[test]
    fn walker_skips_lockfiles_but_not_dotenv() {
        let dir = tempfile::tempdir().unwrap();
        let secret = join(&["gh", "p_", &alnum_of_len(36)]);
        fs::write(dir.path().join("Cargo.lock"), format!("token={secret}")).unwrap();
        fs::write(dir.path().join(".env"), format!("TOKEN={secret}")).unwrap();

        let findings = scan_path(dir.path()).unwrap();
        assert!(findings.iter().all(|f| !f.path.ends_with("Cargo.lock")));
        assert!(findings.iter().any(|f| f.path.ends_with(".env")));
    }

    #[test]
    fn walker_skips_binary_files() {
        let dir = tempfile::tempdir().unwrap();
        let mut bytes = vec![0u8, 1, 2, 3];
        bytes.extend_from_slice(b"AKIA1234567890ABCDEF"); // hearth-vault:allow gitleaks:allow
        fs::write(dir.path().join("blob.bin"), &bytes).unwrap();
        let findings = scan_path(dir.path()).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn allow_comment_suppresses_a_line() {
        let secret = join(&["gh", "p_", &"C".repeat(36)]);
        let content = format!("token = \"{secret}\" # hearth-vault:allow\n");
        let findings = scan_str(&content, "file.txt");
        assert!(findings.is_empty());
    }

    // ── Unquoted dotenv assignments ──────────────────────────────────

    /// The shape a real `.env` file uses. Requiring quotes made the scanner
    /// report a file full of live credentials as clean, which is the worst
    /// possible failure for a tool whose migration story starts with `scan`.
    #[test]
    fn unquoted_env_assignments_are_found() {
        for line in [
            "DB_PASSWORD=S3cure!Passw0rd",
            "aws_secret_access_key = kX9pQmZ2vLr7TbNc4Ws8HdJf1GyUe6Ai3Ro5Pl0Q", // hearth-vault:allow (synthetic test fixture)
            "API_TOKEN=abc123def456ghi789",
            "export STRIPE_SECRET_KEY=rk9Xp2LmQ7vT4bN8cW5sHd1Jf3Gy", // hearth-vault:allow (synthetic test fixture)
        ] {
            let findings = scan_str(&format!("{line}\n"), ".env");
            assert!(
                !findings.is_empty(),
                "missed an unquoted credential: {line}"
            );
        }
    }

    /// Ordinary non-secret config in the same file must stay quiet, or the
    /// report is noise and people turn the scan off.
    #[test]
    fn unquoted_non_secrets_are_not_flagged() {
        for line in [
            "DEBUG=true",
            "PORT=8080",
            "LOG_LEVEL=info",
            "password = \"\"",
        ] {
            let findings = scan_str(&format!("{line}\n"), ".env");
            assert!(findings.is_empty(), "false positive on: {line}");
        }
    }

    /// The unquoted rule is scoped to env-style files on purpose: in source
    /// code `let token = something` is an ordinary assignment, and letting
    /// this rule loose there produced ~60 false positives on this repo.
    #[test]
    fn unquoted_rule_does_not_fire_in_source_files() {
        let line = "let token = compute_something_long_here();\n";
        assert!(find_rule(&scan_str(line, "main.rs"), "dotenv-assignment").is_none());
        // ...but a genuinely env-shaped file still gets it.
        let findings = scan_str("SESSION_TOKEN=9f8Xq2Lm7vT4bN8cW5sHd1J\n", ".env.production"); // hearth-vault:allow (synthetic test fixture)
        assert!(find_rule(&findings, "dotenv-assignment").is_some());
    }

    // ── Rule matching: one positive + one placeholder-negative per family ─

    #[test]
    fn aws_access_key_positive_and_placeholder_negative() {
        let secret = join(&["AKIA", &upper_of_len(16)]);
        let findings = scan_str(&format!("aws_key = \"{secret}\"\n"), "f.txt");
        assert!(find_rule(&findings, "aws-access-key").is_some());

        let findings = scan_str("aws_key = \"AKIAXXXXXXXXXXXXXXXX\"\n", "f.txt");
        assert!(find_rule(&findings, "aws-access-key").is_none());
    }

    #[test]
    fn github_token_positive_and_placeholder_negative() {
        let secret = join(&["gh", "p_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"]); // hearth-vault:allow gitleaks:allow
        let findings = scan_str(&format!("GITHUB_TOKEN={secret}\n"), "f.env");
        assert!(find_rule(&findings, "github-token").is_some());

        let placeholder = join(&["gh", "p_", &"x".repeat(36)]);
        let findings = scan_str(&format!("GITHUB_TOKEN={placeholder}\n"), "f.env");
        assert!(find_rule(&findings, "github-token").is_none());
    }

    #[test]
    fn github_fine_grained_pat_positive_and_negative() {
        let secret = join(&["github_pat_", &alnum_of_len(82)]);
        let findings = scan_str(&format!("token: {secret}\n"), "f.txt");
        assert!(find_rule(&findings, "github-fine-grained-pat").is_some());

        let placeholder = join(&["github_pat_", &"x".repeat(82)]);
        let findings = scan_str(&format!("token: {placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "github-fine-grained-pat").is_none());
    }

    #[test]
    fn gitlab_token_positive_and_negative() {
        let secret = join(&["glpat-", "aB1cD2eF3gH4iJ5kL6mN"]);
        let findings = scan_str(&format!("GITLAB={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "gitlab-token").is_some());

        let placeholder = join(&["glpat-", &"x".repeat(20)]);
        let findings = scan_str(&format!("GITLAB={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "gitlab-token").is_none());
    }

    #[test]
    fn slack_token_positive_and_negative() {
        let secret = join(&["xoxb-", "1234567890-abcDEFghiJKL"]); // hearth-vault:allow gitleaks:allow
        let findings = scan_str(&format!("SLACK_TOKEN={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "slack-token").is_some());

        let placeholder = join(&["xoxb-", &"x".repeat(12)]);
        let findings = scan_str(&format!("SLACK_TOKEN={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "slack-token").is_none());
    }

    #[test]
    fn slack_webhook_positive_and_negative() {
        // Assembled at runtime, like the other fixtures in this file: a
        // literal here trips GitHub's push protection, which blocks the push
        // outright rather than warning. Test fixtures for a secret scanner
        // must never be greppable as the thing they imitate.
        let url = join(&[
            "https://hooks.slack.com/serv",
            "ices/T0AB1CDE2/B0FG3HIJ4/",
            &alnum_of_len(24),
        ]);
        let findings = scan_str(&format!("WEBHOOK={url}\n"), "f.txt");
        assert!(find_rule(&findings, "slack-webhook").is_some());

        let findings = scan_str("WEBHOOK=<your-key-here>\n", "f.txt");
        assert!(find_rule(&findings, "slack-webhook").is_none());
    }

    #[test]
    fn stripe_key_positive_and_negative() {
        let secret = join(&["sk_live_", "aB1cD2eF3gH4iJ5kL6mN7oP8"]); // hearth-vault:allow gitleaks:allow
        let findings = scan_str(&format!("STRIPE_KEY={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "stripe-key").is_some());

        let placeholder = join(&["sk_live_", &"x".repeat(24)]);
        let findings = scan_str(&format!("STRIPE_KEY={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "stripe-key").is_none());
    }

    #[test]
    fn openai_key_positive_and_negative() {
        let secret = join(&["sk-proj-", "aB1cD2eF3gH4iJ5kL6mN7oP8qR9s"]); // hearth-vault:allow gitleaks:allow
        let findings = scan_str(&format!("OPENAI_API_KEY={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "openai-key").is_some());

        let placeholder = join(&["sk-proj-", &"x".repeat(24)]);
        let findings = scan_str(&format!("OPENAI_API_KEY={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "openai-key").is_none());
    }

    #[test]
    fn anthropic_key_positive_and_negative() {
        let secret = join(&["sk-ant-", "aB1cD2eF3gH4iJ5kL6mN7oP8qR9s"]); // hearth-vault:allow gitleaks:allow
        let findings = scan_str(&format!("ANTHROPIC_API_KEY={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "anthropic-key").is_some());

        let placeholder = join(&["sk-ant-", &"x".repeat(24)]);
        let findings = scan_str(&format!("ANTHROPIC_API_KEY={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "anthropic-key").is_none());
    }

    #[test]
    fn google_api_key_positive_and_negative() {
        let secret = join(&["AIza", &alnum_of_len(35)]);
        let findings = scan_str(&format!("GOOGLE_API_KEY={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "google-api-key").is_some());

        let placeholder = join(&["AIza", &"x".repeat(35)]);
        let findings = scan_str(&format!("GOOGLE_API_KEY={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "google-api-key").is_none());
    }

    #[test]
    fn gcp_service_account_positive_and_negative() {
        let findings = scan_str(
            "{\"type\": \"service_account\", \"project_id\": \"x\"}\n",
            "f.json",
        );
        assert!(find_rule(&findings, "gcp-service-account").is_some());

        let findings = scan_str("{\"type\": \"example\"}\n", "f.json");
        assert!(find_rule(&findings, "gcp-service-account").is_none());
    }

    #[test]
    fn sendgrid_key_positive_and_negative() {
        let secret = join(&["SG.", &alnum_of_len(22), ".", &alnum_of_len(43)]);
        let findings = scan_str(&format!("SENDGRID={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "sendgrid-key").is_some());

        let placeholder = join(&["SG.", &"x".repeat(22), ".", &"x".repeat(43)]);
        let findings = scan_str(&format!("SENDGRID={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "sendgrid-key").is_none());
    }

    #[test]
    fn twilio_api_key_positive_and_negative() {
        let secret = join(&["SK", &hex_of_len(32)]);
        let findings = scan_str(&format!("TWILIO={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "twilio-api-key").is_some());

        let placeholder = join(&["SK", &"0".repeat(32)]);
        let findings = scan_str(&format!("TWILIO={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "twilio-api-key").is_none());
    }

    #[test]
    fn twilio_account_sid_positive_and_negative() {
        let secret = join(&["AC", &hex_of_len(32)]);
        let findings = scan_str(&format!("TWILIO_SID={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "twilio-account-sid").is_some());

        let placeholder = join(&["AC", &"0".repeat(32)]);
        let findings = scan_str(&format!("TWILIO_SID={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "twilio-account-sid").is_none());
    }

    #[test]
    fn npm_token_positive_and_negative() {
        let secret = join(&["npm_", &alnum_of_len(36)]);
        let findings = scan_str(&format!("NPM_TOKEN={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "npm-token").is_some());

        let placeholder = join(&["npm_", &"x".repeat(36)]);
        let findings = scan_str(&format!("NPM_TOKEN={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "npm-token").is_none());
    }

    #[test]
    fn pypi_token_positive_and_negative() {
        let secret = join(&["pypi-AgEIcHlwaS5vcmc", &alnum_of_len(55)]);
        let findings = scan_str(&format!("PYPI={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "pypi-token").is_some());

        let placeholder = join(&["pypi-AgEIcHlwaS5vcmc", &"x".repeat(50)]);
        let findings = scan_str(&format!("PYPI={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "pypi-token").is_none());
    }

    #[test]
    fn digitalocean_token_positive_and_negative() {
        let secret = join(&["dop_v1_", &hex_of_len(64)]);
        let findings = scan_str(&format!("DO_TOKEN={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "digitalocean-token").is_some());

        let placeholder = join(&["dop_v1_", &"0".repeat(64)]);
        let findings = scan_str(&format!("DO_TOKEN={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "digitalocean-token").is_none());
    }

    #[test]
    fn hashicorp_vault_token_positive_and_negative() {
        let secret = join(&["hvs.", "aB1cD2eF3gH4iJ5kL6mN7oP8"]); // hearth-vault:allow gitleaks:allow
        let findings = scan_str(&format!("VAULT_TOKEN={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "hashicorp-vault-token").is_some());

        let placeholder = join(&["hvs.", &"x".repeat(24)]);
        let findings = scan_str(&format!("VAULT_TOKEN={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "hashicorp-vault-token").is_none());
    }

    #[test]
    fn telegram_bot_token_positive_and_negative() {
        let secret = join(&["123456789:", &alnum_of_len(35)]);
        let findings = scan_str(&format!("TELEGRAM={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "telegram-bot-token").is_some());

        let placeholder = join(&["123456789:", &"x".repeat(35)]);
        let findings = scan_str(&format!("TELEGRAM={placeholder}\n"), "f.txt");
        assert!(find_rule(&findings, "telegram-bot-token").is_none());
    }

    #[test]
    fn jwt_positive_and_negative() {
        let secret = join(&[
            "eyJhbGciOiJIUzI1NiJ9",
            ".",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            ".",
            "aB1cD2eF3gH4iJ5kL6mN7oP8", // hearth-vault:allow gitleaks:allow
        ]);
        let findings = scan_str(&format!("JWT={secret}\n"), "f.txt");
        assert!(find_rule(&findings, "jwt").is_some());

        let findings = scan_str("JWT=<your-key-here>\n", "f.txt");
        assert!(find_rule(&findings, "jwt").is_none());
    }

    #[test]
    fn private_key_positive_and_negative() {
        let findings = scan_str("-----BEGIN RSA PRIVATE KEY-----\n", "f.pem"); // hearth-vault:allow gitleaks:allow
        assert!(find_rule(&findings, "private-key").is_some());

        let findings = scan_str("-----BEGIN CERTIFICATE-----\n", "f.pem");
        assert!(find_rule(&findings, "private-key").is_none());
    }

    #[test]
    fn connection_string_positive_and_negative() {
        let secret = join(&[
            "postgres://user:",
            "aB1cD2eF3gH4iJ5kL6mN7oP8", // hearth-vault:allow gitleaks:allow
            "@db.example.com/app\n",
        ]);
        let findings = scan_str(&secret, "f.txt");
        assert!(find_rule(&findings, "connection-string-credentials").is_some());

        let findings = scan_str("postgres://user:changeme@db.example.com/app\n", "f.txt");
        assert!(find_rule(&findings, "connection-string-credentials").is_none());
    }

    #[test]
    fn generic_assignment_positive_and_negative() {
        let secret = join(&["password = \"", "aB1cD2eF3gH4iJ5kL6mN7oP8", "\"\n"]); // hearth-vault:allow gitleaks:allow
        let findings = scan_str(&secret, "f.txt");
        assert!(find_rule(&findings, "generic-assignment").is_some());

        // Low-entropy placeholder value must not trip the entropy gate.
        let findings = scan_str("password = \"changeme\"\n", "f.txt");
        assert!(find_rule(&findings, "generic-assignment").is_none());
    }

    // ── suggested_key derivation ─────────────────────────────────────

    #[test]
    fn suggested_key_uses_rule_specific_mapping() {
        let secret = join(&["AKIA", &upper_of_len(16)]);
        let findings = scan_str(&format!("aws_key = \"{secret}\"\n"), "f.txt");
        let f = find_rule(&findings, "aws-access-key").unwrap();
        assert_eq!(f.suggested_key, "aws/access_key_id");
    }

    #[test]
    fn suggested_key_for_generic_assignment_uses_keyname() {
        let secret = join(&["api_key = \"", "aB1cD2eF3gH4iJ5kL6mN7oP8", "\"\n"]); // hearth-vault:allow gitleaks:allow
        let findings = scan_str(&secret, "f.txt");
        let f = find_rule(&findings, "generic-assignment").unwrap();
        assert!(f.suggested_key.ends_with("/api_key"), "{}", f.suggested_key);
    }

    // ── redaction ────────────────────────────────────────────────────

    #[test]
    fn redacted_preview_never_contains_full_secret() {
        let secret = join(&["AKIA", &upper_of_len(16)]);
        let findings = scan_str(&format!("aws_key = \"{secret}\"\n"), "f.txt");
        let f = find_rule(&findings, "aws-access-key").unwrap();
        assert!(!f.redacted.contains(&secret));
        assert!(f.redacted.starts_with(&secret[..4]));
        assert!(f.redacted.contains(&secret.len().to_string()));
    }
}
