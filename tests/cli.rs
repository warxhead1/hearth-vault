//! End-to-end CLI tests for the `hearth-vault` binary, run on all three CI
//! platforms (Linux/macOS/Windows) via `cargo test --all-targets`.
//!
//! Hermeticity rules enforced throughout:
//! - Every invocation gets a fresh `HEARTH_VAULT_HOME` pointed at a
//!   `tempfile::TempDir` and a fixed, obviously-fake `HEARTH_VAULT_PASSPHRASE`
//!   — set per-`Command` via `assert_cmd`'s `.env()`, never
//!   `std::env::set_var`, so tests stay safe under `cargo test`'s default
//!   parallel threads.
//! - `Command` starts from `env_clear()` so a developer's real
//!   `HEARTH_VAULT_HOME`/`HEARTH_VAULT_PASSPHRASE` (if set in the ambient
//!   shell) can never leak in; only the minimal passthrough needed to spawn
//!   a child process on each platform is restored.
//! - No test ever prints a *real* secret. Values used here are synthetic,
//!   clearly-labeled fixtures, not vault-derived material.
//!
//! ## The portable child-process trick
//!
//! `exec` needs a real child process to observe injected env vars in. Using
//! `sh -c` is not portable (absent on Windows), and adding a helper `[[bin]]`
//! would require editing `Cargo.toml` (out of scope for this change). Instead
//! this file re-invokes itself: `std::env::current_exe()` inside a test
//! returns the path to *this* compiled test binary, which is a normal
//! libtest harness executable. `helper_print_env` below is a `#[test]` that,
//! when the `HV_TEST_ECHO_VAR` env var is set, prints the named env var's
//! value wrapped in an unambiguous marker and returns. The exec tests invoke
//! `<this binary> helper_print_env --exact --nocapture` as the child command
//! — that filters the harness down to running just that one test, with
//! output uncaptured, which is exactly and only what's needed. This works
//! identically on Linux, macOS, and Windows because it's just running a
//! normal executable with libtest's own portable CLI flags.

use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

/// Fixed, obviously-synthetic passphrase used to unlock the throwaway test
/// vault. Never a real secret.
const TEST_PASSPHRASE: &str = "cli-test-fixture-passphrase-not-a-real-secret";

/// Helper test invoked as a child process by the `exec` tests (see module
/// docs). Under a normal `cargo test` run `HV_TEST_ECHO_VAR` is unset, so
/// this is a no-op that trivially passes.
#[test]
fn helper_print_env() {
    if let Ok(var_name) = std::env::var("HV_TEST_ECHO_VAR") {
        let value = std::env::var(&var_name).unwrap_or_default();
        // Distinctive markers so the parent test can find this exact line
        // among libtest's own "running 1 test" / "test ... ok" chatter.
        println!("HV_ECHO_BEGIN:{value}:HV_ECHO_END");
    }
}

/// One throwaway vault per test: a fresh temp dir for `HEARTH_VAULT_HOME`
/// plus a `Command` builder pre-wired with hermetic env.
struct VaultFixture {
    home: TempDir,
}

impl VaultFixture {
    fn new() -> Self {
        Self {
            home: TempDir::new().expect("create temp dir for test vault"),
        }
    }

    fn home_path(&self) -> &std::path::Path {
        self.home.path()
    }

    fn vault_file(&self) -> PathBuf {
        self.home_path().join("vault.json")
    }

    /// A `hearth-vault` invocation wired to this fixture's temp vault.
    ///
    /// Starts from `env_clear()` so nothing ambient (a developer's real
    /// `HEARTH_VAULT_HOME`/`HEARTH_VAULT_PASSPHRASE`, if set in the calling
    /// shell) can leak in, then restores only what's needed to spawn a
    /// process on each platform.
    fn cmd(&self) -> Command {
        let mut cmd = Command::cargo_bin("hearth-vault").expect("locate hearth-vault binary");
        cmd.env_clear()
            .env("HEARTH_VAULT_HOME", self.home_path())
            .env("HEARTH_VAULT_PASSPHRASE", TEST_PASSPHRASE);

        // Minimal passthrough so child processes (including the `exec`
        // tests' re-invoked test binary) can actually start on every
        // platform. None of these carry vault state.
        for key in [
            "PATH",
            "SystemRoot",
            "windir",
            "TEMP",
            "TMP",
            "HOME",
            "USERPROFILE",
            "COMSPEC",
        ] {
            if let Ok(val) = std::env::var(key) {
                cmd.env(key, val);
            }
        }
        cmd
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ── set / list / has / delete ───────────────────────────────────────────

#[test]
fn set_list_has_delete_roundtrip() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/api-key"])
        .write_stdin("roundtrip-fixture-value\n")
        .assert()
        .success();

    fx.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("myapp/api-key"));

    fx.cmd()
        .args(["has", "myapp/api-key"])
        .assert()
        .success()
        .stdout(predicate::str::contains("yes"));

    fx.cmd()
        .args(["has", "myapp/does-not-exist"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("no"));

    fx.cmd()
        .args(["delete", "myapp/api-key"])
        .assert()
        .success();

    fx.cmd()
        .args(["has", "myapp/api-key"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("no"));
}

/// `set` with no `--tier` defaults to tier 3 (use-only), and `list` surfaces
/// that in its TIER column.
#[test]
fn set_default_tier_is_three_and_visible_in_list() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/default-tier-key"])
        .write_stdin("default-tier-fixture-value\n")
        .assert()
        .success();

    let assert = fx.cmd().arg("list").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let row = stdout
        .lines()
        .find(|l| l.contains("myapp/default-tier-key"))
        .unwrap_or_else(|| panic!("no row for default-tier-key in list output:\n{stdout}"));
    let cols: Vec<&str> = row.split_whitespace().collect();
    assert_eq!(
        cols.get(1).copied(),
        Some("3"),
        "default tier must print as 3 in list output, row was: {row}"
    );
}

// ── tier-3 exec injection + env-name mapping ────────────────────────────

/// `exec --prefix myapp/ -- <cmd>` puts tier-3 (default) values into the
/// child's environment, mapping `myapp/api-key` -> `$API_KEY` (strip prefix,
/// uppercase, `/` and `-` both become `_`).
#[test]
fn exec_injects_tier3_with_prefix_name_mapping() {
    let fx = VaultFixture::new();
    let secret_value = "exec-injection-fixture-value-42";

    fx.cmd()
        .args(["set", "myapp/api-key", "--tier", "3"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    let helper = std::env::current_exe().expect("path to this test binary");

    let assert = fx
        .cmd()
        .env("HV_TEST_ECHO_VAR", "API_KEY")
        .args(["exec", "--prefix", "myapp/", "--"])
        .arg(&helper)
        .args(["helper_print_env", "--exact", "--nocapture"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let marker = format!("HV_ECHO_BEGIN:{secret_value}:HV_ECHO_END");
    assert!(
        stdout.contains(&marker),
        "expected env-injection marker not found in child output:\n{stdout}"
    );
}

/// A key with a hyphen maps `-` to `_` same as `/`, per `env_name_for`.
#[test]
fn exec_maps_hyphen_to_underscore_in_env_name() {
    let fx = VaultFixture::new();
    let secret_value = "hyphen-mapping-fixture-value";

    fx.cmd()
        .args(["set", "myapp/db-password", "--tier", "3"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    let helper = std::env::current_exe().expect("path to this test binary");

    let assert = fx
        .cmd()
        .env("HV_TEST_ECHO_VAR", "DB_PASSWORD")
        .args(["exec", "--prefix", "myapp/", "--"])
        .arg(&helper)
        .args(["helper_print_env", "--exact", "--nocapture"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let marker = format!("HV_ECHO_BEGIN:{secret_value}:HV_ECHO_END");
    assert!(
        stdout.contains(&marker),
        "expected DB_PASSWORD marker not found in child output:\n{stdout}"
    );
}

// ── tier-4 (sign-only): never exec-injected, never exportable ──────────

#[test]
fn tier4_is_not_exec_injectable() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/signing-key", "--tier", "4"])
        .write_stdin("sign-only-fixture-value\n")
        .assert()
        .success();

    let helper = std::env::current_exe().expect("path to this test binary");

    // No other injectable keys under this prefix, so exec must refuse
    // outright rather than silently running the child with nothing injected.
    fx.cmd()
        .args(["exec", "--prefix", "myapp/", "--"])
        .arg(&helper)
        .args(["helper_print_env", "--exact", "--nocapture"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("no injectable keys"));
}

#[test]
fn tier4_is_not_exportable() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/signing-key", "--tier", "4"])
        .write_stdin("sign-only-fixture-value\n")
        .assert()
        .success();

    fx.cmd()
        .env("HEARTH_VAULT_ALLOW_NON_TTY", "1")
        .args([
            "export-env",
            "myapp/signing-key",
            "--env-name",
            "SIGNING_KEY",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("never printed"));
}

// ── the non-TTY refusal: the single most important property here ──────

/// Under `cargo test`, `assert_cmd` gives the child a piped (non-TTY)
/// stdout — exactly the condition this refusal exists to catch. No special
/// TTY-faking is needed; this is the real, natural non-interactive case.
#[test]
fn export_env_refuses_non_tty_and_allows_with_override() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/token", "--tier", "2"])
        .write_stdin("export-refusal-fixture-value\n")
        .assert()
        .success();

    fx.cmd()
        .args(["export-env", "myapp/token", "--env-name", "TOKEN"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("HEARTH_VAULT_ALLOW_NON_TTY"));

    fx.cmd()
        .env("HEARTH_VAULT_ALLOW_NON_TTY", "1")
        .args(["export-env", "myapp/token", "--env-name", "TOKEN"])
        .assert()
        .success();
}

/// `exec` is deliberately exempt from the non-TTY refusal — the value goes
/// straight into a child process's environment, never a stream the caller
/// reads, so the safe automation path must stay open without the override.
#[test]
fn exec_succeeds_without_tty_override() {
    let fx = VaultFixture::new();
    let secret_value = "exec-no-override-fixture-value";

    fx.cmd()
        .args(["set", "myapp/token", "--tier", "2"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    let helper = std::env::current_exe().expect("path to this test binary");

    let assert = fx
        .cmd()
        .env("HV_TEST_ECHO_VAR", "TOKEN")
        .args(["exec", "--prefix", "myapp/", "--"])
        .arg(&helper)
        .args(["helper_print_env", "--exact", "--nocapture"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let marker = format!("HV_ECHO_BEGIN:{secret_value}:HV_ECHO_END");
    assert!(
        stdout.contains(&marker),
        "exec without HEARTH_VAULT_ALLOW_NON_TTY should still inject; child output:\n{stdout}"
    );
}

// ── invalid tier ─────────────────────────────────────────────────────

#[test]
fn invalid_tier_is_rejected() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/bad-tier", "--tier", "99"])
        .write_stdin("value\n")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid tier"));
}

// ── vault file never contains plaintext ─────────────────────────────

#[test]
fn vault_file_contains_no_plaintext_key_or_value() {
    let fx = VaultFixture::new();
    let distinctive_key = "myapp/distinctive-plaintext-probe-key";
    let distinctive_value = "distinctive-plaintext-probe-value-987654";

    fx.cmd()
        .args(["set", distinctive_key])
        .write_stdin(format!("{distinctive_value}\n"))
        .assert()
        .success();

    let raw = std::fs::read(fx.vault_file()).expect("read vault file bytes");
    let raw_str = String::from_utf8_lossy(&raw);

    assert!(
        !raw_str.contains(distinctive_key),
        "vault file leaked the plaintext key name"
    );
    assert!(
        !raw_str.contains(distinctive_value),
        "vault file leaked the plaintext secret value"
    );
    // Also check the raw bytes directly in case of encoding surprises the
    // lossy UTF-8 string conversion above could mask.
    assert!(
        !contains_bytes(&raw, distinctive_key.as_bytes()),
        "vault file bytes contain the plaintext key name"
    );
    assert!(
        !contains_bytes(&raw, distinctive_value.as_bytes()),
        "vault file bytes contain the plaintext secret value"
    );
}

// ── hermeticity: the real vault location is never touched ──────────

#[test]
fn vault_lives_under_the_fixtures_temp_dir_not_the_real_default() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/probe"])
        .write_stdin("hermeticity-probe-value\n")
        .assert()
        .success();

    let vault_file = fx.vault_file();
    assert!(vault_file.exists(), "vault file should exist after `set`");
    assert!(
        vault_file.starts_with(fx.home_path()),
        "vault file {vault_file:?} must live under the fixture's temp HEARTH_VAULT_HOME {:?}",
        fx.home_path()
    );
    // `tempfile::TempDir` always allocates under the platform temp root
    // (`$TMPDIR`/`TMP`/`TEMP` or the OS default) — this is the actual
    // guarantee that the real, permanent vault location was never touched.
    assert!(
        fx.home_path().starts_with(std::env::temp_dir()),
        "fixture home {:?} is not under the platform temp dir {:?}",
        fx.home_path(),
        std::env::temp_dir()
    );
}
