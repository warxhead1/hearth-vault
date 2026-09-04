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
    // Opt-in self-sealing, exercised by the `--warn-unsealed` tests below:
    // this must run BEFORE anything else so the child's window of exposure
    // matches what a real self-sealing consumer would do (seal first thing
    // in main(), before touching the injected secret).
    if std::env::var("HV_TEST_SEAL_SELF").is_ok() {
        hearth_vault::hsm::platform::disable_core_dumps();
    }
    if let Ok(var_name) = std::env::var("HV_TEST_ECHO_VAR") {
        let value = std::env::var(&var_name).unwrap_or_default();
        // Distinctive markers so the parent test can find this exact line
        // among libtest's own "running 1 test" / "test ... ok" chatter.
        println!("HV_ECHO_BEGIN:{value}:HV_ECHO_END");
    }
    // `--warn-unsealed`'s poll window is up to ~2s of 50ms probes (see
    // `poll_seal_and_warn` in src/main.rs for why it's that generous); this
    // must outlast the full window so a still-`Readable` child survives
    // long enough for the warning's LAST probe to actually fire, and so a
    // slow-to-seal child (under parallel-test scheduler contention) is
    // still alive when a later probe catches it sealed. The margin here
    // (well beyond the nominal 2s) is deliberate: MEASURED flake under a
    // fully loaded `pre-push` run (full test suite + a concurrent build)
    // where `thread::sleep`'s 50ms intervals stretched enough that the
    // poll loop's own wall-clock time exceeded a tighter hold-open budget,
    // making the child exit mid-poll and the warning never fire.
    if std::env::var("HV_TEST_HOLD_OPEN").is_ok() {
        std::thread::sleep(std::time::Duration::from_millis(8000));
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

#[cfg(target_os = "linux")]
#[test]
fn init_machine_is_noninteractive_and_recovery_is_recipient_encrypted() {
    use std::os::unix::fs::PermissionsExt;

    let fx = VaultFixture::new();
    let bin_dir = fx.home_path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let fake = bin_dir.join("systemd-creds");
    let helper_log = fx.home_path().join("systemd-creds.args");
    std::fs::write(
        &fake,
        b"#!/bin/sh\nprintf '%s\\n' \"$*\" >>\"$HEARTH_VAULT_TEST_SYSTEMD_CREDS_LOG\"\ncase \"$1\" in --version) exit 0;; encrypt|decrypt) cat; exit 0;; *) exit 64;; esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
    let recovery_output = fx.home_path().join("machine-recovery.hvs");
    let identity = hearth_vault::share::public_identity(&[9u8; 32]);

    let initialized = fx
        .cmd()
        .env("HEARTH_VAULT_TEST_SYSTEMD_CREDS", &fake)
        .env("HEARTH_VAULT_TEST_SYSTEMD_CREDS_LOG", &helper_log)
        .env_remove("HEARTH_VAULT_PASSPHRASE")
        .args([
            "--backend",
            "systemd-creds",
            "init-machine",
            "--recovery-recipient",
            &identity,
            "--recovery-output",
            recovery_output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stderr(predicate::str::contains("no secret value was printed"));
    let combined = [
        initialized.get_output().stdout.as_slice(),
        initialized.get_output().stderr.as_slice(),
    ]
    .concat();
    assert!(!contains_bytes(&combined, b"machine/recovery-mnemonic"));

    fx.cmd()
        .env("HEARTH_VAULT_TEST_SYSTEMD_CREDS", &fake)
        .env("HEARTH_VAULT_TEST_SYSTEMD_CREDS_LOG", &helper_log)
        .env_remove("HEARTH_VAULT_PASSPHRASE")
        .args(["--backend", "systemd-creds", "status"])
        .assert()
        .success();

    let helper_args = std::fs::read_to_string(&helper_log).unwrap();
    assert!(helper_args.contains("encrypt --name=hearth-vault --with-key=host - -"));
    assert!(helper_args.contains("decrypt --name=hearth-vault - -"));

    let bundle: hearth_vault::share::Bundle =
        serde_json::from_slice(&std::fs::read(&recovery_output).unwrap()).unwrap();
    let (entries, _) = hearth_vault::share::open(&bundle, &[9u8; 32]).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].key, "machine/recovery-mnemonic");
    assert_eq!(entries[0].tier, 3);

    let sealed = fx.home_path().join("vault-passphrase.sealed");
    let mut tampered = std::fs::read(&sealed).unwrap();
    tampered[0] ^= 0x01;
    std::fs::write(&sealed, tampered).unwrap();
    fx.cmd()
        .env("HEARTH_VAULT_TEST_SYSTEMD_CREDS", &fake)
        .env("HEARTH_VAULT_TEST_SYSTEMD_CREDS_LOG", &helper_log)
        .env_remove("HEARTH_VAULT_PASSPHRASE")
        .arg("list")
        .assert()
        .failure();
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

/// Rotating a value must not change who can read it. `set` on an existing
/// key with no `--tier` keeps that key's tier; the tier-3 default applies to
/// NEW keys only. Before this was fixed, rotating a tier-2 credential quietly
/// promoted it to use-only and broke whatever consumed it via export-env.
#[test]
fn set_preserves_the_tier_of_an_existing_key() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/rotating-key", "--tier", "2"])
        .write_stdin("first-value\n")
        .assert()
        .success();

    // Rotate: same key, new value, no --tier.
    fx.cmd()
        .args(["set", "myapp/rotating-key"])
        .write_stdin("second-value\n")
        .assert()
        .success();

    let assert = fx.cmd().arg("list").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let row = stdout
        .lines()
        .find(|l| l.contains("myapp/rotating-key"))
        .unwrap_or_else(|| panic!("no row for rotating-key in list output:\n{stdout}"));
    let cols: Vec<&str> = row.split_whitespace().collect();
    assert_eq!(
        cols.get(1).copied(),
        Some("2"),
        "rotation must keep tier 2, row was: {row}"
    );

    // An explicit --tier still wins.
    fx.cmd()
        .args(["set", "myapp/rotating-key", "--tier", "3"])
        .write_stdin("third-value\n")
        .assert()
        .success();

    let assert = fx.cmd().arg("list").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let row = stdout
        .lines()
        .find(|l| l.contains("myapp/rotating-key"))
        .unwrap_or_else(|| panic!("no row for rotating-key:\n{stdout}"));
    assert_eq!(
        row.split_whitespace().nth(1),
        Some("3"),
        "explicit --tier must override the preserved tier, row was: {row}"
    );
}

/// Tier 4 must be a one-way door. If `retier` can walk a sign-only key back
/// down to an exportable tier, then tier 4 is advice, not a control: anything
/// that can run the binary could downgrade a signing key and export it on the
/// next line, with no proof it ever held the value.
#[test]
fn tier_four_cannot_be_downgraded_by_retier() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/signing-key", "--tier", "4"])
        .write_stdin("sign-only-fixture-value\n")
        .assert()
        .success();

    fx.cmd()
        .args(["retier", "myapp/signing-key", "--tier", "2"])
        .assert()
        .failure()
        .stderr(predicates::str::contains("refusing to lower"));

    // ...and it is still tier 4 afterwards.
    let assert = fx.cmd().arg("list").assert().success();
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let row = stdout
        .lines()
        .find(|l| l.contains("myapp/signing-key"))
        .unwrap_or_else(|| panic!("no row for signing-key:\n{stdout}"));
    assert_eq!(
        row.split_whitespace().nth(1),
        Some("4"),
        "tier must be unchanged after a refused downgrade, row was: {row}"
    );
}

// ── tier-3 exec injection + env-name mapping ────────────────────────────

/// `exec --prefix myapp/ -- <cmd>` puts tier-3 (default) values into the
/// child's environment, mapping `myapp/api-key` -> `$API_KEY` (strip prefix,
/// uppercase, `/` and `-` both become `_`).
#[test]
fn exec_injects_tier3_with_prefix_name_mapping() {
    let fx = VaultFixture::new();
    let secret_value = "exec-injection-fixture-value-42"; // hearth-vault:allow (test fixture, not a credential)

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
    let secret_value = "hyphen-mapping-fixture-value"; // hearth-vault:allow (test fixture, not a credential)

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

/// `exec --redact` scrubs an injected secret value that the child echoes
/// back on its own stdout, replacing it with `<vault:KEY_NAME>` — the
/// exact incident class (an API/script echoing an injected value back into
/// output an agent then reads) this flag exists to kill.
#[test]
fn exec_redact_scrubs_value_the_child_echoes_to_stdout() {
    let fx = VaultFixture::new();
    // Long enough to clear the 8-byte redaction floor.
    let secret_value = "exec-redact-fixture-value-should-not-appear"; // hearth-vault:allow (test fixture, not a credential)

    fx.cmd()
        .args(["set", "myapp/api-key", "--tier", "3"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    let helper = std::env::current_exe().expect("path to this test binary");

    let assert = fx
        .cmd()
        .env("HV_TEST_ECHO_VAR", "API_KEY")
        .args(["exec", "--prefix", "myapp/", "--redact", "--"])
        .arg(&helper)
        .args(["helper_print_env", "--exact", "--nocapture"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        !stdout.contains(secret_value),
        "raw secret leaked through --redact:\n{stdout}"
    );
    assert!(
        stdout.contains("<vault:API_KEY>"),
        "expected placeholder not found in redacted output:\n{stdout}"
    );
}

/// Plain `exec` (no `--redact`) is unchanged: an echoed secret still comes
/// through verbatim. This pins the opt-in contract — redaction must never
/// engage unless asked for, because existing consumers (e.g.
/// tachyonac-engine's deploy scripts) capture exec's passthrough output as
/// the value itself.
#[test]
fn exec_without_redact_still_passes_the_value_through_verbatim() {
    let fx = VaultFixture::new();
    let secret_value = "exec-no-redact-fixture-value-passthrough"; // hearth-vault:allow (test fixture, not a credential)

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
        "expected unredacted marker not found:\n{stdout}"
    );
}

/// `HEARTH_VAULT_REDACT=1` is equivalent to `--redact`.
#[test]
fn exec_redact_env_var_is_equivalent_to_the_flag() {
    let fx = VaultFixture::new();
    let secret_value = "exec-redact-env-var-fixture-value-x"; // hearth-vault:allow (test fixture, not a credential)

    fx.cmd()
        .args(["set", "myapp/api-key", "--tier", "3"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    let helper = std::env::current_exe().expect("path to this test binary");

    let assert = fx
        .cmd()
        .env("HV_TEST_ECHO_VAR", "API_KEY")
        .env("HEARTH_VAULT_REDACT", "1")
        .args(["exec", "--prefix", "myapp/", "--"])
        .arg(&helper)
        .args(["helper_print_env", "--exact", "--nocapture"])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        !stdout.contains(secret_value),
        "raw secret leaked despite HEARTH_VAULT_REDACT=1:\n{stdout}"
    );
}

// ── --warn-unsealed: observing whether the CHILD sealed itself ─────────
//
// Linux-only (like the underlying `/proc` probe itself — see
// `hsm::platform::probe_seal_status`): on macOS/Windows there is no
// portable equivalent to check from outside the process, so
// `--warn-unsealed` is a documented no-op there and these two tests would
// otherwise assert behavior the feature deliberately does not provide.

/// The core claim: a plain child (no self-sealing) still gets its secrets
/// injected exactly as before, AND now also earns a stderr warning naming
/// the exposure risk — the exact mechanism (`ps eww` / `/proc/<pid>/environ`
/// readable to any same-UID process) behind the 2026-09-04 incident this
/// flag exists to surface.
#[test]
#[cfg(target_os = "linux")]
fn exec_warn_unsealed_warns_about_an_unsealed_child() {
    let fx = VaultFixture::new();
    let secret_value = "warn-unsealed-fixture-value-unsealed"; // hearth-vault:allow (test fixture, not a credential)

    fx.cmd()
        .args(["set", "myapp/api-key", "--tier", "3"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    let helper = std::env::current_exe().expect("path to this test binary");

    let assert = fx
        .cmd()
        .env("HV_TEST_ECHO_VAR", "API_KEY")
        .env("HV_TEST_HOLD_OPEN", "1")
        .args(["exec", "--prefix", "myapp/", "--warn-unsealed", "--"])
        .arg(&helper)
        .args(["helper_print_env", "--exact", "--nocapture"])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("has not sealed") && stderr.contains("PR_SET_DUMPABLE"),
        "expected an unsealed-child warning on stderr, got:\n{stderr}"
    );

    // The value itself is never touched by this feature — still passes
    // through exactly like plain `exec` would.
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let marker = format!("HV_ECHO_BEGIN:{secret_value}:HV_ECHO_END");
    assert!(
        stdout.contains(&marker),
        "expected the injected value to still pass through unchanged:\n{stdout}"
    );
}

/// The negative case: a child that calls `disable_core_dumps()` (the same
/// primitive `hearth-vault` itself calls at startup) on entry gets NO
/// warning — this is the "consumer did the right thing" path, and a false
/// positive here would train operators to ignore the warning.
#[test]
#[cfg(target_os = "linux")]
fn exec_warn_unsealed_is_silent_for_a_self_sealed_child() {
    let fx = VaultFixture::new();
    let secret_value = "warn-unsealed-fixture-value-sealed"; // hearth-vault:allow (test fixture, not a credential)

    fx.cmd()
        .args(["set", "myapp/api-key", "--tier", "3"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    let helper = std::env::current_exe().expect("path to this test binary");

    let assert = fx
        .cmd()
        .env("HV_TEST_ECHO_VAR", "API_KEY")
        .env("HV_TEST_SEAL_SELF", "1")
        .env("HV_TEST_HOLD_OPEN", "1")
        .args(["exec", "--prefix", "myapp/", "--warn-unsealed", "--"])
        .arg(&helper)
        .args(["helper_print_env", "--exact", "--nocapture"])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        !stderr.contains("has not sealed"),
        "a self-sealed child must not trigger the unsealed warning:\n{stderr}"
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
    let secret_value = "exec-no-override-fixture-value"; // hearth-vault:allow (test fixture, not a credential)

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

/// `--version` is not decoration here: the release workflow smoke-tests every
/// artifact with it before publishing, and it is how a user confirms which
/// build they hold when the binaries are unsigned and checksum-verified.
#[test]
fn version_flag_reports_the_crate_version() {
    VaultFixture::new()
        .cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicates::str::contains(env!("CARGO_PKG_VERSION")));
}

// ── rotation state ──────────────────────────────────────────────────────

/// The whole point of storing a policy: a later `set` of the same key moves
/// the due date forward on its own. If rotation needed a second command,
/// people would forget it and the dates would be lies.
#[test]
fn rotating_a_value_moves_its_due_date_forward() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/token", "--rotate-days", "30"])
        .write_stdin("first-fixture-value\n")
        .assert()
        .success();

    let first = String::from_utf8(
        fx.cmd()
            .args(["list", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(first.contains("\"rotate_days\": 30"));
    let first_due = extract_json_string(&first, "expires_at");

    std::thread::sleep(std::time::Duration::from_millis(1100));

    fx.cmd()
        .args(["set", "myapp/token"])
        .write_stdin("second-fixture-value\n")
        .assert()
        .success();

    let second = String::from_utf8(
        fx.cmd()
            .args(["list", "--json"])
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap();
    assert!(
        second.contains("\"rotate_days\": 30"),
        "the policy must survive a rotation"
    );
    assert_ne!(
        first_due,
        extract_json_string(&second, "expires_at"),
        "storing a new value must push the due date forward"
    );
}

/// `list --due` is meant to drop into cron/CI, so the exit code carries the
/// answer. An overdue key must make it non-zero and a clean vault zero.
#[test]
fn list_due_exit_code_reports_overdue_credentials() {
    let fx = VaultFixture::new();

    // A key with no policy is never "due" -- old entries must not suddenly
    // start reporting as overdue when a user upgrades.
    fx.cmd()
        .args(["set", "myapp/no-policy"])
        .write_stdin("fixture-value\n")
        .assert()
        .success();
    fx.cmd().args(["list", "--due"]).assert().success();

    // An expiry in the past is overdue.
    fx.cmd()
        .args(["set", "myapp/expired", "--expires", "-1d"])
        .write_stdin("fixture-value\n")
        .assert()
        .success();
    fx.cmd()
        .args(["list", "--due"])
        .assert()
        .failure()
        .stdout(predicate::str::contains("myapp/expired"));
}

/// `list --json` is the scripting surface; it must never gain a value field.
#[test]
fn list_json_carries_metadata_but_never_values() {
    let fx = VaultFixture::new();
    fx.cmd()
        .args(["set", "myapp/api-key"])
        .write_stdin("json-fixture-secret-value\n")
        .assert()
        .success();

    let out = fx.cmd().args(["list", "--json"]).assert().success();
    let stdout = &out.get_output().stdout;
    assert!(contains_bytes(stdout, b"myapp/api-key"));
    assert!(
        !contains_bytes(stdout, b"json-fixture-secret-value"),
        "list --json must never emit a value"
    );
}

fn extract_json_string(json: &str, field: &str) -> String {
    let needle = format!("\"{field}\": \"");
    let start = json.find(&needle).map(|i| i + needle.len());
    match start {
        Some(s) => json[s..].split('"').next().unwrap_or_default().to_string(),
        None => String::new(),
    }
}

// ── backup / restore ────────────────────────────────────────────────────

/// A delete must be undoable, because the recovery mnemonic restores the
/// vault key and not the entries you removed.
#[test]
fn delete_snapshots_first_and_restore_brings_the_key_back() {
    let fx = VaultFixture::new();
    fx.cmd()
        .args(["set", "myapp/precious"])
        .write_stdin("precious-fixture-value\n")
        .assert()
        .success();

    fx.cmd()
        .args(["delete", "myapp/precious"])
        .assert()
        .success();
    fx.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("myapp/precious").not());

    // The pre-delete snapshot lands next to the vault file.
    let snapshot = std::fs::read_dir(fx.home_path())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("vault-") && n.ends_with(".json"))
        })
        .expect("delete must leave a snapshot behind");

    fx.cmd()
        .args(["restore", snapshot.to_str().unwrap()])
        .assert()
        .success();

    fx.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("myapp/precious"));
}

/// Restoring a file that cannot be opened must leave the live vault intact.
/// Getting this wrong destroys both copies at once.
#[test]
fn a_bad_restore_leaves_the_existing_vault_untouched() {
    let fx = VaultFixture::new();
    fx.cmd()
        .args(["set", "myapp/keeper"])
        .write_stdin("keeper-fixture-value\n")
        .assert()
        .success();
    let before = std::fs::read(fx.vault_file()).unwrap();

    let junk = fx.home_path().join("not-a-vault.json");
    std::fs::write(&junk, b"{\"version\":2,\"nonsense\":true}").unwrap();

    fx.cmd()
        .args(["restore", junk.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("nothing was changed"));

    assert_eq!(
        before,
        std::fs::read(fx.vault_file()).unwrap(),
        "a failed restore must not modify the live vault"
    );
    fx.cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("myapp/keeper"));
}

// ── sharing ─────────────────────────────────────────────────────────────

/// The full two-party flow, with two genuinely separate vaults.
#[test]
fn share_and_receive_between_two_vaults() {
    let sender = VaultFixture::new();
    let recipient = VaultFixture::new();

    sender
        .cmd()
        .args(["set", "team/db-password"])
        .write_stdin("shared-fixture-value\n")
        .assert()
        .success();

    let identity = String::from_utf8(
        recipient
            .cmd()
            .arg("identity")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim()
    .to_string();
    assert!(identity.starts_with("hv1pub"), "got: {identity}");

    let bundle = sender.home_path().join("bundle.hvs");
    sender
        .cmd()
        .args([
            "share",
            "--prefix",
            "team/",
            "--to",
            &identity,
            "--output",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    // The bundle is a file that gets emailed around: it must not contain
    // the value in any readable form.
    let raw = std::fs::read(&bundle).unwrap();
    assert!(
        !contains_bytes(&raw, b"shared-fixture-value"),
        "the bundle must not carry a plaintext value"
    );
    assert!(
        !contains_bytes(&raw, b"team/db-password"),
        "the bundle must not carry plaintext key names either"
    );

    recipient
        .cmd()
        .args(["receive", bundle.to_str().unwrap()])
        .assert()
        .success();
    recipient
        .cmd()
        .arg("list")
        .assert()
        .success()
        .stdout(predicate::str::contains("team/db-password"));
}

/// A bundle addressed to someone else must be refused, and refused with an
/// explanation rather than a decryption error.
#[test]
fn a_third_party_cannot_receive_someone_elses_bundle() {
    let sender = VaultFixture::new();
    let recipient = VaultFixture::new();
    let stranger = VaultFixture::new();

    sender
        .cmd()
        .args(["set", "team/secret"])
        .write_stdin("not-for-the-stranger\n")
        .assert()
        .success();

    let identity = String::from_utf8(
        recipient
            .cmd()
            .arg("identity")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim()
    .to_string();

    let bundle = sender.home_path().join("bundle.hvs");
    sender
        .cmd()
        .args([
            "share",
            "--prefix",
            "team/",
            "--to",
            &identity,
            "--output",
            bundle.to_str().unwrap(),
        ])
        .assert()
        .success();

    stranger
        .cmd()
        .args(["receive", bundle.to_str().unwrap()])
        .assert()
        .failure()
        .stderr(predicate::str::contains("addressed to"));
}

/// Sign-only keys must not be shareable by any route -- that tier's promise
/// is that the material never leaves the process holding it.
#[test]
fn tier_four_keys_cannot_be_shared() {
    let sender = VaultFixture::new();
    let recipient = VaultFixture::new();

    sender
        .cmd()
        .args(["set", "team/signing-key", "--tier", "4"])
        .write_stdin("sign-only-fixture-value\n")
        .assert()
        .success();

    let identity = String::from_utf8(
        recipient
            .cmd()
            .arg("identity")
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim()
    .to_string();

    sender
        .cmd()
        .args([
            "share",
            "--prefix",
            "team/",
            "--to",
            &identity,
            "--output",
            sender.home_path().join("b.hvs").to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("sign-only"));
}

// ── exec prefix discovery ───────────────────────────────────────────────

/// `exec` with no --prefix must find the project marker, so an agent in a
/// configured repo does not have to guess or hardcode a prefix.
#[test]
fn exec_falls_back_to_the_project_marker_for_its_prefix() {
    let fx = VaultFixture::new();
    fx.cmd()
        .args(["set", "marker/api-key"])
        .write_stdin("marker-fixture-value\n")
        .assert()
        .success();

    let project = fx.home_path().join("project");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join(".hearth-vault"), "marker/\n").unwrap();

    let helper = std::env::current_exe().expect("test binary path");
    let out = fx
        .cmd()
        .current_dir(&project)
        .env("HV_TEST_ECHO_VAR", "API_KEY")
        .args([
            "exec",
            "--",
            helper.to_str().unwrap(),
            "helper_print_env",
            "--exact",
            "--nocapture",
        ])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&out.get_output().stdout).into_owned();
    assert!(
        stdout.contains("HV_ECHO_BEGIN:marker-fixture-value:HV_ECHO_END"),
        "prefix was not discovered from .hearth-vault; got: {stdout}"
    );
}

/// With nothing discoverable, the error must name every way to fix it --
/// this is the message a new user meets first.
#[test]
fn exec_without_a_discoverable_prefix_explains_the_options() {
    let fx = VaultFixture::new();
    let empty = fx.home_path().join("empty");
    std::fs::create_dir_all(&empty).unwrap();

    fx.cmd()
        .current_dir(&empty)
        .args(["exec", "--", "true"])
        .assert()
        .failure()
        .stderr(
            predicate::str::contains("--prefix")
                .and(predicate::str::contains("HEARTH_VAULT_PREFIX"))
                .and(predicate::str::contains(".hearth-vault")),
        );
}

// ── seal-check: auditing an already-running process ─────────────────────
//
// Linux-only, same reason as the `--warn-unsealed` tests above: the
// underlying probe needs `/proc`.

/// Spawn this test binary's `helper_print_env` re-invocation as a
/// stand-in "already-running consumer" for `seal-check` to audit, with a
/// FULLY CLEARED environment (`env_clear()`) plus only the `extra_env`
/// pairs the caller asks for.
///
/// This is deliberate and load-bearing, not incidental hygiene: a plain
/// `Command::new` without `env_clear()` inherits the calling test
/// process's entire ambient environment — which, in an interactive
/// developer/agent session, can include real API keys the session holds
/// for unrelated tools. `current_exe()` is an absolute path, so no `PATH`
/// lookup is needed to spawn it.
fn spawn_helper_child(extra_env: &[(&str, &str)]) -> std::process::Child {
    let helper = std::env::current_exe().expect("path to this test binary");
    let mut cmd = std::process::Command::new(&helper);
    cmd.env_clear()
        .args(["helper_print_env", "--exact", "--nocapture"])
        .stdout(std::process::Stdio::null());
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.spawn().expect("spawn hermetic helper child")
}

/// A plain (unsealed) process holding an env var whose NAME matches what
/// this vault would generate for one of its keys is reported READABLE with
/// that name flagged, and the command exits non-zero — the actionable
/// finding this whole feature exists to produce.
#[test]
#[cfg(target_os = "linux")]
fn seal_check_pid_flags_a_vault_managed_name_on_an_unsealed_process() {
    let fx = VaultFixture::new();
    let secret_value = "seal-check-fixture-value-in-vault"; // hearth-vault:allow (test fixture, not a credential)

    fx.cmd()
        .args(["set", "myapp/api-key", "--tier", "3"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    // Deliberately NOT launched via `hearth-vault exec` — this is a
    // stand-in for an already-running consumer `seal-check` audits after
    // the fact. The value here is a distinct fixture, never the vault's own
    // value; only the NAME `API_KEY` needs to match. Hermetic (`env_clear`)
    // so this can never touch the test session's own ambient environment.
    let mut child = spawn_helper_child(&[
        (
            "API_KEY",
            "child-side-fixture-value-not-vault-derived", // hearth-vault:allow (test fixture, not a credential)
        ),
        ("HV_TEST_HOLD_OPEN", "1"),
    ]);
    let pid = child.id();

    let assert = fx
        .cmd()
        .args(["seal-check", "--pid", &pid.to_string()])
        .assert()
        .code(1);

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        stdout.contains("READABLE") && stdout.contains("API_KEY"),
        "expected a READABLE finding naming API_KEY, got:\n{stdout}"
    );

    let _ = child.kill();
    let _ = child.wait();
}

/// The negative case for the SAME scenario: a process that seals itself
/// (`disable_core_dumps()`, same primitive `hearth-vault` calls on itself)
/// is reported SEALED and the command exits 0 — the "consumer did the
/// right thing" path.
#[test]
#[cfg(target_os = "linux")]
fn seal_check_pid_reports_sealed_for_a_self_sealed_process() {
    let fx = VaultFixture::new();
    let secret_value = "seal-check-fixture-value-sealed"; // hearth-vault:allow (test fixture, not a credential)

    fx.cmd()
        .args(["set", "myapp/api-key", "--tier", "3"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    let mut child = spawn_helper_child(&[
        (
            "API_KEY",
            "child-side-fixture-value-sealed", // hearth-vault:allow (test fixture, not a credential)
        ),
        ("HV_TEST_SEAL_SELF", "1"),
        ("HV_TEST_HOLD_OPEN", "1"),
    ]);
    let pid = child.id();

    let assert = fx
        .cmd()
        .args(["seal-check", "--pid", &pid.to_string()])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        stdout.contains("SEALED"),
        "expected a SEALED finding, got:\n{stdout}"
    );

    let _ = child.kill();
    let _ = child.wait();
}

/// A READABLE process whose env var names don't overlap the vault at all
/// is reported as such but does NOT fail the command — only a confirmed
/// name match is treated as a finding, never bare readability alone (an
/// unsealed `bash` or `sleep` is not itself news).
#[test]
#[cfg(target_os = "linux")]
fn seal_check_pid_readable_without_a_vault_match_exits_zero() {
    let fx = VaultFixture::new();
    let secret_value = "seal-check-fixture-value-unrelated"; // hearth-vault:allow (test fixture, not a credential)

    fx.cmd()
        .args(["set", "myapp/other-key", "--tier", "3"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    let mut child = spawn_helper_child(&[
        ("SOME_UNRELATED_VAR", "not-a-vault-name"),
        ("HV_TEST_HOLD_OPEN", "1"),
    ]);
    let pid = child.id();

    let assert = fx
        .cmd()
        .args(["seal-check", "--pid", &pid.to_string()])
        .assert()
        .success();

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        stdout.contains("READABLE"),
        "expected a READABLE finding, got:\n{stdout}"
    );
    assert!(
        !stdout.contains("OTHER_KEY"),
        "must not flag a vault key whose name the child never exposed:\n{stdout}"
    );

    let _ = child.kill();
    let _ = child.wait();
}

/// `--json` never changes WHAT is reported — same names-only contract —
/// only the format. Parsed structurally rather than string-matched, so a
/// future field addition doesn't silently break this test.
#[test]
#[cfg(target_os = "linux")]
fn seal_check_json_reports_structured_fields_names_only() {
    let fx = VaultFixture::new();
    let secret_value = "seal-check-fixture-value-json"; // hearth-vault:allow (test fixture, not a credential)

    fx.cmd()
        .args(["set", "myapp/api-key", "--tier", "3"])
        .write_stdin(format!("{secret_value}\n"))
        .assert()
        .success();

    let mut child = spawn_helper_child(&[
        (
            "API_KEY",
            "child-side-fixture-value-json", // hearth-vault:allow (test fixture, not a credential)
        ),
        ("HV_TEST_HOLD_OPEN", "1"),
    ]);
    let pid = child.id();

    let assert = fx
        .cmd()
        .args(["seal-check", "--pid", &pid.to_string(), "--json"])
        .assert()
        .code(1);

    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    let rows: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON output");
    let rows = rows.as_array().expect("top-level JSON array");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["pid"], pid);
    assert_eq!(rows[0]["status"], "readable");
    assert_eq!(rows[0]["exposed_vault_names"][0], "API_KEY");

    // Never a value: the fixture's secret string must not appear anywhere
    // in the JSON output, structurally or otherwise.
    assert!(!stdout.contains(secret_value));
    assert!(!stdout.contains("child-side-fixture-value-json"));

    let _ = child.kill();
    let _ = child.wait();
}

/// A vault that cannot be opened (wrong passphrase here) does not stop
/// seal status from being reported — it degrades to seal-status-only and
/// says so, rather than silently claiming a clean name-overlap result it
/// never actually checked.
#[test]
#[cfg(target_os = "linux")]
fn seal_check_reports_seal_status_even_when_the_vault_cannot_be_opened() {
    let fx = VaultFixture::new();

    fx.cmd()
        .args(["set", "myapp/api-key", "--tier", "3"])
        .write_stdin("seal-check-fixture-value-locked\n") // hearth-vault:allow (test fixture, not a credential)
        .assert()
        .success();

    let mut child = spawn_helper_child(&[("HV_TEST_HOLD_OPEN", "1")]);
    let pid = child.id();

    let assert = fx
        .cmd()
        .env("HEARTH_VAULT_PASSPHRASE", "definitely-the-wrong-passphrase")
        .args(["seal-check", "--pid", &pid.to_string()])
        .assert()
        .success();

    let stderr = String::from_utf8_lossy(&assert.get_output().stderr);
    assert!(
        stderr.contains("vault not opened") && stderr.contains("skipped"),
        "expected an explicit degraded-mode note, got:\n{stderr}"
    );
    let stdout = String::from_utf8_lossy(&assert.get_output().stdout);
    assert!(
        stdout.contains("READABLE"),
        "seal status must still be reported without the vault:\n{stdout}"
    );

    let _ = child.kill();
    let _ = child.wait();
}
