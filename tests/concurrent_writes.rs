//! Lost-update regression (issue #8): many processes mutating one vault at the
//! same moment must all land. Every invocation uses a throwaway
//! `HEARTH_VAULT_HOME` and a synthetic passphrase; nothing here can reach a
//! real vault.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as Std, Stdio};

use assert_cmd::Command;
use tempfile::TempDir;

const PASSPHRASE: &str = "race-test-fixture-passphrase-not-a-real-secret";
const N: usize = 16;

fn bin() -> std::ffi::OsString {
    Command::cargo_bin("hearth-vault")
        .expect("locate hearth-vault binary")
        .get_program()
        .to_owned()
}

fn base(home: &Path) -> Std {
    let mut c = Std::new(bin());
    c.env_clear()
        .env("HEARTH_VAULT_HOME", home)
        .env("HEARTH_VAULT_PASSPHRASE", PASSPHRASE);
    for key in [
        "PATH",
        "SystemRoot",
        "windir",
        "TEMP",
        "TMP",
        "HOME",
        "USERPROFILE",
    ] {
        if let Ok(v) = std::env::var(key) {
            c.env(key, v);
        }
    }
    c.stdout(Stdio::null()).stderr(Stdio::null());
    c
}

struct Job {
    key: String,
    src: Option<PathBuf>,
    child: Child,
}

/// Returns (keys whose command exited 0 but are not in the vault,
/// imports whose source file is gone but whose key is not in the vault).
fn run_round(seed_first: bool) -> (Vec<String>, Vec<String>) {
    let home = TempDir::new().unwrap();
    let srcs = TempDir::new().unwrap();
    if seed_first {
        let mut ch = base(home.path())
            .args(["set", "seed/base"])
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        ch.stdin
            .take()
            .unwrap()
            .write_all(b"synthetic-seed\n")
            .unwrap();
        assert!(ch.wait().unwrap().success());
    }

    let mut jobs = Vec::new();
    for i in 0..N {
        let key = format!("race/key-{i:02}");
        if i % 2 == 0 {
            let child = base(home.path())
                .args(["set", &key])
                .stdin(Stdio::piped())
                .spawn()
                .unwrap();
            jobs.push(Job {
                key,
                src: None,
                child,
            });
        } else {
            let f = srcs.path().join(format!("src-{i:02}.txt"));
            std::fs::write(&f, format!("synthetic-value-{i:02}")).unwrap();
            let child = base(home.path())
                .args(["import", f.to_str().unwrap(), "--key", &key])
                .spawn()
                .unwrap();
            jobs.push(Job {
                key,
                src: Some(f),
                child,
            });
        }
    }
    // Release the `set` children only once every process is up, so they
    // contend for the same window.
    for j in jobs.iter_mut() {
        if let Some(mut stdin) = j.child.stdin.take() {
            stdin.write_all(b"synthetic-set-value\n").unwrap();
        }
    }

    let mut ok_keys = Vec::new();
    let mut src_gone = Vec::new();
    for mut j in jobs {
        if j.child.wait().unwrap().success() {
            ok_keys.push(j.key.clone());
        }
        if let Some(f) = j.src
            && !f.exists()
        {
            src_gone.push(j.key);
        }
    }

    let out = base(home.path())
        .arg("list")
        .stdout(Stdio::piped())
        .output()
        .unwrap();
    let listing = String::from_utf8_lossy(&out.stdout).to_string();
    let missing = |keys: &[String]| -> Vec<String> {
        keys.iter()
            .filter(|k| !listing.contains(k.as_str()))
            .cloned()
            .collect()
    };
    (missing(&ok_keys), missing(&src_gone))
}

#[test]
fn parallel_set_and_import_on_distinct_keys_all_survive() {
    let mut lost = 0;
    let mut src_lost = 0;
    for round in 0..3 {
        let (l, s) = run_round(round != 0);
        eprintln!(
            "round {round}: {} of {N} succeeded-but-missing, {} source-deleted-but-missing",
            l.len(),
            s.len()
        );
        lost += l.len();
        src_lost += s.len();
    }
    assert_eq!(
        src_lost, 0,
        "an import deleted its source but the key was not stored"
    );
    assert_eq!(lost, 0, "reported-successful writes were lost");
}
