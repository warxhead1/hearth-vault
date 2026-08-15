//! A short-lived unlock cache, in the style of `ssh-agent`.
//!
//! # Why this exists
//! Opening the vault costs one Argon2id derivation — ~120ms on a desktop, by
//! design, because that cost is what makes the passphrase expensive to
//! attack. Paid once, that is invisible. Paid on every `exec` in a shell
//! wrapper or a loop, it is the reason people quietly go back to `.env`.
//!
//! The pre-agent workaround was `export HEARTH_VAULT_PASSPHRASE=$(hearth-vault
//! prompt)`, which parks the vault passphrase in an environment variable that
//! every child process — including the coding agents this project exists to
//! defend against — inherits and can read. That is the one place the old
//! design argued against its own thesis. This module replaces it.
//!
//! # What is cached, and what is not
//! The agent holds the passphrase-derived **wrap key**, never the passphrase
//! and never the data key. See `VaultStore::derive_wrap_key` for the full
//! reasoning; the short version is that a wrap key is scoped to one vault at
//! one salt, so `change-passphrase` invalidates every cached copy instantly,
//! and the human-reusable secret never leaves the process that read it.
//!
//! # Threat model
//! The socket lives in a `0700` directory inside `$XDG_RUNTIME_DIR` (a
//! tmpfs owned by you, cleared at logout) and is itself `0600`, and every
//! connection is checked with `SO_PEERCRED` to confirm the peer's uid
//! matches ours. That defends against other *users*. It does not — and
//! cannot — defend against another process running as you: anything with
//! your uid can already read `/proc/<pid>/environ` of your `exec`'d children
//! and ptrace them. The agent is strictly better than the env var it
//! replaces (bounded lifetime, not inherited, not visible in `ps`/`environ`),
//! and is not a substitute for tier 4, which is the answer when a key must
//! never be usable by a process you did not intend.
//!
//! Unix only. Windows has no `AF_UNIX` in std, and its answer to this
//! problem is the OS keyring auto-unseal path (tier 2), which has no
//! per-invocation KDF cost to begin with.

#![cfg(unix)]

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use zeroize::{Zeroize, Zeroizing};

/// Default cache lifetime. Long enough to cover a working session of shell
/// commands, short enough that a forgotten unlock does not outlive a coffee
/// break.
pub const DEFAULT_TTL_SECS: u64 = 900;

/// Socket path: `$XDG_RUNTIME_DIR/hearth-vault/agent.sock`, falling back to
/// `$TMPDIR/hearth-vault-<uid>/agent.sock` on systems without one (macOS).
/// `$HEARTH_VAULT_AGENT_SOCK` overrides both, which is what the tests use.
pub fn socket_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("HEARTH_VAULT_AGENT_SOCK") {
        return PathBuf::from(explicit);
    }
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR") {
        return PathBuf::from(runtime)
            .join("hearth-vault")
            .join("agent.sock");
    }
    // SAFETY: getuid is always safe; it cannot fail and touches no memory.
    let uid = unsafe { libc::getuid() };
    std::env::temp_dir()
        .join(format!("hearth-vault-{uid}"))
        .join("agent.sock")
}

/// Identify a vault by a hash of its canonical path rather than the path
/// itself, so the protocol never carries filesystem layout and a stray
/// `strace` on the socket reveals nothing about what you have or where.
fn vault_id(vault_path: &Path) -> String {
    let canonical = vault_path
        .canonicalize()
        .unwrap_or_else(|_| vault_path.to_path_buf());
    B64.encode(crate::crypto::hash_blake3(
        canonical.to_string_lossy().as_bytes(),
    ))
}

struct CachedKey {
    key: [u8; 32],
    expires: Instant,
}

impl Drop for CachedKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Default)]
struct Cache {
    keys: HashMap<String, CachedKey>,
}

impl Cache {
    fn reap(&mut self) {
        let now = Instant::now();
        self.keys.retain(|_, v| v.expires > now);
    }
}

// ── Client ───────────────────────────────────────────────────────────────

/// Ask a running agent for a cached wrap key. Returns `None` for every
/// "no agent" or "not cached" case — a missing or broken agent must degrade
/// to a passphrase prompt, never to an error.
pub fn try_get(vault_path: &Path) -> Option<Zeroizing<[u8; 32]>> {
    let mut stream = UnixStream::connect(socket_path()).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(2))).ok()?;
    writeln!(stream, "GET {}", vault_id(vault_path)).ok()?;
    let mut line = String::new();
    BufReader::new(&stream).read_line(&mut line).ok()?;
    let encoded = line.trim().strip_prefix("OK ")?;
    let bytes = Zeroizing::new(B64.decode(encoded).ok()?);
    if bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(Zeroizing::new(key))
}

/// Offer a freshly derived wrap key to a running agent. Best-effort and
/// silent: if no agent is listening this is a no-op, because "there is no
/// agent" is a normal, supported way to run.
pub fn try_put(vault_path: &Path, key: &[u8; 32]) -> bool {
    let Ok(mut stream) = UnixStream::connect(socket_path()) else {
        return false;
    };
    let line = Zeroizing::new(format!(
        "PUT {} {}\n",
        vault_id(vault_path),
        B64.encode(key)
    ));
    if stream.write_all(line.as_bytes()).is_err() {
        return false;
    }
    let mut resp = String::new();
    BufReader::new(&stream).read_line(&mut resp).is_ok() && resp.starts_with("OK")
}

/// Send a one-word command (`DROP`, `STATUS`, `STOP`) and return the reply.
pub fn control(word: &str) -> anyhow::Result<String> {
    let mut stream = UnixStream::connect(socket_path())
        .map_err(|e| anyhow::anyhow!("no agent running at {}: {e}", socket_path().display()))?;
    writeln!(stream, "{word}")?;
    let mut resp = String::new();
    BufReader::new(&stream).read_line(&mut resp)?;
    Ok(resp.trim().to_string())
}

/// True if an agent is listening and answering.
pub fn is_running() -> bool {
    control("STATUS").is_ok()
}

// ── Server ───────────────────────────────────────────────────────────────

/// Detach the calling process's stdio from the terminal, pointing all three
/// descriptors at `/dev/null`.
///
/// Required for `--daemon`, and not optional: a forked child that keeps the
/// inherited stdout holds the pipe open, so the shell that started it waits
/// forever for output that never comes. `hearth-vault agent --daemon`
/// appears to hang, which is exactly the first impression this feature
/// cannot afford.
pub fn detach_stdio() {
    // SAFETY: opening /dev/null and dup2'ing it over the three standard
    // descriptors. Failure is tolerable (we simply stay attached), so the
    // return values are checked rather than assumed.
    unsafe {
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_RDWR);
        if null < 0 {
            return;
        }
        libc::dup2(null, libc::STDIN_FILENO);
        libc::dup2(null, libc::STDOUT_FILENO);
        libc::dup2(null, libc::STDERR_FILENO);
        if null > libc::STDERR_FILENO {
            libc::close(null);
        }
    }
}

/// Run the agent in the foreground until it is told to stop or every cached
/// key has expired. Foreground by design: daemonising correctly (session
/// leader, fd hygiene, reparenting) is a pile of subtle code, and every
/// process supervisor already knows how to background a foreground process.
/// The CLI wraps this with `--daemon` for the common case.
pub fn serve(ttl: Duration) -> anyhow::Result<()> {
    let path = socket_path();
    let dir = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("agent socket path has no parent directory"))?;
    std::fs::create_dir_all(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;

    // A stale socket file from a killed agent would make bind() fail
    // forever. Only remove it once we know nothing is answering on it, so a
    // second `agent` invocation cannot silently steal a live agent's socket.
    if path.exists() {
        if UnixStream::connect(&path).is_ok() {
            anyhow::bail!(
                "an agent is already running on {} (use `hearth-vault agent --stop`)",
                path.display()
            );
        }
        std::fs::remove_file(&path)?;
    }

    let listener = UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;

    let cache = Arc::new(Mutex::new(Cache::default()));
    eprintln!(
        "hearth-vault agent listening on {} (ttl {}s)",
        path.display(),
        ttl.as_secs()
    );

    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        if !peer_is_self(&stream) {
            continue;
        }
        match handle(stream, &cache, ttl) {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) => tracing::debug!("agent connection error: {e}"),
        }
    }

    let _ = std::fs::remove_file(&path);
    Ok(())
}

/// Reject any peer that is not the same uid as us. Filesystem permissions
/// already do this; `SO_PEERCRED` is the belt to that suspenders, and it is
/// the check that still holds if someone loosens the directory mode.
fn peer_is_self(stream: &UnixStream) -> bool {
    use std::os::unix::io::AsRawFd;
    let fd = stream.as_raw_fd();
    // SAFETY: getuid cannot fail.
    let us = unsafe { libc::getuid() };

    // std's `UnixStream::peer_cred` is still unstable, so this reaches for
    // the platform call directly. Linux spells it SO_PEERCRED on the socket;
    // the BSDs (macOS included) spell it getpeereid().
    #[cfg(target_os = "linux")]
    {
        let mut cred = libc::ucred {
            pid: 0,
            uid: u32::MAX,
            gid: u32::MAX,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        // SAFETY: `cred` is a live, correctly-sized ucred and `len` matches
        // it; getsockopt writes at most `len` bytes into it.
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&raw mut cred).cast(),
                &mut len,
            )
        };
        rc == 0 && cred.uid == us
    }
    #[cfg(not(target_os = "linux"))]
    {
        let mut uid: libc::uid_t = u32::MAX;
        let mut gid: libc::gid_t = u32::MAX;
        // SAFETY: both out-params are live, correctly typed locals.
        let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
        rc == 0 && uid == us
    }
}

/// Handle one connection. Returns `Ok(true)` when the agent should exit.
fn handle(stream: UnixStream, cache: &Arc<Mutex<Cache>>, ttl: Duration) -> anyhow::Result<bool> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let mut parts = line.trim().splitn(3, ' ');
    let verb = parts.next().unwrap_or("");

    match verb {
        "GET" => {
            let id = parts.next().unwrap_or("");
            let mut cache = cache.lock().unwrap();
            cache.reap();
            match cache.keys.get(id) {
                Some(entry) => writeln!(writer, "OK {}", B64.encode(entry.key))?,
                None => writeln!(writer, "MISS")?,
            }
        }
        "PUT" => {
            let id = parts.next().unwrap_or("").to_string();
            let encoded = parts.next().unwrap_or("");
            let bytes = Zeroizing::new(B64.decode(encoded).unwrap_or_default());
            if id.is_empty() || bytes.len() != 32 {
                writeln!(writer, "ERR bad request")?;
                return Ok(false);
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&bytes);
            let mut cache = cache.lock().unwrap();
            cache.reap();
            cache.keys.insert(
                id,
                CachedKey {
                    key,
                    expires: Instant::now() + ttl,
                },
            );
            writeln!(writer, "OK")?;
        }
        "DROP" => {
            let mut cache = cache.lock().unwrap();
            let n = cache.keys.len();
            cache.keys.clear();
            writeln!(writer, "OK dropped {n}")?;
        }
        "STATUS" => {
            let mut cache = cache.lock().unwrap();
            cache.reap();
            writeln!(writer, "OK {} cached", cache.keys.len())?;
        }
        "STOP" => {
            let mut cache = cache.lock().unwrap();
            cache.keys.clear();
            writeln!(writer, "OK stopping")?;
            return Ok(true);
        }
        other => writeln!(writer, "ERR unknown verb {other}")?,
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The protocol identifies vaults by hash, never by path — a leak of the
    /// wire format must not tell an observer where your vaults live.
    #[test]
    fn vault_id_does_not_contain_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("distinctive-name.json");
        std::fs::write(&vault, "{}").unwrap();
        let id = vault_id(&vault);
        assert!(!id.contains("distinctive-name"));
        assert_eq!(id, vault_id(&vault), "must be stable across calls");
    }

    /// A vault reached by two different path spellings is one vault. Without
    /// canonicalisation, `./vault.json` and `/abs/vault.json` would be two
    /// cache entries and the second one would always miss.
    #[test]
    fn vault_id_is_canonical() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("vault.json");
        std::fs::write(&vault, "{}").unwrap();
        let indirect = dir.path().join(".").join("vault.json");
        assert_eq!(vault_id(&vault), vault_id(&indirect));
    }

    /// With no agent running, every client call must degrade quietly. This
    /// is the path taken by every user who never starts an agent at all.
    #[test]
    #[serial_test::serial]
    fn client_calls_are_noops_without_an_agent() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("definitely-not-listening.sock");
        // SAFETY: single-threaded test, and the var is read only by this
        // process's own socket_path().
        unsafe { std::env::set_var("HEARTH_VAULT_AGENT_SOCK", &sock) };

        let vault = dir.path().join("vault.json");
        std::fs::write(&vault, "{}").unwrap();
        assert!(try_get(&vault).is_none());
        assert!(!try_put(&vault, &[7u8; 32]));
        assert!(!is_running());

        unsafe { std::env::remove_var("HEARTH_VAULT_AGENT_SOCK") };
    }

    /// End-to-end: put a key, get it back, drop it, and confirm the drop
    /// actually clears (a DROP that silently kept the key would be the worst
    /// possible failure here — the user believes they locked up and has not).
    #[test]
    #[serial_test::serial]
    fn put_get_drop_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        // SAFETY: set before any thread reads it below.
        unsafe { std::env::set_var("HEARTH_VAULT_AGENT_SOCK", &sock) };

        let server = std::thread::spawn(move || serve(Duration::from_secs(60)));
        for _ in 0..100 {
            if is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let vault = dir.path().join("vault.json");
        std::fs::write(&vault, "{}").unwrap();
        let key = [0xABu8; 32];

        assert!(try_get(&vault).is_none(), "empty agent must miss");
        assert!(try_put(&vault, &key));
        assert_eq!(try_get(&vault).map(|k| *k), Some(key));

        assert!(control("DROP").unwrap().starts_with("OK"));
        assert!(
            try_get(&vault).is_none(),
            "DROP must really clear the cache"
        );

        let _ = control("STOP");
        let _ = server.join();
        unsafe { std::env::remove_var("HEARTH_VAULT_AGENT_SOCK") };
    }

    /// An expired key must miss. A TTL that did not actually expire would
    /// turn "cached for 15 minutes" into "cached until reboot".
    #[test]
    #[serial_test::serial]
    fn keys_expire() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("agent.sock");
        // SAFETY: set before the server thread starts.
        unsafe { std::env::set_var("HEARTH_VAULT_AGENT_SOCK", &sock) };

        let server = std::thread::spawn(move || serve(Duration::from_millis(150)));
        for _ in 0..100 {
            if is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let vault = dir.path().join("vault.json");
        std::fs::write(&vault, "{}").unwrap();
        assert!(try_put(&vault, &[3u8; 32]));
        assert!(try_get(&vault).is_some());
        std::thread::sleep(Duration::from_millis(300));
        assert!(try_get(&vault).is_none(), "key outlived its TTL");

        let _ = control("STOP");
        let _ = server.join();
        unsafe { std::env::remove_var("HEARTH_VAULT_AGENT_SOCK") };
    }

    /// The socket must not be reachable by other users, and neither must the
    /// directory holding it.
    #[test]
    #[serial_test::serial]
    fn socket_and_directory_are_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("nested").join("agent.sock");
        // SAFETY: set before the server thread starts.
        unsafe { std::env::set_var("HEARTH_VAULT_AGENT_SOCK", &sock) };

        let server = std::thread::spawn(move || serve(Duration::from_secs(60)));
        for _ in 0..100 {
            if is_running() {
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }

        let sock_mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        let dir_mode = std::fs::metadata(sock.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(sock_mode, 0o600, "socket must be owner-only");
        assert_eq!(dir_mode, 0o700, "socket directory must be owner-only");

        let _ = control("STOP");
        let _ = server.join();
        unsafe { std::env::remove_var("HEARTH_VAULT_AGENT_SOCK") };
    }
}
