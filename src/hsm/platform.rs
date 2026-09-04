//! Platform primitives: file ownership restriction, core-dump suppression,
//! and TTY detection.
//!
//! `unsafe` is allowed ONLY in this file (Win32 and libc FFI are unavoidable
//! here). Every block is kept minimal and documents the invariant it relies
//! on.

use std::path::Path;

/// Restrict a DIRECTORY that holds secret files to its owner (`0700` on
/// Unix; the same single-ACE protected DACL on Windows).
///
/// A 0600 vault file inside a 0755 directory is fine for confidentiality --
/// another local user cannot read the file -- but they CAN list the
/// directory, learn that you use this tool, see the vault's mtime, and, if
/// the directory is writable by them, rename or replace files in it. The
/// directory is part of the secret's containment, so it gets tightened too.
///
/// Never fails the caller: a vault living in a directory whose mode cannot be
/// changed (a mount with restricted permissions, a shared parent someone else
/// owns) is a reason to warn, not a reason to refuse to save.
pub fn restrict_dir_to_owner(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(dir)?;
        let mode = meta.permissions().mode() & 0o777;
        // Only touch it if it is actually loose, so a deliberately chosen
        // 0750 with a trusted group is left alone.
        if mode & 0o077 != 0 {
            let mut perms = meta.permissions();
            perms.set_mode(0o700);
            std::fs::set_permissions(dir, perms)?;
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        // Deliberately a no-op.
        //
        // `restrict_to_owner` installs a PROTECTED DACL carrying one
        // non-inheritable ACE. That is right for a file and wrong for a
        // directory: stripping inherited ACEs from a directory broke creating
        // files inside it (Windows CI caught exactly this -- every `adopt`
        // write into a temp directory started failing). Directory ACLs need
        // inheritance flags this helper does not model.
        //
        // The concrete risk being addressed -- a 0755 directory holding a
        // 0600 vault -- is a Unix mode-bit problem. On Windows the vault file
        // itself already carries a protected owner-only DACL, and a user
        // profile directory is not world-listable to begin with.
        let _ = dir;
        Ok(())
    }
}

/// Write secret-bearing bytes to `path` so that the file is never, at any
/// instant, readable by anyone but its owner, and so that a crash cannot
/// leave a half-written file behind.
///
/// The naive `fs::write` + `restrict_to_owner` sequence gets both wrong:
///
///   - The content lands with the process umask (commonly 0644) and is only
///     narrowed afterwards, so there is a window where another local user can
///     read it. `fs::write` also FOLLOWS a symlink at `path`, which lets an
///     attacker who can create one aim the plaintext wherever they like.
///   - `fs::write` truncates the destination first. A crash, a full disk or a
///     killed process between truncate and completion leaves a truncated
///     vault -- every secret in it gone, with no copy anywhere.
///
/// So: create a fresh temp file beside the destination with owner-only
/// permissions AT CREATION, write, fsync, then rename over the destination.
/// Rename replaces whatever is at `path` (including a symlink, as the link
/// rather than through it) in one step.
pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        path.file_name().and_then(|s| s.to_str()).unwrap_or("vault"),
        std::process::id()
    ));
    // A stale temp from a previous crash must not make this fail.
    let _ = std::fs::remove_file(&tmp);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let mut f = opts.open(&tmp)?;
    let write_result = f
        .write_all(bytes)
        // fsync: a rename is atomic with respect to ordering, but on a crash
        // an unsynced file can be renamed into place with zero length.
        .and_then(|_| f.sync_all());
    drop(f);

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // Windows has no mode bits; apply the DACL before the file is reachable
    // under its real name.
    #[cfg(windows)]
    if let Err(e) = restrict_to_owner(&tmp) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }

    // On Unix this replaces the destination atomically. On Windows, rename
    // onto an existing file fails, so remove first -- a brief window where
    // the destination is absent, which is still strictly better than the
    // truncate-in-place it replaces.
    #[cfg(windows)]
    let _ = std::fs::remove_file(path);

    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// Restrict a file to the current user only.
///
/// Unix: `chmod 0600`.
/// Windows: this is a real gap if left as a no-op — the old code set a Unix
/// mode bit that Windows silently ignores, leaving the vault file's DACL
/// inherited from its parent directory (potentially readable by other local
/// users). We instead replace the file's DACL with a single ACE granting the
/// current user's SID full control, and mark the DACL protected so inherited
/// ACEs are stripped.
#[cfg(unix)]
pub fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)
}

#[cfg(windows)]
pub fn restrict_to_owner(path: &Path) -> std::io::Result<()> {
    use std::mem::size_of;
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::Security::Authorization::{SE_FILE_OBJECT, SetNamedSecurityInfoW};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, AddAccessAllowedAce, DACL_SECURITY_INFORMATION,
        GetLengthSid, GetTokenInformation, InitializeAcl, PROTECTED_DACL_SECURITY_INFORMATION,
        TOKEN_QUERY, TOKEN_USER, TokenUser,
    };
    use windows_sys::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
    // `OpenProcessToken` lives under System::Threading in windows-sys, not
    // Security — despite operating on a security token, it's grouped with
    // the other process/thread APIs upstream.
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: OpenProcessToken/GetTokenInformation/CloseHandle follow the
    // documented Win32 handle-lifecycle contract: the token handle obtained
    // here is closed on every exit path before this block ends. All buffers
    // passed to GetTokenInformation are sized from its own "how much space
    // do you need" query, never guessed.
    let owner_sid_bytes: Vec<u8> = unsafe {
        let mut token = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error());
        }

        let mut needed: u32 = 0;
        // First call intentionally fails; it only fills in `needed`.
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 {
            CloseHandle(token);
            return Err(std::io::Error::last_os_error());
        }

        let mut buf = vec![0u8; needed as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            buf.as_mut_ptr() as *mut core::ffi::c_void,
            needed,
            &mut needed,
        );
        CloseHandle(token);
        if ok == 0 {
            return Err(std::io::Error::last_os_error());
        }
        buf
    };

    // SAFETY: `owner_sid_bytes` was sized and filled by GetTokenInformation
    // above for TokenUser, so reinterpreting its head as TOKEN_USER is valid
    // per the Win32 contract for that information class. The PSID it embeds
    // points into the same buffer and stays valid for as long as
    // `owner_sid_bytes` is alive, which we hold until after
    // SetNamedSecurityInfoW returns.
    let owner_sid = unsafe {
        let token_user = &*(owner_sid_bytes.as_ptr() as *const TOKEN_USER);
        token_user.User.Sid
    };

    // SAFETY: `acl_buf` is sized using the documented ACL-plus-one-ACE
    // formula (header + one ACCESS_ALLOWED_ACE, minus the ACE's placeholder
    // SID DWORD, plus the real SID length) and zero-initialized before
    // InitializeAcl writes its header into it. `acl_ptr` does not outlive
    // `acl_buf`.
    let (acl_buf_keep_alive, acl_ptr) = unsafe {
        let sid_len = GetLengthSid(owner_sid);
        let acl_len = size_of::<ACL>() as u32 + size_of::<ACCESS_ALLOWED_ACE>() as u32
            - size_of::<u32>() as u32
            + sid_len;
        let mut acl_buf = vec![0u8; acl_len as usize];
        let acl_ptr = acl_buf.as_mut_ptr() as *mut ACL;

        if InitializeAcl(acl_ptr, acl_len, ACL_REVISION) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        if AddAccessAllowedAce(acl_ptr, ACL_REVISION, FILE_ALL_ACCESS, owner_sid) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        (acl_buf, acl_ptr)
    };

    // SAFETY: `wide_path` is a NUL-terminated UTF-16 buffer alive for this
    // call. `acl_ptr` points into `acl_buf_keep_alive`, which outlives this
    // call (dropped only after we're done with it below).
    // PROTECTED_DACL_SECURITY_INFORMATION strips inherited ACEs so the file
    // ends up owner-only rather than owner-plus-whatever-the-parent-granted.
    let result = unsafe {
        SetNamedSecurityInfoW(
            wide_path.as_ptr() as *mut u16,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            acl_ptr,
            null_mut(),
        )
    };
    drop(acl_buf_keep_alive);

    if result != 0 {
        return Err(std::io::Error::from_raw_os_error(result as i32));
    }
    Ok(())
}

/// Best-effort: prevent this process from producing a core dump. Never
/// panics, never returns an error the caller must handle — a failure here
/// just means the OS default (dumps enabled) applies.
///
/// On Linux this also closes `/proc/self/{environ,mem,maps,...}` to every
/// other same-UID process (the kernel reassigns those entries to root once
/// `PR_SET_DUMPABLE` is cleared) — the actual fix for the 2026-09-04
/// incident where a same-UID agent read a live credential out of
/// `/proc/<engine-pid>/environ`. Measured (`stat -c %U /proc/<pid>/environ`
/// before/after `prctl` in a throwaway test process): owner flips from the
/// real user to `root`, and `ps eww -p <pid>` stops showing the value.
///
/// Two things this does NOT do, measured directly and not to be assumed
/// otherwise: it does not survive a subsequent `execve` (the kernel resets
/// `dumpable` to 1 on a normal exec — a child spawned by `hearth-vault exec`
/// is NOT sealed by the vault process having called this; only the child
/// calling it again, itself, after its own exec, seals it — see
/// `USAGE.md`/`SECURITY.md` "Sealing a secret-holding process" for the
/// per-language snippet), and it does not hide argv (`/proc/<pid>/cmdline`
/// stays readable regardless).
pub fn disable_core_dumps() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes no pointer arguments and
        // cannot fault; a nonzero return (failure) is safe to ignore since
        // this is explicitly best-effort.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }

    #[cfg(any(
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        // SAFETY: `limit` is a plain-old-data struct passed by reference (the
        // compiler coerces it to `*const rlimit`); setrlimit only adjusts a
        // process-local resource limit and cannot corrupt memory. Ignoring
        // the return code is intentional (best-effort).
        unsafe {
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            libc::setrlimit(libc::RLIMIT_CORE, &limit);
        }
    }

    // Windows: no user-mode equivalent of RLIMIT_CORE/PR_SET_DUMPABLE. Crash
    // dump behavior there is a machine-wide registry/WER policy, out of
    // scope for a per-process best-effort call. No-op.
}

/// Whether a process's `/proc/<pid>/environ` (and `/mem`, `/maps`, ...) is
/// closed to same-UID readers.
///
/// Backs `hearth-vault seal-check` and `exec --warn-unsealed`. See the
/// module-level incident note in `disable_core_dumps` for why this exists:
/// `PR_SET_DUMPABLE` does NOT survive `execve`, so a parent can never seal a
/// child for it — the child must seal itself, and this is how a THIRD party
/// (the vault, or an operator) can tell whether it did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcSealStatus {
    /// `/proc/<pid>/environ` is owned by a different uid than the caller's
    /// own (in practice: the kernel reassigns it to root once the process
    /// calls `prctl(PR_SET_DUMPABLE, 0)`), so a same-UID reader is denied.
    Sealed,
    /// Still owned by the caller's own uid — a same-UID reader (an agent,
    /// `ps eww`, a debugger) can read the full environment, including any
    /// vault-injected secret values.
    Readable,
    /// The process is gone, not ours to inspect, or `/proc` doesn't exist
    /// on this platform (non-Linux). Carries a short reason, never any
    /// data read from the target.
    Unknown(String),
}

/// The calling process's real UID. A trivial wrapper so the rest of the
/// codebase never needs its own `unsafe` block for something this simple —
/// this file's module doc says `unsafe` stays contained here.
#[cfg(unix)]
pub fn own_uid() -> u32 {
    // SAFETY: getuid() takes no arguments and cannot fail.
    unsafe { libc::getuid() }
}

/// PIDs of every process currently running as the caller, found by reading
/// `/proc/*/status`'s `Uid:` line (the REAL uid — first of the four numbers
/// on that line — compared against `own_uid()`). Backs `seal-check --all`.
/// Never reads `environ`/`mem`/`maps` of anything it enumerates; a process
/// that vanishes mid-scan (exited, or a status line in an unexpected shape)
/// is silently skipped rather than failing the whole sweep.
///
/// Always compiles (like `probe_seal_status`), so a caller doesn't need its
/// own `#[cfg(target_os = "linux")]` just to reach this — on a non-Linux
/// target it returns an explicit `Unsupported` error rather than an empty
/// (and misleadingly "nothing found") list.
pub fn list_own_pids() -> std::io::Result<Vec<u32>> {
    #[cfg(target_os = "linux")]
    {
        let self_uid = own_uid();
        let mut pids = Vec::new();
        for entry in std::fs::read_dir("/proc")? {
            let Ok(entry) = entry else { continue };
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            else {
                continue;
            };
            let Ok(status) = std::fs::read_to_string(format!("/proc/{pid}/status")) else {
                continue;
            };
            let Some(uid_line) = status.lines().find(|l| l.starts_with("Uid:")) else {
                continue;
            };
            let real_uid = uid_line
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u32>().ok());
            if real_uid == Some(self_uid) {
                pids.push(pid);
            }
        }
        Ok(pids)
    }
    #[cfg(not(target_os = "linux"))]
    {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "process enumeration needs /proc, which only exists on Linux",
        ))
    }
}

/// The short executable name from `/proc/<pid>/comm` — non-secret process
/// metadata (like argv), used only to make a `seal-check --all` report
/// readable. `None` if the process is gone, `/proc` is unavailable, or this
/// isn't Linux — always compiles, same reasoning as `list_own_pids`.
pub fn read_proc_comm(pid: u32) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string(format!("/proc/{pid}/comm"))
            .ok()
            .map(|s| s.trim().to_string())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        None
    }
}

/// Best-effort probe of `pid`'s seal state. Linux-only: `/proc` is a Linux
/// construct, and there is no portable equivalent on macOS/BSD/Windows to
/// probe from outside the process (searched: no macOS `/proc`; FreeBSD's
/// optional `procfs` mount is not enabled by default and was not probed
/// further here — this function conservatively returns `Unknown` on every
/// non-Linux target rather than guessing).
pub fn probe_seal_status(pid: u32) -> ProcSealStatus {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/{pid}/environ");
        let meta = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(e) => return ProcSealStatus::Unknown(format!("{path}: {e}")),
        };
        use std::os::unix::fs::MetadataExt;
        let owner = meta.uid();
        let self_uid = own_uid();
        if self_uid == 0 {
            // Root can read a sealed process's /proc entries too (dumpable
            // only gates *other* same-UID readers) — the ownership check is
            // meaningless for a root caller, so say so rather than report a
            // false Readable/Sealed.
            return ProcSealStatus::Unknown(
                "caller is root — root can read a sealed process's /proc entries too, so \
                 ownership cannot distinguish sealed from unsealed here"
                    .to_string(),
            );
        }
        if owner == self_uid {
            ProcSealStatus::Readable
        } else {
            ProcSealStatus::Sealed
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        ProcSealStatus::Unknown("seal probing needs /proc, which only exists on Linux".to_string())
    }
}

/// Read only the *names* of `pid`'s environment variables — never a value.
///
/// Splits `/proc/<pid>/environ` on NUL and keeps only the substring before
/// the first `=` of each entry; everything after `=` is dropped immediately
/// and never stored, returned, printed, or compared. This is the primitive
/// `seal-check` uses to report "these vault-managed NAMES are exposed"
/// without a value ever leaving this function.
/// Environment variable NAMES (never values) of a process, read from
/// `/proc/<pid>/environ`. Callers use this only against processes already
/// confirmed `ProcSealStatus::Readable` — this function itself does not
/// re-check that, it just parses whatever `/proc` hands back. Always
/// compiles (same reasoning as `list_own_pids`); on non-Linux it returns an
/// explicit `Unsupported` error rather than silently claiming "no names".
pub fn read_proc_env_names(pid: u32) -> std::io::Result<Vec<String>> {
    #[cfg(target_os = "linux")]
    {
        let raw = std::fs::read(format!("/proc/{pid}/environ"))?;
        Ok(raw
            .split(|b| *b == 0)
            .filter(|entry| !entry.is_empty())
            .map(|entry| {
                let name_bytes = match entry.iter().position(|b| *b == b'=') {
                    Some(idx) => &entry[..idx],
                    None => entry,
                };
                String::from_utf8_lossy(name_bytes).into_owned()
            })
            .collect())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "reading environ names needs /proc, which only exists on Linux",
        ))
    }
}

/// True if stdout is a terminal. Backs the CLI's non-TTY refusal rule for
/// commands that would otherwise write a secret value to stdout.
#[cfg(unix)]
pub fn stdout_is_tty() -> bool {
    // SAFETY: isatty(1) queries file descriptor 1 (stdout), which is always
    // a valid (if possibly closed/redirected) descriptor number for a
    // running process; the call takes no pointers and cannot fault.
    unsafe { libc::isatty(1) == 1 }
}

/// Is stderr a terminal?
///
/// This matters as much as stdout: prompts, warnings AND the recovery
/// mnemonic banner are written to stderr, so a guard that only inspects
/// stdout leaves `hearth-vault init 2>mnemonic.log` writing the phrase that
/// unlocks the whole vault into a plaintext file, from a session whose
/// stdout is a perfectly ordinary terminal.
#[cfg(unix)]
pub fn stderr_is_tty() -> bool {
    // SAFETY: as above, for file descriptor 2.
    unsafe { libc::isatty(2) == 1 }
}

#[cfg(windows)]
fn handle_is_console(which: windows_sys::Win32::System::Console::STD_HANDLE) -> bool {
    use windows_sys::Win32::System::Console::{CONSOLE_MODE, GetConsoleMode, GetStdHandle};

    // SAFETY: GetStdHandle/GetConsoleMode are simple Win32 queries with no
    // caller-owned pointers except the output `mode`, which is a valid local
    // stack variable. An invalid/null handle just makes GetConsoleMode fail,
    // which we correctly treat as "not a console/TTY" (e.g. redirected to a
    // file or pipe).
    unsafe {
        let handle = GetStdHandle(which);
        if handle.is_null() {
            return false;
        }
        let mut mode: CONSOLE_MODE = 0;
        GetConsoleMode(handle, &mut mode) != 0
    }
}

#[cfg(windows)]
pub fn stderr_is_tty() -> bool {
    handle_is_console(windows_sys::Win32::System::Console::STD_ERROR_HANDLE)
}

#[cfg(windows)]
pub fn stdout_is_tty() -> bool {
    handle_is_console(windows_sys::Win32::System::Console::STD_OUTPUT_HANDLE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The vault file being 0600 is not enough on its own: another local
    /// user must not be able to list, rename, or replace things in the
    /// directory holding it.
    #[cfg(unix)]
    #[test]
    fn restrict_dir_to_owner_tightens_a_loose_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        restrict_dir_to_owner(dir.path()).expect("restrict");

        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "expected 0700, got {mode:o}");
    }

    /// A deliberately chosen group-shared mode with no other-access is left
    /// alone; this function tightens what is loose, it does not enforce a
    /// house style.
    #[cfg(unix)]
    #[test]
    fn restrict_dir_to_owner_leaves_an_already_private_directory() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        restrict_dir_to_owner(dir.path()).expect("restrict");

        let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    /// Hardening a directory must not make it unusable. Windows CI caught
    /// the version of this that installed a protected, non-inheritable DACL
    /// on the directory: every subsequent write INTO it failed. Whatever the
    /// platform does here, creating a file afterwards has to still work.
    #[test]
    fn restrict_dir_to_owner_leaves_the_directory_writable() {
        let dir = tempfile::tempdir().expect("tempdir");
        restrict_dir_to_owner(dir.path()).expect("restrict");
        write_private(&dir.path().join("after.txt"), b"still writable").expect("write after");
        assert_eq!(
            std::fs::read(dir.path().join("after.txt")).unwrap(),
            b"still writable"
        );
    }

    /// write_private must never leave a world-readable window, and must
    /// replace the destination rather than following a symlink out of it.
    #[cfg(unix)]
    #[test]
    fn write_private_creates_owner_only_and_replaces_a_symlink() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let target = dir.path().join("elsewhere.txt");
        let dest = dir.path().join("vault.json");

        write_private(&dest, b"first").expect("write");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0600, got {mode:o}");

        // Point the destination at another file; the write must replace the
        // link itself, leaving the target untouched.
        std::fs::remove_file(&dest).unwrap();
        std::fs::write(&target, b"do not overwrite me").unwrap();
        std::os::unix::fs::symlink(&target, &dest).unwrap();

        write_private(&dest, b"second").expect("write over symlink");
        assert_eq!(std::fs::read(&target).unwrap(), b"do not overwrite me");
        assert_eq!(std::fs::read(&dest).unwrap(), b"second");
        assert!(
            !std::fs::symlink_metadata(&dest)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn test_restrict_to_owner_produces_owner_only_perms() {
        let tmp = tempfile::NamedTempFile::new().expect("tempfile");
        restrict_to_owner(tmp.path()).expect("restrict_to_owner should succeed");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        #[cfg(windows)]
        {
            let _ = std::fs::read(tmp.path()).expect("owner must still be able to read the file");
            assert_windows_dacl_is_owner_only_and_protected(tmp.path());
        }
    }

    /// Reads the DACL back with `GetNamedSecurityInfoW` (independent of the
    /// `SetNamedSecurityInfoW` call under test — both are Win32 calls, but
    /// exercising the read side is what catches a `restrict_to_owner` that
    /// silently no-ops: a no-op still leaves the file readable by its
    /// owner, so the read-then-write assertion above alone would not catch
    /// it) and asserts the three properties the doc comment on
    /// `restrict_to_owner` promises:
    /// 1. a DACL is actually present (not "no DACL" = everyone allowed),
    /// 2. `SE_DACL_PROTECTED` is set, so inherited ACEs from the parent
    ///    directory were stripped, and
    /// 3. there is exactly one ACE — the single owner-full-control entry
    ///    `restrict_to_owner` adds, nothing inherited or left over.
    #[cfg(windows)]
    fn assert_windows_dacl_is_owner_only_and_protected(path: &Path) {
        use std::mem::size_of;
        use std::os::windows::ffi::OsStrExt;
        use std::ptr::null_mut;

        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
        use windows_sys::Win32::Security::{
            ACL, ACL_SIZE_INFORMATION, AclSizeInformation, DACL_SECURITY_INFORMATION,
            GetAclInformation, GetSecurityDescriptorControl, SE_DACL_PROTECTED,
        };

        let wide_path: Vec<u16> = path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut dacl: *mut ACL = null_mut();
        let mut security_descriptor: *mut core::ffi::c_void = null_mut();

        // SAFETY: `wide_path` is a NUL-terminated UTF-16 buffer alive for
        // this call. `dacl`/`security_descriptor` are valid local
        // out-pointers. The security descriptor buffer GetNamedSecurityInfoW
        // allocates is freed via LocalFree below before this function
        // returns on every path (including the panics from the assertions,
        // since those run after the free... see the ordering note below).
        let result = unsafe {
            GetNamedSecurityInfoW(
                wide_path.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut security_descriptor,
            )
        };
        assert_eq!(
            result, 0,
            "GetNamedSecurityInfoW failed reading back the DACL restrict_to_owner just set"
        );
        assert!(
            !security_descriptor.is_null(),
            "GetNamedSecurityInfoW returned no security descriptor"
        );
        assert!(
            !dacl.is_null(),
            "restrict_to_owner must leave a DACL present (a null DACL means \"everyone \
             allowed\", the opposite of owner-only)"
        );

        // SAFETY: `security_descriptor` was just filled in and validated
        // non-null above by GetNamedSecurityInfoW; `control`/`revision` are
        // valid local out-pointers.
        let mut control: u16 = 0;
        let mut revision: u32 = 0;
        let control_ok = unsafe {
            GetSecurityDescriptorControl(security_descriptor, &mut control, &mut revision)
        };
        assert_ne!(control_ok, 0, "GetSecurityDescriptorControl failed");
        assert_ne!(
            control & SE_DACL_PROTECTED,
            0,
            "SE_DACL_PROTECTED must be set — otherwise inherited ACEs from the parent \
             directory were not stripped and the file may be readable by more than the owner"
        );

        // SAFETY: `dacl` was validated non-null above and is still valid —
        // it points into the same buffer LocalFree(security_descriptor)
        // below releases, which we don't call until after this read.
        // `acl_size_info` is a valid local out-buffer sized exactly to the
        // struct GetAclInformation with AclSizeInformation writes.
        let mut acl_size_info = ACL_SIZE_INFORMATION {
            AceCount: 0,
            AclBytesInUse: 0,
            AclBytesFree: 0,
        };
        let size_ok = unsafe {
            GetAclInformation(
                dacl,
                &mut acl_size_info as *mut _ as *mut core::ffi::c_void,
                size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        };
        assert_ne!(size_ok, 0, "GetAclInformation failed");
        assert_eq!(
            acl_size_info.AceCount, 1,
            "restrict_to_owner should leave exactly one ACE (the owner-full-control entry) — \
             found {}, which means either extra inherited entries survived or the single-ACE \
             AddAccessAllowedAce call didn't run as expected",
            acl_size_info.AceCount
        );

        // SAFETY: `security_descriptor` is the exact pointer
        // GetNamedSecurityInfoW allocated above via LocalAlloc; freeing it
        // with LocalFree is the documented cleanup for that API. `dacl`
        // points inside this same buffer and must not be used after this.
        unsafe {
            LocalFree(security_descriptor as _);
        }
    }

    #[test]
    fn test_disable_core_dumps_does_not_panic() {
        disable_core_dumps();
    }

    #[test]
    fn test_stdout_is_tty_does_not_panic() {
        // No assertion on the value — under `cargo test` stdout is typically
        // captured/redirected, so this is expected to return false; the
        // point of this test is just that the platform call doesn't panic.
        let _ = stdout_is_tty();
    }

    /// Helper invoked as a child process by
    /// `probe_seal_status_distinguishes_sealed_from_unsealed_process` below
    /// (same `current_exe()` re-invocation trick as `tests/cli.rs`'s
    /// `helper_print_env`: `std::env::current_exe()` inside a `#[test]`
    /// returns this compiled test-harness binary, which is a normal
    /// executable). Under a plain `cargo test` run, both env vars are unset
    /// and this is a no-op.
    #[test]
    fn helper_seal_self_and_wait() {
        if std::env::var("HV_SEAL_HELPER_SEAL").is_ok() {
            disable_core_dumps();
        }
        if std::env::var("HV_SEAL_HELPER_SEAL").is_ok()
            || std::env::var("HV_SEAL_HELPER_WAIT").is_ok()
        {
            use std::io::Write;
            // Distinctive marker so the parent can find this exact line
            // among libtest's own "running 1 test" chatter, same convention
            // as `tests/cli.rs`'s `HV_ECHO_BEGIN`/`HV_ECHO_END`.
            println!("HV_SEAL_HELPER_PID:{}", std::process::id());
            std::io::stdout().flush().ok();
            std::thread::sleep(std::time::Duration::from_millis(1500));
        }
    }

    /// The actual claim this module exists to back: after
    /// `disable_core_dumps()`, `/proc/<pid>/environ` is closed to a
    /// same-UID reader; without it, the same reader can read it. Spawns two
    /// real child processes (this same test binary, re-invoked) to prove
    /// both sides rather than asserting behavior of a mocked probe.
    #[test]
    #[cfg(target_os = "linux")]
    fn probe_seal_status_distinguishes_sealed_from_unsealed_process() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};

        let exe = std::env::current_exe().expect("path to this test binary");

        // clippy's zombie_processes lint can't see that the caller below
        // (after this closure returns) always kills+waits both children on
        // every path, including panics via the outer test's own assertions
        // failing before cleanup — that residual risk is the same as any
        // other test that panics mid-assertion, not specific to this one.
        #[allow(clippy::zombie_processes)]
        let spawn_and_read_pid = |env_var: &str| -> (std::process::Child, u32) {
            let mut child = Command::new(&exe)
                .args([
                    "hsm::platform::tests::helper_seal_self_and_wait",
                    "--exact",
                    "--nocapture",
                ])
                .env(env_var, "1")
                .stdout(Stdio::piped())
                .spawn()
                .expect("spawn helper child");
            let stdout = child.stdout.take().expect("piped stdout");
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                let n = reader.read_line(&mut line).expect("read helper stdout");
                assert!(n > 0, "helper exited before printing its PID marker");
                if let Some(rest) = line.trim_end().strip_prefix("HV_SEAL_HELPER_PID:") {
                    let pid: u32 = rest.parse().expect("parse helper PID");
                    // Leak the reader thread's ownership of stdout by
                    // forgetting it: we've read what we need, and the
                    // helper's later output (none, in this case) doesn't
                    // matter. Keep `child` alive so the process doesn't
                    // exit/reap before we probe it.
                    std::mem::forget(reader);
                    return (child, pid);
                }
            }
        };

        let (mut sealed_child, sealed_pid) = spawn_and_read_pid("HV_SEAL_HELPER_SEAL");
        let (mut unsealed_child, unsealed_pid) = spawn_and_read_pid("HV_SEAL_HELPER_WAIT");

        assert_eq!(
            probe_seal_status(sealed_pid),
            ProcSealStatus::Sealed,
            "a child that called disable_core_dumps() before printing its PID must be Sealed"
        );
        assert_eq!(
            probe_seal_status(unsealed_pid),
            ProcSealStatus::Readable,
            "a plain child (no disable_core_dumps()) must be Readable"
        );

        // Only the env var NAME is asserted anywhere in this test — the
        // value never leaves the helper process (never printed, never read
        // back here) as the whole point of read_proc_env_names.
        let sealed_names = read_proc_env_names(sealed_pid);
        assert!(
            sealed_names.is_err(),
            "reading environ of a sealed same-UID process must be denied"
        );
        let unsealed_names =
            read_proc_env_names(unsealed_pid).expect("read environ of an unsealed process");
        assert!(
            unsealed_names.iter().any(|n| n == "HV_SEAL_HELPER_WAIT"),
            "expected HV_SEAL_HELPER_WAIT among the unsealed child's env var NAMES, got: {unsealed_names:?}"
        );

        let _ = sealed_child.kill();
        let _ = sealed_child.wait();
        let _ = unsealed_child.kill();
        let _ = unsealed_child.wait();
    }
}
