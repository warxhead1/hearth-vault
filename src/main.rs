//! hearth-vault: a secrets vault built so a coding agent can use your API
//! keys without ever seeing them.
//!
//! Values are stored encrypted (AES-256-GCM, Argon2id-derived keys) in a
//! single vault file. The default vault lives in the platform data
//! directory; see `--vault-path` / `HEARTH_VAULT_HOME` below to override.

use std::fs;
use std::io::{BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use hearth_vault::hsm::platform;
use hearth_vault::{SensitiveString, TIER_SIGN_ONLY, TIER_USE_ONLY, VaultStore};
use zeroize::Zeroize;

#[derive(Parser)]
#[command(
    name = "hearth-vault",
    // `--version` is how a user (or a release smoke test) confirms WHICH
    // build they are holding — which matters more than usual for a tool
    // whose releases are unsigned and verified by checksum.
    version,
    about = "A secrets vault built so a coding agent can use your API keys without ever seeing them."
)]
struct Cli {
    /// Explicit vault file path. Highest-priority override — beats
    /// $HEARTH_VAULT_HOME and the platform default directory.
    #[arg(long, global = true, value_name = "PATH")]
    vault_path: Option<PathBuf>,

    /// Secret backend to use for auto-unseal / seal instead of
    /// auto-detection: tpm2, keyring, or software.
    #[arg(long, global = true, value_name = "BACKEND")]
    backend: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Store one or more credentials (prompts for each value with hidden input).
    /// Example: hearth-vault set myapp/api_key myapp/db_password
    Set {
        /// Key name(s) (e.g., "myapp/api_key", "myapp/db_password")
        keys: Vec<String>,
        /// Security tier: 1/2 = exportable (printable to stdout or a file),
        /// 3 = use-only, never printed but usable via `exec` (default),
        /// 4 = sign-only, never printed and never injected — `sign` only
        #[arg(short, long, default_value_t = TIER_USE_ONLY)]
        tier: u8,
    },
    /// Import a single credential from a file (for browser-automation
    /// handoff, or piping a generated key straight in).
    Import {
        /// Path to a temp file containing the credential value
        file: String,
        /// Key name to store as
        #[arg(short, long)]
        key: String,
        /// Security tier: 1/2 = exportable (printable to stdout or a file),
        /// 3 = use-only, never printed but usable via `exec` (default),
        /// 4 = sign-only, never printed and never injected — `sign` only
        #[arg(short, long, default_value_t = TIER_USE_ONLY)]
        tier: u8,
    },
    /// Bulk-import a dotenv file: one vault key per line, then (by default)
    /// delete the file and print the `exec` command that replaces it.
    ///
    /// Parses `KEY=value`, `export KEY=value`, single- and double-quoted
    /// values, `#` comments, and blank lines. Every pair is stored at
    /// `<prefix><KEY>`; imported values default to tier 3 (use-only) — pass
    /// `--tier 2` if you actually need to export them back out later.
    ///
    /// Example: hearth-vault import-env .env --prefix myapp/
    ImportEnv {
        /// Path to the dotenv file (default: ./.env)
        file: Option<String>,
        /// Prefix every stored key with this string (e.g. "myapp/")
        #[arg(long)]
        prefix: Option<String>,
        /// Security tier for every imported key (default: 3, use-only —
        /// never printed, but usable via `exec`)
        #[arg(long, default_value_t = TIER_USE_ONLY)]
        tier: u8,
        /// Do not delete the source file after import
        #[arg(long)]
        keep: bool,
        /// Overwrite vault keys that already exist
        #[arg(long)]
        force: bool,
    },
    /// Move a legacy `~/.hearth/vault.json` (v1 format) into the platform
    /// data directory in the current v2 on-disk format.
    Migrate,
    /// List all stored credential keys (never shows values)
    List,
    /// Check if a credential exists
    Has { key: String },
    /// Delete a credential
    Delete { key: String },
    /// Rename (move) a credential to a new key name.
    /// Example: hearth-vault rename GITHUB_TOKEN auth/GITHUB_TOKEN
    Rename { from: String, to: String },
    /// Change the security tier of an existing credential in place.
    ///
    /// Tier semantics:
    ///   1 = keyring (low sensitivity, exportable)
    ///   2 = software-vault (exportable)
    ///   3 = use-only (default for new secrets) — `export-env` and
    ///       `export-env-file` REFUSE to export the value. `sign`,
    ///       `github-app-token`, and `exec` still work, because they use
    ///       the value inside the vault process (or a child's environment)
    ///       and never print it to a stream the caller reads directly.
    ///
    /// Example: hearth-vault retier myapp/signing-key --tier 3
    Retier {
        /// Key name to retier
        key: String,
        /// New tier (1, 2, or 3)
        #[arg(short, long)]
        tier: u8,
    },
    /// Print a credential as a shell `export` line (masked to stderr, real
    /// value to stdout). Refused for tier-3 keys and for non-TTY stdout —
    /// see `hearth-vault exec` for the agent-safe equivalent.
    ExportEnv {
        key: String,
        /// Environment variable name
        #[arg(short, long)]
        env_name: String,
    },
    /// Initialize the vault (first-time setup)
    Init,
    /// Show vault status (backend type, path, permissions)
    Status,
    /// Recover vault access using your 24-word recovery mnemonic. Also
    /// rotates the recovery key, since the old one was just used/entered.
    Recover,
    /// Change the vault passphrase (requires current passphrase or recovery
    /// key). The recovery mnemonic is unaffected — it wraps the same data
    /// key independently of the passphrase.
    ChangePassphrase,
    /// Generate a fresh 24-word recovery mnemonic, replacing any existing one.
    ///
    /// Needed after `migrate`: a v1 vault's recovery phrase came from a
    /// checksumless word list that v2 cannot represent, so migration drops it
    /// and leaves the vault with no recovery path until you run this.
    ///
    /// The new phrase is printed once and never again. Requires the current
    /// passphrase.
    NewRecoveryKey,
    /// Print the vault passphrase for session caching
    /// (use with: export HEARTH_VAULT_PASSPHRASE=$(hearth-vault prompt))
    Prompt,
    /// Seal the vault passphrase to a hardware-backed secret backend
    /// (TPM2 or OS keyring) for auto-unseal on this machine — no
    /// passphrase needed on subsequent runs here.
    Seal,
    /// Export matching vault keys to an env file (KEY=value per line, owner-only
    /// perms). Designed for systemd ExecStartPre injection.
    /// Example: hearth-vault export-env-file --prefix myapp/ --output /run/myapp/env
    ExportEnvFile {
        /// Only include keys starting with this prefix (e.g. "myapp/")
        #[arg(short, long)]
        prefix: String,
        /// Output file path (parent dirs created if needed, owner-only perms)
        #[arg(short, long)]
        output: String,
    },
    /// Run a command with vault secrets injected into its environment —
    /// never materializing a value on stdout or disk. This is the
    /// agent-safe consumption path and the only value-bearing command that
    /// is NOT subject to the non-TTY refusal, because the value goes
    /// straight into a child process's environment, never a stream the
    /// caller (human or agent) reads.
    ///
    /// Every tier-<3 key under `--prefix` is resolved to an env var (same
    /// name mapping as export-env-file: strip prefix, uppercase, `/` and
    /// `-` → `_`) and added to the child's environment; then the command is
    /// exec'd. Tier-3 (use-only) keys are skipped — use `sign` for those.
    ///
    /// Example:
    ///   hearth-vault exec --prefix myapp/ -- ./start-server --port 8080
    Exec {
        /// Inject keys starting with this prefix (e.g. "myapp/")
        #[arg(short, long)]
        prefix: String,
        /// Command and arguments to run (everything after `--`)
        #[arg(last = true, required = true)]
        command: Vec<String>,
    },
    /// Mint a GitHub App installation access token without ever exposing
    /// the App private key.
    ///
    /// Reads `auth/GITHUB_APP_APP_ID` and `auth/GITHUB_APP_PRIVATE_KEY` from
    /// the vault, builds + signs an RS256 JWT internally, and exchanges it
    /// at `POST /app/installations/<id>/access_tokens`. The private key is
    /// loaded into vault-process memory only for the signing operation;
    /// nothing it derives leaks except the (short-lived) installation token.
    /// This is the flagship demo of "use a key you can never see": the App
    /// private key never leaves the vault process, ever.
    ///
    /// Output: just the installation token on stdout (a 40-byte string
    /// starting with `ghs_`). Use --json to also emit the expiry timestamp.
    /// Tokens last 1 hour; callers should refresh before expiry.
    ///
    /// Example: hearth-vault github-app-token --installation-id 123456789
    /// Example (scoped): hearth-vault github-app-token --installation-id 123456789 --repository myapp --repository myapp-infra
    GithubAppToken {
        /// GitHub App installation ID. If omitted, falls back to the
        /// `auth/GITHUB_APP_INSTALLATION_ID` vault entry.
        #[arg(long)]
        installation_id: Option<i64>,
        /// Output JSON with token + expires_at instead of just the token.
        #[arg(long)]
        json: bool,
        /// Restrict the minted token to a specific repository (repeatable).
        /// Pass simple repo names (`myapp`, not `owner/myapp`) — GitHub
        /// scopes by name within the installation. When omitted, the token
        /// inherits the App installation's full repo access (backward compat).
        ///
        /// Without this flag a caller minting a token for one repo can push
        /// to every repo the App is installed on; pass `--repository <name>`
        /// to narrow the blast radius.
        #[arg(long = "repository")]
        repository: Vec<String>,
    },
    /// Cryptographically sign a message using a private key stored in the vault.
    /// The private key never leaves the vault process. Outputs base64-encoded
    /// signature to stdout.
    ///
    /// Algorithms (case-insensitive):
    ///   RSA-PSS-SHA256   RSASSA-PSS with SHA-256 (e.g. Coinbase, many
    ///                    request-signing APIs)
    ///   RS256            RSASSA-PKCS1-v1_5 with SHA-256 (GitHub App JWT)
    ///   RS512            RSASSA-PKCS1-v1_5 with SHA-512 (GitHub App JWT,
    ///                    alternative; also what Go's jwt-go
    ///                    SigningMethodRS512 produces)
    ///
    /// Output: base64-encoded signature on stdout. For RS256/RS512 the
    /// encoding is the standard JWT base64url-without-padding so the caller
    /// can directly concatenate `header.payload.signature`.
    ///
    /// Example: hearth-vault sign --key myapp/signing-key --algorithm RSA-PSS-SHA256 --message "GET\n/v1/orders\n1711234567890"
    /// Example: hearth-vault sign --key auth/GITHUB_APP_PRIVATE_KEY --algorithm RS256 --message "<jwt-header.jwt-payload>"
    Sign {
        /// Vault key path for the PEM-encoded private key
        #[arg(short, long)]
        key: String,
        /// Signing algorithm: RSA-PSS-SHA256 | RS256 | RS512
        #[arg(short, long)]
        algorithm: String,
        /// Message to sign (\n is interpreted as literal newline)
        #[arg(short, long)]
        message: String,
    },
    /// Scan a directory (or file) for gitleaks-style secret-shaped strings
    /// lying around unencrypted, so they can be migrated into the vault.
    ///
    /// Every finding is redacted — this command never prints a usable
    /// secret, which is why it is exempt from the non-TTY refusal rule that
    /// governs `export-env`, `sign`, and friends (see `refuse_if_non_tty`'s
    /// doc comment). Do not "fix" that by adding a refusal here.
    ///
    /// Exit code is 1 if any findings were reported (so this doubles as a
    /// CI/pre-commit gate), 0 if the scan came back clean.
    ///
    /// Example: hearth-vault scan .
    /// Example: hearth-vault scan . --adopt --prefix myapp/
    Scan {
        /// Directory or file to scan (default: current directory)
        path: Option<String>,
        /// Emit findings as JSON instead of a human-readable report
        #[arg(long)]
        json: bool,
        /// Migrate findings into the vault: for `.env`-style files, store
        /// the value and comment out the source line; for source code,
        /// report only (never rewritten — too dangerous to do
        /// automatically).
        #[arg(long)]
        adopt: bool,
        /// Prefix to store adopted keys under (e.g. "myapp/"). Also written
        /// to a `.hearth-vault` project marker file at the scan root so
        /// `hearth-vault project-prefix` / `shell-init`'s `hv` wrapper can
        /// find it later.
        #[arg(long)]
        prefix: Option<String>,
        /// List the built-in rule table and exit without scanning anything
        #[arg(long)]
        rules: bool,
        /// Overwrite a vault key that already exists (only meaningful with
        /// --adopt)
        #[arg(long)]
        force: bool,
    },
    /// Print a shell snippet to eval from your rc file
    /// (`eval "$(hearth-vault shell-init zsh)"`). Defines an `hv` wrapper
    /// function that injects this project's vault secrets into a single
    /// command's environment via `exec` — it deliberately does NOT export
    /// secrets into the interactive shell itself. See the generated
    /// snippet's own comments for why.
    ShellInit {
        /// Shell to generate a snippet for
        #[arg(value_enum)]
        shell: ShellKind,
    },
    /// Print the prefix recorded in the nearest `.hearth-vault` project
    /// marker file, walking up from the current directory. Used by the
    /// `hv` wrapper `shell-init` generates.
    ProjectPrefix,
}

#[derive(Clone, Copy, clap::ValueEnum)]
enum ShellKind {
    Bash,
    Zsh,
    Fish,
}

/// Routine per-invocation chatter (unlock banner, injection summaries).
///
/// hearth-vault can be called very frequently (once per credential-bearing
/// script or agent step); these lines say nothing an caller can act on, so
/// they are silent unless `HEARTH_VAULT_VERBOSE=1`. Warnings and failures
/// are NOT routed through this — they always print.
fn verbose() -> bool {
    std::env::var("HEARTH_VAULT_VERBOSE").is_ok_and(|v| v != "0" && !v.is_empty())
}

macro_rules! note {
    ($($arg:tt)*) => {
        if verbose() {
            eprintln!($($arg)*);
        }
    };
}

/// True when hearth-vault should refuse to write a secret value to a
/// stream/file for this invocation, given whether stdout is a terminal and
/// whether the escape-hatch env var is set.
///
/// Split out from `refuse_if_non_tty` as a pure function so the policy
/// boundary is unit-testable without faking an actual TTY.
fn should_refuse_non_tty(stdout_is_tty: bool, allow_override: bool) -> bool {
    !stdout_is_tty && !allow_override
}

/// Refuse a value-emitting subcommand when stdout is not a terminal.
///
/// Rationale — do NOT replace this with sniffing agent env vars
/// (`CLAUDECODE`, `CURSOR_*`, `AIDER_*`, ...): an agent's tool call is
/// structurally a pipe (its stdout is captured and typically forwarded to a
/// model provider off-box), and a human's interactive shell is structurally
/// a TTY. That is one invariant that holds regardless of which agent
/// framework is calling and can't be defeated by unsetting an env var the
/// agent itself controls. A fingerprint list of agent markers is guaranteed
/// to rot as new tools ship; "is this stdout a pipe or a terminal" is not.
/// `exec` is deliberately exempt — see its doc comment.
fn refuse_if_non_tty(cmd: &str) -> anyhow::Result<()> {
    let stdout_is_tty = platform::stdout_is_tty();
    let allow_override =
        std::env::var("HEARTH_VAULT_ALLOW_NON_TTY").is_ok_and(|v| v != "0" && !v.is_empty());
    if should_refuse_non_tty(stdout_is_tty, allow_override) {
        anyhow::bail!(
            "`{cmd}` writes a secret value and refuses to run with stdout redirected (not a \
             terminal). If this is an intentional systemd/CI invocation, set \
             HEARTH_VAULT_ALLOW_NON_TTY=1. If you're an automation or agent that needs the \
             secret's *effect* rather than its raw value, use `hearth-vault exec --prefix \
             <prefix> -- <command>` instead — it injects secrets into a child process's \
             environment and never puts them on a stream you (or anything reading your output) \
             can capture."
        );
    }
    Ok(())
}

/// Pure policy check: may a key at this tier be *printed* — written to
/// stdout by `export-env`, or to a file by `export-env-file`? Tier 3 and
/// above refuse. Split out so the boundary is unit-testable without opening
/// a vault.
fn tier_allows_export(tier: u8) -> bool {
    tier < TIER_USE_ONLY
}

/// Pure policy check: may a key at this tier be *injected* into a child
/// process's environment by `exec`?
///
/// This is deliberately a different question from `tier_allows_export`.
/// `exec` never writes the value to a stream the caller reads — it goes into
/// the child's environment and dies with it — so tier-3 use-only keys are
/// injectable even though they are unprintable. Only sign-only keys, which
/// must never leave the vault process at all, are withheld.
///
/// Collapsing these two checks into one makes the default tier un-`exec`-able
/// and silently breaks the `import-env` → `exec` workflow, while the export
/// refusal message tells the user to run the very command that will refuse.
fn tier_allows_exec_injection(tier: u8) -> bool {
    tier < TIER_SIGN_ONLY
}

/// Best-effort home directory lookup via the `directories` crate (already a
/// dependency for `VaultStore::default_path()`), so we don't need to add
/// the separate `dirs` crate just for the legacy-path fallback.
fn home_dir() -> Option<PathBuf> {
    directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf())
}

/// Path of the legacy (pre-migration) vault file.
fn legacy_vault_path() -> anyhow::Result<PathBuf> {
    let home = home_dir().ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?;
    Ok(home.join(".hearth").join("vault.json"))
}

/// Resolve the vault file path in priority order: `--vault-path`, then
/// `$HEARTH_VAULT_HOME/vault.json`, then the platform data directory. If
/// the platform-dir vault doesn't exist yet but a legacy
/// `~/.hearth/vault.json` does, use the legacy path and print a one-line
/// hint to run `hearth-vault migrate`.
fn resolve_vault_path(explicit: Option<&PathBuf>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.clone());
    }
    if let Ok(dir) = std::env::var("HEARTH_VAULT_HOME") {
        if !dir.trim().is_empty() {
            return Ok(PathBuf::from(dir).join("vault.json"));
        }
    }
    let platform_path = VaultStore::default_path()?;
    if !platform_path.exists() {
        if let Ok(legacy) = legacy_vault_path() {
            if legacy.exists() {
                eprintln!(
                    "Using legacy vault at {} — run `hearth-vault migrate` to move it to {}.",
                    legacy.display(),
                    platform_path.display()
                );
                return Ok(legacy);
            }
        }
    }
    Ok(platform_path)
}

/// Resolve the secret backend for TPM2/keyring auto-unseal and `seal`.
///
/// Backends exist only to seal the vault passphrase for automatic unlock, so
/// a machine with no hardware backend has no backend at all — that surfaces
/// as a clear `Err` here (propagated via `?`, never unwrapped), and callers
/// fall back to prompting for the passphrase.
fn resolve_backend(
    name: Option<&str>,
) -> anyhow::Result<Box<dyn hearth_vault::hsm::SecretBackend>> {
    match name {
        Some(n) => hearth_vault::hsm::backend_named(n)
            .map_err(|e| anyhow::anyhow!("backend '{n}' unavailable: {e}")),
        None => hearth_vault::hsm::detect_backend()
            .map_err(|e| anyhow::anyhow!("no secret backend available: {e}")),
    }
}

/// Path where the sealed vault passphrase blob lives, alongside the vault
/// file it unlocks.
fn sealed_passphrase_path(vault_path: &Path) -> PathBuf {
    vault_path.with_file_name("vault-passphrase.sealed")
}

/// Open the vault with the best available method.
///
/// Priority:
/// 1. Hardware-backed auto-unseal (sealed blob next to the vault file,
///    unsealed via TPM2/keyring — skipped entirely if no such backend is
///    available or nothing was ever sealed).
/// 2. HEARTH_VAULT_PASSPHRASE env var (session caching / SSH / tmux)
/// 3. Interactive prompt via rpassword
fn open_vault(vault_path: PathBuf, backend_name: Option<&str>) -> anyhow::Result<VaultStore> {
    let sealed_path = sealed_passphrase_path(&vault_path);

    if sealed_path.exists() {
        match resolve_backend(backend_name) {
            Ok(hsm) if hsm.tier() <= 2 => {
                if let Ok(blob) = fs::read(&sealed_path) {
                    match hsm.unseal(&blob, "hearth-vault") {
                        Ok(passphrase_bytes) => {
                            if let Ok(passphrase) = String::from_utf8(passphrase_bytes.to_vec()) {
                                match VaultStore::open_at_with_passphrase(
                                    vault_path.clone(),
                                    &passphrase,
                                ) {
                                    Ok(store) => {
                                        note!(
                                            "Vault unlocked via {} (tier {})",
                                            hsm.name(),
                                            hsm.tier()
                                        );
                                        return Ok(store);
                                    }
                                    Err(_) => {
                                        eprintln!(
                                            "Sealed passphrase doesn't match vault — falling back."
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => eprintln!("Auto-unseal failed (boot chain changed?): {e}"),
                    }
                }
            }
            Ok(_) => {
                // A backend resolved but isn't hardware-backed; auto-unseal
                // isn't meaningful for it. Fall through to passphrase.
            }
            Err(e) => note!(
                "No secret backend available for auto-unseal ({e}); falling back to passphrase."
            ),
        }
    }

    if let Ok(passphrase) = std::env::var("HEARTH_VAULT_PASSPHRASE") {
        if !passphrase.is_empty() {
            return VaultStore::open_at_with_passphrase(vault_path, &passphrase);
        }
    }

    let passphrase = rpassword::prompt_password("Vault passphrase: ")?;
    VaultStore::open_at_with_passphrase(vault_path, &passphrase)
}

fn main() -> anyhow::Result<()> {
    // Best-effort: prevent a crash from writing vault-derived secrets to a
    // core file. Must happen before anything touches vault contents.
    platform::disable_core_dumps();

    let cli = Cli::parse();
    let vault_path = resolve_vault_path(cli.vault_path.as_ref())?;
    let backend = cli.backend.as_deref();

    match cli.command {
        Commands::Init => cmd_init(vault_path)?,
        Commands::Set { keys, tier } => cmd_set(vault_path, backend, &keys, tier)?,
        Commands::Import { file, key, tier } => cmd_import(vault_path, backend, &file, &key, tier)?,
        Commands::ImportEnv {
            file,
            prefix,
            tier,
            keep,
            force,
        } => cmd_import_env(vault_path, backend, file, prefix, tier, keep, force)?,
        Commands::Migrate => cmd_migrate()?,
        Commands::List => cmd_list(vault_path, backend)?,
        Commands::Has { key } => cmd_has(vault_path, backend, &key)?,
        Commands::Delete { key } => cmd_delete(vault_path, backend, &key)?,
        Commands::Rename { from, to } => cmd_rename(vault_path, backend, &from, &to)?,
        Commands::Retier { key, tier } => cmd_retier(vault_path, backend, &key, tier)?,
        Commands::ExportEnv { key, env_name } => {
            cmd_export_env(vault_path, backend, &key, &env_name)?
        }
        Commands::Status => cmd_status(vault_path, backend)?,
        Commands::Recover => cmd_recover(vault_path)?,
        Commands::ChangePassphrase => cmd_change_passphrase(vault_path, backend)?,
        Commands::NewRecoveryKey => cmd_new_recovery_key(vault_path)?,
        Commands::Prompt => cmd_prompt(vault_path)?,
        Commands::Seal => cmd_seal(vault_path, backend)?,
        Commands::ExportEnvFile { prefix, output } => {
            cmd_export_env_file(vault_path, backend, &prefix, &output)?
        }
        Commands::Exec { prefix, command } => cmd_exec(vault_path, backend, &prefix, &command)?,
        Commands::Sign {
            key,
            algorithm,
            message,
        } => cmd_sign(vault_path, backend, &key, &algorithm, &message)?,
        Commands::GithubAppToken {
            installation_id,
            json,
            repository,
        } => cmd_github_app_token(vault_path, backend, installation_id, json, &repository)?,
        Commands::Scan {
            path,
            json,
            adopt,
            prefix,
            rules,
            force,
        } => cmd_scan(vault_path, backend, path, json, adopt, prefix, rules, force)?,
        Commands::ShellInit { shell } => cmd_shell_init(shell),
        Commands::ProjectPrefix => cmd_project_prefix()?,
    }

    Ok(())
}

/// Print a boxed banner followed by the 24-word mnemonic, six words per
/// line with 1-based numbering so it's easy to transcribe by hand.
fn print_mnemonic_banner(title: &str, mnemonic: &str) {
    eprintln!();
    eprintln!("======================================================================");
    eprintln!("  {title}");
    eprintln!("======================================================================");
    eprintln!();
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    for (i, chunk) in words.chunks(6).enumerate() {
        let numbered: Vec<String> = chunk
            .iter()
            .enumerate()
            .map(|(j, w)| format!("{:>2}. {:<12}", i * 6 + j + 1, w))
            .collect();
        eprintln!("  {}", numbered.join("  "));
    }
    eprintln!();
}

fn cmd_init(vault_path: PathBuf) -> anyhow::Result<()> {
    refuse_if_non_tty("init")?;

    if vault_path.exists() {
        eprintln!("Vault already exists at {}", vault_path.display());
        eprintln!("Use 'hearth-vault set' to add credentials.");
        return Ok(());
    }

    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent)?;
    }

    eprintln!("Initializing new vault at {}", vault_path.display());
    let passphrase = rpassword::prompt_password("Choose a vault passphrase: ")?;
    if passphrase.is_empty() {
        anyhow::bail!("passphrase cannot be empty");
    }
    let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
    if passphrase != confirm {
        anyhow::bail!("passphrases do not match");
    }

    let mut store = VaultStore::open_at_with_passphrase(vault_path.clone(), &passphrase)?;
    store.save()?;

    let mnemonic = store.generate_recovery_key()?;
    store.save()?;

    eprintln!("Vault initialized at {}", vault_path.display());
    eprintln!("File permissions restricted to the current user.");
    print_mnemonic_banner("RECOVERY KEY", &mnemonic);
    eprintln!("Write down these 24 words and store them somewhere safe.");
    eprintln!(
        "This is your ONLY way back in if you forget the passphrase — it will NEVER be shown again."
    );
    eprintln!();
    eprintln!("Press Enter after you have written down the recovery key...");
    let mut buf = String::new();
    std::io::stdin().read_line(&mut buf)?;

    Ok(())
}

fn cmd_set(
    vault_path: PathBuf,
    backend: Option<&str>,
    keys: &[String],
    tier: u8,
) -> anyhow::Result<()> {
    if keys.is_empty() {
        anyhow::bail!("provide at least one key name");
    }

    // Single unlock for all keys
    let mut store = open_vault(vault_path, backend)?;

    let interactive = std::io::stdin().is_terminal();

    for key in keys {
        let mut value = if interactive {
            rpassword::prompt_password(format!("Value for '{key}': "))?
        } else {
            // Non-interactive (piped/scripted): read one line from stdin.
            // Allows: echo "$SECRET" | hearth-vault set key
            //   or:   hearth-vault set key <<< "$SECRET"
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            line.trim_end_matches(['\n', '\r']).to_string()
        };

        if value.is_empty() {
            eprintln!("Skipping '{key}' (empty value)");
            value.zeroize();
            continue;
        }

        let sensitive = SensitiveString::new(value.clone());
        value.zeroize();
        store.set(key, &sensitive, tier)?;
        eprintln!("  \u{2713} {key}");
    }

    store.save()?;
    eprintln!("Stored {} credential(s) at tier {tier}.", keys.len());
    if tier == TIER_USE_ONLY {
        eprintln!(
            "Tier {TIER_USE_ONLY} is use-only: never printed by export-env / export-env-file. \
             Use them with `hearth-vault exec --prefix <prefix> -- <command>`, or run \
             `hearth-vault retier <key> --tier 2` to make one printable."
        );
    }
    Ok(())
}

fn cmd_import(
    vault_path: PathBuf,
    backend: Option<&str>,
    file_path: &str,
    key: &str,
    tier: u8,
) -> anyhow::Result<()> {
    let path = PathBuf::from(file_path);
    if !path.exists() {
        anyhow::bail!("file not found: {file_path}");
    }

    // Read the credential value from the file
    let value = fs::read_to_string(&path)?.trim().to_string();
    if value.is_empty() {
        anyhow::bail!("file is empty");
    }

    let mut store = open_vault(vault_path, backend)?;
    let sensitive = SensitiveString::new(value);
    store.set(key, &sensitive, tier)?;
    store.save()?;

    // Securely delete the source file: overwrite with zeros, then remove
    secure_delete_file(&path)?;

    eprintln!("Imported: {key} (tier {tier})");
    eprintln!("Source file securely deleted: {file_path}");
    Ok(())
}

/// Overwrite a file with zeros before deleting it.
fn secure_delete_file(path: &PathBuf) -> anyhow::Result<()> {
    let metadata = fs::metadata(path)?;
    let size = metadata.len() as usize;

    // Overwrite with zeros
    let mut file = fs::OpenOptions::new().write(true).open(path)?;
    let zeros = vec![0u8; size];
    file.write_all(&zeros)?;
    file.sync_all()?;
    drop(file);

    // Delete the file
    fs::remove_file(path)?;
    Ok(())
}

/// Parse a minimal dotenv-format buffer into ordered (key, value) pairs.
///
/// Supports: `KEY=value`, `export KEY=value`, single- and double-quoted
/// values (with `\"`, `\\`, and `\n` unescaped inside double-quoted
/// values), `#` full-line comments, and blank lines. Deliberately hand
/// rolled rather than pulling in a dotenv crate — the grammar this tool
/// needs is small enough to keep in one file and audit at a glance.
fn parse_dotenv(contents: &str) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim();
        let parsed_value = if value.len() >= 2
            && ((value.starts_with('"') && value.ends_with('"'))
                || (value.starts_with('\'') && value.ends_with('\'')))
        {
            let quote = value.as_bytes()[0] as char;
            let inner = &value[1..value.len() - 1];
            if quote == '"' {
                inner
                    .replace("\\n", "\n")
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\")
            } else {
                inner.to_string()
            }
        } else {
            value.to_string()
        };
        pairs.push((key.to_string(), parsed_value));
    }
    pairs
}

/// Best-effort: append `entry` to `./.gitignore` if the file exists and
/// doesn't already list it verbatim. Never creates a `.gitignore` that
/// wasn't already there — running `import-env` in a bare directory
/// shouldn't grow one just because we felt like it.
fn add_to_gitignore(entry: &str) {
    let gitignore = Path::new(".gitignore");
    if !gitignore.exists() {
        return;
    }
    let Ok(contents) = fs::read_to_string(gitignore) else {
        return;
    };
    if contents.lines().any(|l| l.trim() == entry) {
        return;
    }
    let mut new_contents = contents;
    if !new_contents.is_empty() && !new_contents.ends_with('\n') {
        new_contents.push('\n');
    }
    new_contents.push_str(entry);
    new_contents.push('\n');
    if fs::write(gitignore, new_contents).is_ok() {
        eprintln!("Added {entry} to .gitignore");
    }
}

fn cmd_import_env(
    vault_path: PathBuf,
    backend: Option<&str>,
    file: Option<String>,
    prefix: Option<String>,
    tier: u8,
    keep: bool,
    force: bool,
) -> anyhow::Result<()> {
    let file_path = file.unwrap_or_else(|| ".env".to_string());
    let path = PathBuf::from(&file_path);
    if !path.exists() {
        anyhow::bail!("file not found: {file_path}");
    }

    let contents = fs::read_to_string(&path)?;
    let pairs = parse_dotenv(&contents);
    if pairs.is_empty() {
        anyhow::bail!("no KEY=value pairs found in {file_path}");
    }

    let prefix = prefix.unwrap_or_default();
    if prefix.is_empty() {
        eprintln!(
            "Warning: no --prefix given; imported keys land with no prefix, so \
             `hearth-vault exec --prefix '' -- ...` would inject every exportable secret in the \
             vault, not just these. Re-run with --prefix <something>/ to scope them."
        );
    }

    let mut store = open_vault(vault_path, backend)?;

    let mut stored = 0usize;
    let mut skipped = Vec::new();
    for (key, value) in &pairs {
        let full_key = format!("{prefix}{key}");
        if value.is_empty() {
            skipped.push(format!("{full_key} (empty value)"));
            continue;
        }
        if store.has(&full_key) && !force {
            skipped.push(format!(
                "{full_key} (already exists — pass --force to overwrite)"
            ));
            continue;
        }
        store.set(&full_key, &SensitiveString::new(value.clone()), tier)?;
        stored += 1;
    }
    store.save()?;

    eprintln!("Imported {stored} credential(s) from {file_path} at tier {tier}.");
    if !skipped.is_empty() {
        eprintln!("Skipped {} key(s):", skipped.len());
        for k in &skipped {
            eprintln!("  - {k}");
        }
    }

    add_to_gitignore(&file_path);

    if keep {
        eprintln!(
            "Kept {file_path} (--keep passed). Delete it manually once you trust the vault copy."
        );
    } else {
        secure_delete_file(&path)?;
        eprintln!("Deleted {file_path}. Replace whatever sourced it with:");
        eprintln!("  hearth-vault exec --prefix {prefix} -- <your command>");
    }

    Ok(())
}

fn cmd_migrate() -> anyhow::Result<()> {
    let legacy = legacy_vault_path()?;
    if !legacy.exists() {
        anyhow::bail!(
            "no legacy vault found at {} — nothing to migrate.",
            legacy.display()
        );
    }
    let target = VaultStore::default_path()?;
    if target.exists() {
        anyhow::bail!(
            "a vault already exists at {} — refusing to overwrite it. Move it aside first if \
             you really want to replace it.",
            target.display()
        );
    }

    eprintln!(
        "Migrating legacy vault:\n  from {}\n  to   {}",
        legacy.display(),
        target.display()
    );
    let passphrase = rpassword::prompt_password("Legacy vault passphrase: ")?;
    hearth_vault::store::migrate_v1_to_v2(&legacy, &passphrase)?;

    eprintln!("Migration complete.");
    eprintln!("  New vault: {}", target.display());
    eprintln!(
        "  Old file left in place at {} — delete it once `hearth-vault status` confirms the \
         new vault opens.",
        legacy.display()
    );
    Ok(())
}

fn cmd_list(vault_path: PathBuf, backend: Option<&str>) -> anyhow::Result<()> {
    let store = open_vault(vault_path, backend)?;
    let entries = store.list();

    if entries.is_empty() {
        eprintln!("Vault is empty. Use 'hearth-vault set <key>' to add credentials.");
        return Ok(());
    }

    println!("{:<35} {:>4}  {:<25} UPDATED", "KEY", "TIER", "CREATED");
    println!("{}", "-".repeat(90));
    for entry in &entries {
        println!(
            "{:<35} {:>4}  {:<25} {}",
            entry.key, entry.tier, entry.created_at, entry.updated_at
        );
    }
    eprintln!("\n{} credential(s) stored.", entries.len());
    Ok(())
}

fn cmd_has(vault_path: PathBuf, backend: Option<&str>, key: &str) -> anyhow::Result<()> {
    let store = open_vault(vault_path, backend)?;
    if store.has(key) {
        println!("yes");
    } else {
        println!("no");
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_delete(vault_path: PathBuf, backend: Option<&str>, key: &str) -> anyhow::Result<()> {
    let mut store = open_vault(vault_path, backend)?;
    if store.delete(key)? {
        store.save()?;
        eprintln!("Deleted: {key}");
    } else {
        eprintln!("Key not found: {key}");
        std::process::exit(1);
    }
    Ok(())
}

fn cmd_rename(
    vault_path: PathBuf,
    backend: Option<&str>,
    from: &str,
    to: &str,
) -> anyhow::Result<()> {
    let mut store = open_vault(vault_path, backend)?;
    store.rename(from, to)?;
    store.save()?;
    eprintln!("  \u{2713} {from} -> {to}");
    Ok(())
}

fn cmd_retier(
    vault_path: PathBuf,
    backend: Option<&str>,
    key: &str,
    tier: u8,
) -> anyhow::Result<()> {
    let mut store = open_vault(vault_path, backend)?;
    let prev_tier = store
        .tier_of(key)
        .ok_or_else(|| anyhow::anyhow!("key not found: {key}"))?;
    store.retier(key, tier)?;
    store.save()?;
    eprintln!("  \u{2713} {key}: tier {prev_tier} -> {tier}");
    if tier == TIER_USE_ONLY {
        eprintln!(
            "    Note: tier-{tier} keys are no longer printed by export-env / \
             export-env-file. They are still usable via exec and sign."
        );
    }
    Ok(())
}

fn cmd_export_env(
    vault_path: PathBuf,
    backend: Option<&str>,
    key: &str,
    env_name: &str,
) -> anyhow::Result<()> {
    refuse_if_non_tty("export-env")?;
    let store = open_vault(vault_path, backend)?;
    let key_tier = store.tier_of(key).unwrap_or(0);
    if !tier_allows_export(key_tier) {
        anyhow::bail!(
            "key {key} is tier {key_tier}, which is never printed.\n\
             \n\
             Tiers: 1/2 exportable, 3 use-only (the default), {TIER_SIGN_ONLY} sign-only.\n\
             \n\
             Use it without printing it:\n  \
               hearth-vault exec --prefix <prefix> -- <command>{}\n\
             Or, if you really need the value on stdout:\n  \
               hearth-vault retier {key} --tier 2",
            if key_tier >= TIER_SIGN_ONLY {
                format!(
                    "   (tier {TIER_SIGN_ONLY} is excluded from exec too)\n  \
                     hearth-vault sign --key {key} --algorithm <alg> --message <msg>"
                )
            } else {
                String::new()
            }
        );
    }
    match store.get(key)? {
        Some(value) => {
            // Print the actual export command (value is real, not masked)
            // The value goes to stdout for eval; status messages to stderr
            println!("export {}={}", env_name, shell_escape(value.as_str()));
            eprintln!("export {}=***", env_name);
        }
        None => {
            anyhow::bail!("key not found: {key}");
        }
    }
    Ok(())
}

/// Escape a string for safe use in a shell export command.
fn shell_escape(s: &str) -> String {
    // Use single quotes, escaping any single quotes within
    format!("'{}'", s.replace('\'', "'\\''"))
}

fn cmd_recover(vault_path: PathBuf) -> anyhow::Result<()> {
    refuse_if_non_tty("recover")?;

    if !vault_path.exists() {
        anyhow::bail!("no vault found at {}", vault_path.display());
    }

    eprintln!("Enter your 24-word recovery mnemonic:");
    let mnemonic = rpassword::prompt_password("Recovery words: ")?;

    let mut store = VaultStore::open_at_with_mnemonic(vault_path, &mnemonic)?;

    let entries = store.list();
    eprintln!(
        "Recovery successful! Vault contains {} credential(s).",
        entries.len()
    );

    // Rotate the recovery key since the old one was just typed in — treat
    // it as used. This does not touch the passphrase wrap or the data key.
    let new_mnemonic = store.generate_recovery_key()?;
    store.save()?;
    print_mnemonic_banner("NEW RECOVERY KEY", &new_mnemonic);
    eprintln!("Your old recovery key is no longer valid.");
    eprintln!();
    eprintln!("You may also want to run: hearth-vault change-passphrase");

    Ok(())
}

/// Generate (or replace) the vault's recovery mnemonic.
///
/// The recovery wrap is independent of the passphrase wrap — both wrap the
/// same data key — so this rewraps only the recovery slot and never touches
/// entries or the passphrase.
fn cmd_new_recovery_key(vault_path: PathBuf) -> anyhow::Result<()> {
    refuse_if_non_tty("new-recovery-key")?;

    if !vault_path.exists() {
        anyhow::bail!("no vault found at {}", vault_path.display());
    }

    let passphrase = rpassword::prompt_password("Vault passphrase: ")?;
    let mut store = VaultStore::open_at_with_passphrase(vault_path, &passphrase)?;

    let had_recovery = store.has_recovery_key();
    let mnemonic = store.generate_recovery_key()?;
    store.save()?;

    print_mnemonic_banner("RECOVERY KEY", &mnemonic);
    if had_recovery {
        eprintln!("Your previous recovery phrase is no longer valid.");
    }

    Ok(())
}

fn cmd_change_passphrase(vault_path: PathBuf, backend: Option<&str>) -> anyhow::Result<()> {
    if !vault_path.exists() {
        anyhow::bail!("no vault found at {}", vault_path.display());
    }

    eprintln!("Open vault with current passphrase (or recovery key):");
    eprintln!("  1. Current passphrase");
    eprintln!("  2. Recovery mnemonic");
    eprint!("Choice [1]: ");
    std::io::stderr().flush()?;

    let mut choice = String::new();
    std::io::stdin().read_line(&mut choice)?;
    let choice = choice.trim();

    let mut store = if choice == "2" {
        let mnemonic = rpassword::prompt_password("Recovery words: ")?;
        VaultStore::open_at_with_mnemonic(vault_path.clone(), &mnemonic)?
    } else {
        open_vault(vault_path.clone(), backend)?
    };

    let new_pass = rpassword::prompt_password("New passphrase: ")?;
    if new_pass.is_empty() {
        anyhow::bail!("passphrase cannot be empty");
    }
    let confirm = rpassword::prompt_password("Confirm new passphrase: ")?;
    if new_pass != confirm {
        anyhow::bail!("passphrases do not match");
    }

    // Rewraps the data key only — entries are never re-encrypted, and the
    // recovery mnemonic (which wraps the same data key independently)
    // keeps working unchanged.
    store.change_passphrase(&new_pass)?;
    store.save()?;

    eprintln!("Passphrase changed. Your recovery mnemonic is unchanged.");
    Ok(())
}

fn cmd_prompt(vault_path: PathBuf) -> anyhow::Result<()> {
    refuse_if_non_tty("prompt")?;
    let passphrase = rpassword::prompt_password("Vault passphrase: ")?;
    // Verify it works
    let _store = VaultStore::open_at_with_passphrase(vault_path, &passphrase)?;
    // Output to stdout for capture: export HEARTH_VAULT_PASSPHRASE=$(hearth-vault prompt)
    print!("{passphrase}");
    eprintln!("Passphrase verified. To cache for this session:");
    eprintln!("  export HEARTH_VAULT_PASSPHRASE=$(hearth-vault prompt)");
    eprintln!("To clear: unset HEARTH_VAULT_PASSPHRASE");
    Ok(())
}

fn cmd_seal(vault_path: PathBuf, backend: Option<&str>) -> anyhow::Result<()> {
    let hsm = resolve_backend(backend)?;
    eprintln!("HSM backend: {} (tier {})", hsm.name(), hsm.tier());

    if hsm.tier() > 2 {
        anyhow::bail!(
            "No hardware-backed backend available (need TPM2 or an OS keyring, tier <= 2).\n\
             Current backend: {} (tier {})\n\
             Ensure TPM2 is accessible (/dev/tpmrm0) or an OS keyring daemon is running, or pass \
             --backend explicitly if more than one is available.",
            hsm.name(),
            hsm.tier()
        );
    }

    // Get the passphrase to seal
    let passphrase = rpassword::prompt_password("Vault passphrase to seal: ")?;

    // Verify it opens the vault
    let _store = VaultStore::open_at_with_passphrase(vault_path.clone(), &passphrase)?;
    eprintln!("Passphrase verified against vault.");

    // Seal passphrase to TPM2/keyring
    let sealed_blob = hsm
        .seal(passphrase.as_bytes(), "hearth-vault")
        .map_err(|e| anyhow::anyhow!("seal failed: {e}"))?;

    // Write sealed blob to disk
    let sealed_path = sealed_passphrase_path(&vault_path);
    fs::write(&sealed_path, &sealed_blob)?;
    platform::restrict_to_owner(&sealed_path)?;

    eprintln!("Passphrase sealed to {} (tier {}).", hsm.name(), hsm.tier());
    eprintln!("Sealed blob: {}", sealed_path.display());
    eprintln!("The vault will now auto-unseal on this machine — no passphrase needed.");
    eprintln!();
    eprintln!("On a different machine, you'll need the passphrase or recovery key.");

    Ok(())
}

/// Map a vault key to its env-var name: strip the prefix, uppercase, and turn
/// path/word separators (`/` and `-`) into `_`. Shared by export-env-file and
/// exec so both produce the same variable names for the same key.
///
/// `-` must become `_`: a hyphen is not a valid POSIX environment-variable
/// name, so `myapp/database-url` has to surface as `DATABASE_URL` (what
/// consumers read), not `DATABASE-URL` (which no shell can set and Go's
/// os.Getenv would never find).
fn env_name_for(key: &str, prefix: &str) -> String {
    key.strip_prefix(prefix)
        .unwrap_or(key)
        .to_uppercase()
        .replace(['/', '-'], "_")
}

/// A single `ENV_NAME=value` line plus the human-facing `key -> ENV_NAME`
/// mapping, kept together so callers can write the file and log names
/// without re-deriving either.
struct ExportLine {
    env_name: String,
    key: String,
    line: String,
}

/// Build the env-file lines for every tier-<3 key under `prefix`, returning
/// `(lines, skipped_use_only)`.
///
/// Multi-line values (PEM keys) are written verbatim: this path is the
/// legitimate systemd/ExecStartPre injection into an owner-only-perms file
/// that a service loader reads, where embedded newlines are fine.
/// Use-only material still belongs at tier 3 (skipped below), and the whole
/// command is refused outright for non-TTY callers by `refuse_if_non_tty`
/// before this runs.
fn collect_export_lines(
    store: &VaultStore,
    prefix: &str,
) -> anyhow::Result<(Vec<ExportLine>, Vec<String>)> {
    let entries = store.list();
    let mut lines = Vec::new();
    let mut skipped_use_only = Vec::new();

    for e in entries.iter() {
        if !e.key.starts_with(prefix) {
            continue;
        }
        if !tier_allows_export(e.tier) {
            skipped_use_only.push(e.key.clone());
            continue;
        }
        let value = store
            .get(&e.key)?
            .ok_or_else(|| anyhow::anyhow!("key disappeared during export: {}", e.key))?;
        let env_name = env_name_for(&e.key, prefix);
        lines.push(ExportLine {
            line: format!("{}={}", env_name, value.as_str()),
            env_name,
            key: e.key.clone(),
        });
    }

    Ok((lines, skipped_use_only))
}

fn cmd_export_env_file(
    vault_path: PathBuf,
    backend: Option<&str>,
    prefix: &str,
    output_path: &str,
) -> anyhow::Result<()> {
    refuse_if_non_tty("export-env-file")?;
    let store = open_vault(vault_path, backend)?;

    let (lines, skipped_use_only) = collect_export_lines(&store, prefix)?;

    for k in &skipped_use_only {
        eprintln!("  skipped (tier >= {TIER_USE_ONLY}, not printable): {k}");
    }

    if lines.is_empty() {
        if !skipped_use_only.is_empty() {
            anyhow::bail!(
                "all matching keys for prefix '{prefix}' are tier {TIER_USE_ONLY} or higher and \
                 are never printed. Use `hearth-vault exec --prefix {prefix} -- <command>` to \
                 hand them to a process without writing them anywhere."
            );
        }
        anyhow::bail!("no keys found with prefix '{prefix}'");
    }

    let content = lines
        .iter()
        .map(|l| l.line.as_str())
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";

    // Create parent directories
    let path = PathBuf::from(output_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Write file
    fs::write(&path, content.as_bytes())?;
    platform::restrict_to_owner(&path)?;

    eprintln!(
        "Exported {} key(s) with prefix '{}' to {}",
        lines.len(),
        prefix,
        output_path
    );
    for l in &lines {
        note!("  {} -> {}", l.key, l.env_name);
    }

    Ok(())
}

/// Resolve every tier-<3 key under `prefix` into `(ENV_NAME, value)` pairs
/// for environment injection, returning `(injected, skipped_use_only)`.
///
/// Unlike export-env-file this does NOT reject multi-line values: they go
/// straight into a child process environment (which handles embedded
/// newlines fine) and are never written to a line-oriented file or stdout,
/// so there is nothing to spill. Tier-3 keys are still skipped — those are
/// use-only and belong to `sign`.
/// `(env vars to inject, keys skipped because they are use-only)`.
type ExecEnv = (Vec<(String, SensitiveString)>, Vec<String>);

fn collect_exec_env(store: &VaultStore, prefix: &str) -> anyhow::Result<ExecEnv> {
    let entries = store.list();
    let mut injected = Vec::new();
    let mut skipped_use_only = Vec::new();

    for e in entries.iter() {
        if !e.key.starts_with(prefix) {
            continue;
        }
        if !tier_allows_exec_injection(e.tier) {
            skipped_use_only.push(e.key.clone());
            continue;
        }
        let value = store
            .get(&e.key)?
            .ok_or_else(|| anyhow::anyhow!("key disappeared during exec: {}", e.key))?;
        injected.push((env_name_for(&e.key, prefix), value));
    }

    Ok((injected, skipped_use_only))
}

fn cmd_exec(
    vault_path: PathBuf,
    backend: Option<&str>,
    prefix: &str,
    command: &[String],
) -> anyhow::Result<()> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("no command given after `--`"))?;

    let store = open_vault(vault_path, backend)?;
    let (injected, skipped_use_only) = collect_exec_env(&store, prefix)?;

    for k in &skipped_use_only {
        note!("  skipped (tier {TIER_SIGN_ONLY}, sign-only): {k}");
    }
    if injected.is_empty() {
        anyhow::bail!(
            "no injectable keys found with prefix '{prefix}' (tier-{TIER_SIGN_ONLY} sign-only \
             keys are skipped — use `hearth-vault sign` for those); nothing to inject"
        );
    }

    note!(
        "Injecting {} secret(s) into `{}` environment (values never printed).",
        injected.len(),
        program
    );

    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    for (name, value) in &injected {
        cmd.env(name, value.as_str());
    }

    // On Unix, replace this process image with the child so exit codes and
    // signals pass through unchanged and the injected secrets never outlive
    // the exec. `exec()` only returns on failure.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(anyhow::anyhow!("failed to exec `{program}`: {err}"))
    }
    #[cfg(not(unix))]
    {
        let status = cmd.status()?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Supported signing algorithms. The string forms accepted on the CLI
/// are case-insensitive.
#[derive(Debug, Clone, Copy)]
enum SignAlgorithm {
    /// RSASSA-PSS with SHA-256 — randomized signature, used by several
    /// request-signing APIs (e.g. Coinbase's CB-ACCESS-SIGN scheme).
    RsaPssSha256,
    /// RSASSA-PKCS1-v1_5 with SHA-256 — deterministic signature, the
    /// algorithm GitHub Apps' JWT bearer tokens accept (alongside RS512).
    Rs256,
    /// RSASSA-PKCS1-v1_5 with SHA-512 — deterministic signature, another
    /// algorithm GitHub App JWT bearer tokens accept. Provided so a
    /// vault-signed JWT can be byte-compatible with existing in-process
    /// signers (e.g. Go's jwt-go `SigningMethodRS512`).
    Rs512,
}

impl SignAlgorithm {
    fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_uppercase().as_str() {
            "RSA-PSS-SHA256" => Ok(Self::RsaPssSha256),
            "RS256" => Ok(Self::Rs256),
            "RS512" => Ok(Self::Rs512),
            other => anyhow::bail!(
                "unsupported algorithm: {other} (supported: RSA-PSS-SHA256, RS256, RS512)"
            ),
        }
    }

    /// Returns true when the algorithm produces JWT-shaped output. JWTs use
    /// base64url-without-padding for the signature segment so it survives
    /// concatenation with `header.payload.` without re-encoding. PSS callers
    /// typically use standard base64.
    fn is_jwt(self) -> bool {
        matches!(self, Self::Rs256 | Self::Rs512)
    }
}

fn cmd_sign(
    vault_path: PathBuf,
    backend: Option<&str>,
    key: &str,
    algorithm: &str,
    message: &str,
) -> anyhow::Result<()> {
    refuse_if_non_tty("sign")?;
    let algo = SignAlgorithm::parse(algorithm)?;
    let store = open_vault(vault_path, backend)?;
    // Parse \n escape sequences in message to actual newlines.
    let message_resolved = message.replace("\\n", "\n");
    let b64 = sign_with_key(&store, key, algo, &message_resolved)?;
    println!("{b64}");
    Ok(())
}

/// Build the JSON body POSTed to `/app/installations/<id>/access_tokens`.
///
/// - Empty `repos` → `null`, which the caller serializes as no body
///   (preserves the default behavior: full-installation-scoped token).
/// - Non-empty `repos` → `{"repositories": [...]}`, which narrows the minted
///   token to those repos only. Any empty/whitespace-only entry is a hard
///   error — passing `[""]` to GitHub silently returns a full-scope token,
///   which would defeat the security goal of this flag.
///
/// Names are simple repo names (`myapp`), not `owner/repo` slugs — GitHub
/// scopes by name within the installation's owner.
fn build_token_request_body(repos: &[String]) -> anyhow::Result<Option<serde_json::Value>> {
    if repos.is_empty() {
        return Ok(None);
    }
    for r in repos {
        if r.trim().is_empty() {
            anyhow::bail!(
                "--repository value must not be empty; pass a simple repo name like `myapp`"
            );
        }
    }
    Ok(Some(serde_json::json!({ "repositories": repos })))
}

fn cmd_github_app_token(
    vault_path: PathBuf,
    backend: Option<&str>,
    installation_id: Option<i64>,
    output_json: bool,
    repositories: &[String],
) -> anyhow::Result<()> {
    use base64::Engine;

    refuse_if_non_tty("github-app-token")?;

    // Validate repository scoping up front so we never even open the vault
    // (or sign a JWT) on a malformed invocation.
    let scoping_body = build_token_request_body(repositories)?;

    let store = open_vault(vault_path, backend)?;

    // Read the App ID and Installation ID. These are not secret per se
    // (they're visible in the GitHub App settings page) but we still avoid
    // logging them to stdout/stderr.
    let app_id_sensitive = store
        .get("auth/GITHUB_APP_APP_ID")?
        .ok_or_else(|| anyhow::anyhow!("vault key auth/GITHUB_APP_APP_ID not found"))?;
    let app_id: i64 = app_id_sensitive
        .as_str()
        .trim()
        .parse()
        .map_err(|_| anyhow::anyhow!("auth/GITHUB_APP_APP_ID is not a valid integer"))?;

    let installation_id = match installation_id {
        Some(id) => id,
        None => {
            let inst_sensitive = store
                .get("auth/GITHUB_APP_INSTALLATION_ID")?
                .ok_or_else(|| anyhow::anyhow!(
                    "no --installation-id passed and vault key auth/GITHUB_APP_INSTALLATION_ID not found"
                ))?;
            inst_sensitive.as_str().trim().parse().map_err(|_| {
                anyhow::anyhow!("auth/GITHUB_APP_INSTALLATION_ID is not a valid integer")
            })?
        }
    };

    // Build JWT header + payload. GitHub requires RS256 (or RS512), iat in
    // the past, exp <= 10 minutes ahead, iss == app_id.
    let header = serde_json::json!({"alg": "RS256", "typ": "JWT"});
    let now = chrono::Utc::now().timestamp();
    let payload = serde_json::json!({
        "iat": now - 30,            // tolerate clock skew
        "exp": now + 9 * 60,        // 9 minutes (max is 10)
        "iss": app_id,
    });
    let header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?);
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?);
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Sign with the in-vault helper. The PEM bytes are loaded only for the
    // duration of this call and zeroized in cmd_sign / sign_with_key.
    let signature_b64 = sign_with_key(
        &store,
        "auth/GITHUB_APP_PRIVATE_KEY",
        SignAlgorithm::Rs256,
        &signing_input,
    )?;
    let jwt = format!("{signing_input}.{signature_b64}");

    // POST /app/installations/<id>/access_tokens, Bearer JWT.
    let url = format!("https://api.github.com/app/installations/{installation_id}/access_tokens");
    let client = reqwest::blocking::Client::builder()
        .user_agent("hearth-vault/github-app-token")
        .timeout(std::time::Duration::from_secs(15))
        .build()?;
    let mut req = client
        .post(&url)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .bearer_auth(&jwt);
    if let Some(ref body) = scoping_body {
        req = req.json(body);
    }
    let resp = req.send()?;

    let status = resp.status();
    if !status.is_success() {
        // SAFETY: GitHub error responses occasionally echo back fragments of
        // the bearer JWT. Surface only the status code.
        //
        // 422 from this endpoint with a non-empty `repositories` body almost
        // always means one of the requested repos is not granted to the
        // installation. Surface a clearer message; do NOT fall back to an
        // unscoped token — that would silently broaden access past what the
        // caller asked for, which is the exact security gap this flag closes.
        if status.as_u16() == 422 && !repositories.is_empty() {
            anyhow::bail!(
                "GitHub installation-token exchange failed: HTTP 422 — one of repositories {:?} is not granted to installation {} (response body suppressed to avoid echoing JWT fragments)",
                repositories,
                installation_id,
            );
        }
        anyhow::bail!(
            "GitHub installation-token exchange failed: HTTP {status} (response body suppressed to avoid echoing JWT fragments)"
        );
    }

    #[derive(serde::Deserialize)]
    struct InstallationTokenResp {
        token: String,
        expires_at: String,
    }
    let parsed: InstallationTokenResp = resp.json()?;

    if output_json {
        // Use serde to escape the token correctly even if GitHub adds
        // unusual characters in the future.
        let out = serde_json::json!({
            "token": parsed.token,
            "expires_at": parsed.expires_at,
        });
        println!("{}", serde_json::to_string(&out)?);
    } else {
        // Bare token, newline-terminated for shell-friendly $(...) capture.
        println!("{}", parsed.token);
    }
    Ok(())
}

/// Sign `message` with the PEM-encoded private key stored at `vault_key`,
/// using `algo`. Returns the signature as a base64-encoded string (URL-safe
/// no-pad for JWT algorithms, standard for PSS raw output).
///
/// # CVE note
/// This implementation uses `ring` (constant-time RSA, immune to the Marvin
/// timing attack that affected the `rsa 0.9` crate / RUSTSEC-2023-0071).
/// Both PKCS#8 ("PRIVATE KEY") and PKCS#1 ("RSA PRIVATE KEY") PEM formats
/// are supported: PKCS#8 keys are forwarded directly to `ring`; PKCS#1 keys
/// are passed via `ring::signature::RsaKeyPair::from_der`, which reads the
/// raw RSAPrivateKey DER sequence directly.
fn sign_with_key(
    store: &VaultStore,
    vault_key: &str,
    algo: SignAlgorithm,
    message: &str,
) -> anyhow::Result<String> {
    use base64::Engine;
    use ring::rand::SystemRandom;
    use ring::signature::{self, RsaKeyPair};

    let pem_sensitive = store
        .get(vault_key)?
        .ok_or_else(|| anyhow::anyhow!("key not found in vault: {vault_key}"))?;
    // SAFETY: as_str() returns the real bytes; to_string() would invoke
    // Display and produce "***" (SensitiveString's redacted Display impl).
    let mut pem_string = pem_sensitive.as_str().to_owned();

    let result = (|| -> anyhow::Result<String> {
        // Decode PEM to DER. Try PKCS#8 ("PRIVATE KEY") first, then
        // PKCS#1 ("RSA PRIVATE KEY") for GitHub App keys and similar.
        let (label, der_bytes) = pem_rfc7468::decode_vec(pem_string.as_bytes())
            .map_err(|e| anyhow::anyhow!("failed to decode PEM: {e}"))?;
        let key_pair: RsaKeyPair = match label {
            "PRIVATE KEY" => {
                // PKCS#8 DER — ring can parse this directly.
                RsaKeyPair::from_pkcs8(&der_bytes)
                    .map_err(|e| anyhow::anyhow!("failed to parse PKCS#8 RSA key: {e}"))?
            }
            "RSA PRIVATE KEY" => {
                // PKCS#1 DER — ring::signature::RsaKeyPair::from_der() reads
                // the raw RSAPrivateKey structure (version, n, e, d, p, q…).
                RsaKeyPair::from_der(&der_bytes)
                    .map_err(|e| anyhow::anyhow!("failed to parse PKCS#1 RSA key: {e}"))?
            }
            other => {
                return Err(anyhow::anyhow!(
                    "unsupported PEM label '{other}' (expected 'PRIVATE KEY' or 'RSA PRIVATE KEY')"
                ));
            }
        };

        let rng = SystemRandom::new();
        let modulus_len = key_pair.public().modulus_len();
        let mut sig_bytes = vec![0u8; modulus_len];

        let encoding: &dyn signature::RsaEncoding = match algo {
            SignAlgorithm::RsaPssSha256 => &signature::RSA_PSS_SHA256,
            SignAlgorithm::Rs256 => &signature::RSA_PKCS1_SHA256,
            SignAlgorithm::Rs512 => &signature::RSA_PKCS1_SHA512,
        };

        key_pair
            .sign(encoding, &rng, message.as_bytes(), &mut sig_bytes)
            .map_err(|e| anyhow::anyhow!("RSA signing failed: {e}"))?;

        Ok(if algo.is_jwt() {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&sig_bytes)
        } else {
            base64::engine::general_purpose::STANDARD.encode(&sig_bytes)
        })
    })();

    pem_string.zeroize();
    result
}

fn cmd_status(vault_path: PathBuf, backend: Option<&str>) -> anyhow::Result<()> {
    match resolve_backend(backend) {
        Ok(hsm) => println!("HSM backend: {} (tier {})", hsm.name(), hsm.tier()),
        Err(e) => println!(
            "HSM backend: unavailable for inspection ({e}). Hardware-backed backends need a \
             TPM2 or an OS keyring; the software backend needs vault-passphrase-derived key \
             material this command doesn't have without unlocking first."
        ),
    }

    if !vault_path.exists() {
        println!("Vault: not initialized");
        println!("  Run 'hearth-vault init' to create the vault.");
        return Ok(());
    }

    println!("Vault: {}", vault_path.display());
    // Entry names and count are themselves encrypted as part of the vault
    // body (see the on-disk format), so status — which never unlocks the
    // vault — can't report them. `list` unlocks and shows both.
    println!(
        "(entry names and count are encrypted; run `hearth-vault list` to unlock and view them)"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(&vault_path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode != 0o600 {
                eprintln!("WARNING: vault file permissions are {mode:o}, should be 600!");
            } else {
                println!("Permissions: 600 (OK)");
            }
        }
    }

    Ok(())
}

// ── scan / shell-init / project-prefix ──────────────────────────────────

/// True when `path`'s file name looks like a dotenv-style file: `.env`
/// itself, `.env.<anything>` (`.env.local`, `.env.production`), or anything
/// ending in `.env`. Only files matching this are eligible for the
/// line-rewrite path of `scan --adopt` — source code is reported, never
/// rewritten.
fn is_dotenv_file(path: &Path) -> bool {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name == ".env" || name.starts_with(".env.") || name.ends_with(".env"),
        None => false,
    }
}

fn print_rule_table() {
    println!("{:<32} {:>8}  DESCRIPTION", "RULE ID", "ENTROPY");
    println!("{}", "-".repeat(100));
    for rule in hearth_vault::scan::RULES {
        let entropy = rule
            .min_entropy
            .map(|e| format!("{e:.1}"))
            .unwrap_or_else(|| "-".to_string());
        println!("{:<32} {:>8}  {}", rule.id, entropy, rule.description);
    }
}

fn print_scan_report(findings: &[hearth_vault::scan::Finding]) {
    if findings.is_empty() {
        println!("No secrets found.");
        return;
    }

    let mut by_rule: std::collections::BTreeMap<&str, Vec<&hearth_vault::scan::Finding>> =
        std::collections::BTreeMap::new();
    for f in findings {
        by_rule.entry(f.rule_id.as_str()).or_default().push(f);
    }

    for (rule_id, group) in &by_rule {
        let desc = hearth_vault::scan::RULES
            .iter()
            .find(|r| r.id == *rule_id)
            .map(|r| r.description)
            .unwrap_or("");
        println!("== {rule_id} \u{2014} {desc} ==");
        for f in group {
            println!(
                "  {}:{}  {}  (suggested key: {})",
                f.path.display(),
                f.line_number,
                f.redacted,
                f.suggested_key
            );
        }
    }

    let file_count = findings
        .iter()
        .map(|f| f.path.as_path())
        .collect::<std::collections::HashSet<_>>()
        .len();
    println!();
    println!(
        "{} finding(s) across {} file(s).",
        findings.len(),
        file_count
    );
    println!(
        "Run `hearth-vault scan --adopt --prefix <name>/` to migrate .env findings into the \
         vault (source-code findings are reported only, never rewritten)."
    );
}

/// Write (or overwrite) the `.hearth-vault` project marker: a single bare
/// line containing the prefix, e.g. `myapp/`. No key, no `=`, no parser —
/// `hearth-vault project-prefix` reads it back tolerantly (see
/// `parse_project_prefix_line`) so an old `prefix = myapp/` line found lying
/// around still works.
fn write_project_marker(root: &Path, prefix: &str) -> anyhow::Result<()> {
    let marker_path = root.join(".hearth-vault");
    fs::write(&marker_path, format!("{prefix}\n"))?;
    eprintln!(
        "Wrote {} (prefix: {prefix}) — `hearth-vault project-prefix` and the `hv` shell-init \
         wrapper read this.",
        marker_path.display()
    );
    Ok(())
}

/// Result of running `scan --adopt`: vault keys written, keys skipped
/// because they already existed (and `--force` wasn't passed), source-code
/// findings that were reported but never rewritten, and lines that couldn't
/// be parsed/adopted for some other reason.
struct AdoptOutcome {
    adopted: Vec<String>,
    skipped_existing: Vec<String>,
    skipped_source: Vec<hearth_vault::scan::Finding>,
    errors: Vec<String>,
}

/// Migrate every `.env`-style finding into the vault under `prefix`,
/// commenting out the source line in place with a note of where the value
/// went. Source-code findings are collected into `skipped_source` and never
/// touched — rewriting arbitrary source is too dangerous to do
/// automatically.
fn adopt_findings(
    vault_path: PathBuf,
    backend: Option<&str>,
    findings: &[hearth_vault::scan::Finding],
    prefix: &str,
    force: bool,
) -> anyhow::Result<AdoptOutcome> {
    let mut skipped_source = Vec::new();
    let mut env_findings: Vec<&hearth_vault::scan::Finding> = Vec::new();
    let mut seen_lines: std::collections::HashSet<(PathBuf, usize)> =
        std::collections::HashSet::new();

    for f in findings {
        if !is_dotenv_file(&f.path) {
            skipped_source.push(f.clone());
            continue;
        }
        // Multiple rules can match the same line (e.g. a named rule and the
        // generic-assignment safety net both firing on one KEY=value). Only
        // adopt it once.
        if seen_lines.insert((f.path.clone(), f.line_number)) {
            env_findings.push(f);
        }
    }

    let mut adopted = Vec::new();
    let mut skipped_existing = Vec::new();
    let mut errors = Vec::new();

    if env_findings.is_empty() {
        return Ok(AdoptOutcome {
            adopted,
            skipped_existing,
            skipped_source,
            errors,
        });
    }

    let mut store = open_vault(vault_path, backend)?;

    let mut by_file: std::collections::BTreeMap<PathBuf, Vec<&hearth_vault::scan::Finding>> =
        std::collections::BTreeMap::new();
    for f in env_findings {
        by_file.entry(f.path.clone()).or_default().push(f);
    }

    for (file_path, file_findings) in by_file {
        let Ok(content) = fs::read_to_string(&file_path) else {
            errors.push(format!("{}: could not read file", file_path.display()));
            continue;
        };
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        let mut changed = false;

        for f in file_findings {
            let idx = f.line_number.saturating_sub(1);
            let Some(line) = lines.get(idx).cloned() else {
                errors.push(format!(
                    "{}:{}: line vanished before adopt",
                    file_path.display(),
                    f.line_number
                ));
                continue;
            };
            let Some((var_name, value)) = parse_dotenv(&line).into_iter().next() else {
                errors.push(format!(
                    "{}:{}: could not parse KEY=value",
                    file_path.display(),
                    f.line_number
                ));
                continue;
            };
            if value.is_empty() {
                errors.push(format!(
                    "{}:{}: empty value, skipped",
                    file_path.display(),
                    f.line_number
                ));
                continue;
            }

            let full_key = format!("{prefix}{}", f.suggested_key);
            if store.has(&full_key) && !force {
                skipped_existing.push(full_key);
                continue;
            }

            store.set(&full_key, &SensitiveString::new(value), TIER_USE_ONLY)?;
            adopted.push(full_key.clone());

            // Write a pointer, NOT the commented-out original. Commenting a
            // line leaves the secret sitting in the file verbatim — anything
            // that can read the file (including the agent this tool exists to
            // defend against) still gets every value with one `cat`. The
            // whole point of adopting is that the plaintext leaves the disk.
            lines[idx] = format!("# {var_name} -> hearth-vault: {full_key} (value removed)");
            changed = true;
        }

        if changed {
            let mut new_content = lines.join("\n");
            new_content.push('\n');
            fs::write(&file_path, new_content)?;
        }
    }

    store.save()?;

    Ok(AdoptOutcome {
        adopted,
        skipped_existing,
        skipped_source,
        errors,
    })
}

#[allow(clippy::too_many_arguments)]
fn cmd_scan(
    vault_path: PathBuf,
    backend: Option<&str>,
    path: Option<String>,
    json: bool,
    adopt: bool,
    prefix: Option<String>,
    rules: bool,
    force: bool,
) -> anyhow::Result<()> {
    // `scan` never emits a usable secret — every value that reaches stdout
    // here is redacted first (see `hearth_vault::scan`'s module doc: at most
    // 4 leading characters plus a length marker). That is precisely why this
    // command is exempt from `refuse_if_non_tty`, unlike `export-env`,
    // `sign`, etc. Do NOT add a non-TTY refusal to this function — there is
    // nothing here for that guard to protect.
    if rules {
        print_rule_table();
        return Ok(());
    }

    let root = PathBuf::from(path.unwrap_or_else(|| ".".to_string()));
    if !root.exists() {
        anyhow::bail!("path not found: {}", root.display());
    }

    let findings = hearth_vault::scan::scan_path(&root)?;

    if !adopt {
        if json {
            println!("{}", serde_json::to_string_pretty(&findings)?);
        } else {
            print_scan_report(&findings);
        }
        if !findings.is_empty() {
            std::process::exit(1);
        }
        return Ok(());
    }

    let prefix_str = prefix.clone().unwrap_or_default();
    let outcome = adopt_findings(vault_path, backend, &findings, &prefix_str, force)?;

    if let Some(p) = &prefix {
        let marker_root = if root.is_dir() {
            root.clone()
        } else {
            root.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."))
        };
        write_project_marker(&marker_root, p)?;
    }

    if json {
        let out = serde_json::json!({
            "adopted": outcome.adopted,
            "skipped_existing": outcome.skipped_existing,
            "skipped_source_code": outcome.skipped_source,
            "errors": outcome.errors,
        });
        println!("{}", serde_json::to_string_pretty(&out)?);
    } else {
        println!(
            "Adopted {} credential(s) into the vault.",
            outcome.adopted.len()
        );
        for k in &outcome.adopted {
            println!("  \u{2713} {k}");
        }
        if !outcome.skipped_existing.is_empty() {
            println!(
                "Skipped {} (already in vault \u{2014} pass --force to overwrite):",
                outcome.skipped_existing.len()
            );
            for k in &outcome.skipped_existing {
                println!("  - {k}");
            }
        }
        if !outcome.skipped_source.is_empty() {
            println!(
                "Found {} secret(s) in source code \u{2014} not rewritten automatically. Move \
                 these into the vault by hand:",
                outcome.skipped_source.len()
            );
            for f in &outcome.skipped_source {
                println!(
                    "  - {}:{} [{}] {} (suggested key: {})",
                    f.path.display(),
                    f.line_number,
                    f.rule_id,
                    f.redacted,
                    f.suggested_key
                );
            }
        }
        if !outcome.errors.is_empty() {
            println!("{} finding(s) could not be adopted:", outcome.errors.len());
            for e in &outcome.errors {
                println!("  - {e}");
            }
        }
        if !outcome.adopted.is_empty() {
            println!();
            println!("Replace whatever sourced these values with:");
            println!("  hearth-vault exec --prefix {prefix_str} -- <your command>");
        }
    }

    Ok(())
}

const SHELL_INIT_COMMENT: &str = r#"# hearth-vault shell integration
#
# WHY THIS DOES NOT EXPORT SECRETS INTO YOUR SHELL:
# Anything `export`ed into this interactive shell is inherited by every
# child process it starts from here on -- including any coding agent you
# launch from this terminal. That is strictly worse than a .env file: a
# .env file only leaks if something reads it off disk, while an exported
# shell variable is silently forwarded into every subprocess and agent
# tool call in this session whether or not it ever needed it.
#
# Instead this defines a wrapper, `hv`, that hands this project's vault
# secrets to exactly ONE command via `hearth-vault exec` and lets them die
# with that command's environment. The shell itself never holds a real
# value.
#
# Usage:
#   hv npm run dev
#   hv ./deploy.sh"#;

fn cmd_shell_init(shell: ShellKind) {
    match shell {
        ShellKind::Bash | ShellKind::Zsh => {
            println!("{SHELL_INIT_COMMENT}");
            println!("hv() {{");
            println!("    hearth-vault exec --prefix \"$(hearth-vault project-prefix)\" -- \"$@\"");
            println!("}}");
        }
        ShellKind::Fish => {
            println!("{SHELL_INIT_COMMENT}");
            println!("function hv");
            println!("    hearth-vault exec --prefix (hearth-vault project-prefix) -- $argv");
            println!("end");
        }
    }
}

/// Parse a `.hearth-vault` marker line tolerantly. The current format is a
/// bare prefix on its own line (`myapp/`), but users may still have the
/// older `prefix = myapp/` form lying around (copy-pasted from an old doc,
/// an old scan's output, etc.), so both are accepted: an optional leading
/// `prefix` keyword (only stripped when followed by whitespace or `=`, so a
/// literal prefix that happens to start with the word "prefix" survives
/// intact), an optional `=`, and optional surrounding quotes.
fn parse_project_prefix_line(line: &str) -> String {
    let mut s = line.trim();
    if let Some(rest) = s.strip_prefix("prefix") {
        let looks_like_keyword =
            rest.is_empty() || rest.starts_with(char::is_whitespace) || rest.starts_with('=');
        if looks_like_keyword {
            s = rest.trim_start();
            if let Some(rest2) = s.strip_prefix('=') {
                s = rest2.trim_start();
            }
        }
    }
    s = s.trim();
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            s = &s[1..s.len() - 1];
        }
    }
    s.trim().to_string()
}

/// Walk up from `start` looking for a `.hearth-vault` project marker file.
/// Split out from [`find_project_marker`] as a pure function of a starting
/// path so it's unit-testable without changing the test process's actual
/// working directory.
fn find_project_marker_from(start: &Path) -> Option<PathBuf> {
    let mut dir = start.to_path_buf();
    loop {
        let candidate = dir.join(".hearth-vault");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            return None;
        }
    }
}

/// Walk up from the current directory looking for a `.hearth-vault` project
/// marker file.
fn find_project_marker() -> Option<PathBuf> {
    find_project_marker_from(&std::env::current_dir().ok()?)
}

/// Read a `.hearth-vault` marker file at `marker_path` and return its
/// resolved prefix. Split out from [`cmd_project_prefix`] so the parsing
/// logic is unit-testable independent of `find_project_marker`'s reliance on
/// the process's actual current directory.
fn read_project_prefix(marker_path: &Path) -> anyhow::Result<String> {
    let content = fs::read_to_string(marker_path)?;
    content
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('#'))
        .map(parse_project_prefix_line)
        .filter(|p| !p.is_empty())
        .ok_or_else(|| anyhow::anyhow!("{} has no usable prefix line", marker_path.display()))
}

fn cmd_project_prefix() -> anyhow::Result<()> {
    let marker = find_project_marker().ok_or_else(|| {
        let cwd = std::env::current_dir()
            .map(|d| d.display().to_string())
            .unwrap_or_else(|_| ".".to_string());
        anyhow::anyhow!(
            "no .hearth-vault project marker found walking up from {cwd} \u{2014} run \
             `hearth-vault scan --adopt --prefix <name>/` once to create it, or by hand: \
             `echo \"<name>/\" > .hearth-vault`"
        )
    })?;

    println!("{}", read_project_prefix(&marker)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn make_test_store() -> (TempDir, VaultStore) {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("vault.json");
        let store = VaultStore::open_at_with_passphrase(path, "test-passphrase").unwrap();
        (dir, store)
    }

    /// Regression coverage for the historical rename data-destruction bug
    /// (renaming used to invoke `SensitiveString::to_string()`, which is
    /// `Display` and returns the redacted literal "***"). Rename now lives
    /// in `VaultStore::rename` (core-owned, frozen contract); this asserts
    /// main.rs's usage of it round-trips both value and tier correctly.
    #[test]
    fn rename_preserves_value_and_tier_via_store() {
        let (_tmp, mut store) = make_test_store();
        let original_value = "ghp_thisIsTheRealSecretValue123456789"; // hearth-vault:allow gitleaks:allow
        store
            .set(
                "GITHUB_TOKEN",
                &SensitiveString::new(original_value.to_string()),
                2,
            )
            .unwrap();

        store.rename("GITHUB_TOKEN", "auth/GITHUB_TOKEN").unwrap();

        let renamed = store
            .get("auth/GITHUB_TOKEN")
            .unwrap()
            .expect("renamed key should exist");
        assert_eq!(
            renamed.as_str(),
            original_value,
            "rename must preserve the original value byte-for-byte"
        );
        assert_ne!(renamed.as_str(), "***");
        assert!(store.get("GITHUB_TOKEN").unwrap().is_none());
        assert_eq!(store.tier_of("auth/GITHUB_TOKEN"), Some(2));
    }

    #[test]
    fn rename_missing_key_errors() {
        let (_tmp, mut store) = make_test_store();
        store
            .set("alpha", &SensitiveString::new("a".to_string()), 2)
            .unwrap();
        assert!(store.rename("no-such-key", "dest").is_err());
        // Store must be untouched.
        assert!(store.get("alpha").unwrap().is_some());
        assert!(store.get("dest").unwrap().is_none());
    }

    /// `VaultStore::tier_of` returns the right tier for a stored key and
    /// `None` for an absent one.
    #[test]
    fn store_tier_of_returns_correct_tier() {
        let (_tmp, mut store) = make_test_store();
        store
            .set("k1", &SensitiveString::new("v1".to_string()), 1)
            .unwrap();
        store
            .set("k2", &SensitiveString::new("v2".to_string()), 2)
            .unwrap();
        store
            .set("k3", &SensitiveString::new("v3".to_string()), 3)
            .unwrap();

        assert_eq!(store.tier_of("k1"), Some(1));
        assert_eq!(store.tier_of("k2"), Some(2));
        assert_eq!(store.tier_of("k3"), Some(3));
        assert_eq!(store.tier_of("missing"), None);
    }

    /// Confirms TIER_USE_ONLY is the policy boundary the implementation
    /// uses everywhere — so adjusting it in one place is honored.
    #[test]
    fn tier_use_only_is_three() {
        assert_eq!(TIER_USE_ONLY, 3);
    }

    /// tier_allows_export is the single source of truth for the export
    /// boundary used by export-env, export-env-file, and exec.
    #[test]
    fn tier_allows_export_boundary() {
        assert!(tier_allows_export(1));
        assert!(tier_allows_export(2));
        assert!(!tier_allows_export(3));
        assert!(!tier_allows_export(4));
    }

    /// Direct store.get() must STILL work for tier-3 keys — sign/derive
    /// operations need the bytes. Only export-* commands enforce the
    /// no-extraction policy at the CLI layer.
    #[test]
    fn store_get_succeeds_for_tier_three_keys() {
        let (_tmp, mut store) = make_test_store();
        store
            .set(
                "auth/secret",
                &SensitiveString::new("real-pem-bytes".to_string()),
                3,
            )
            .unwrap();

        let v = store.get("auth/secret").unwrap();
        assert!(v.is_some());
        assert_eq!(
            v.unwrap().as_str(),
            "real-pem-bytes",
            "store.get() must return real bytes for tier-3 keys so sign/derive operations work"
        );
    }

    #[test]
    fn sign_algorithm_parse_accepts_supported_algorithms() {
        for s in &["RSA-PSS-SHA256", "rsa-pss-sha256", "Rsa-Pss-Sha256"] {
            assert!(matches!(
                SignAlgorithm::parse(s).unwrap(),
                SignAlgorithm::RsaPssSha256
            ));
        }
        for s in &["RS256", "rs256", "Rs256"] {
            assert!(matches!(
                SignAlgorithm::parse(s).unwrap(),
                SignAlgorithm::Rs256
            ));
        }
        for s in &["RS512", "rs512"] {
            assert!(matches!(
                SignAlgorithm::parse(s).unwrap(),
                SignAlgorithm::Rs512
            ));
        }
    }

    #[test]
    fn sign_algorithm_parse_rejects_unknown() {
        for bad in &["", "MD5", "HS256", "ED25519", "RS384"] {
            assert!(
                SignAlgorithm::parse(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn sign_algorithm_jwt_classification() {
        assert!(SignAlgorithm::Rs256.is_jwt());
        assert!(SignAlgorithm::Rs512.is_jwt());
        assert!(!SignAlgorithm::RsaPssSha256.is_jwt());
    }

    /// Zero repos must yield no JSON body — preserves the pre-flag behavior
    /// where the POST goes out empty and GitHub returns a full-installation
    /// token. This is the backward-compat guarantee for existing callers.
    #[test]
    fn build_token_request_body_zero_repos_is_none() {
        let body = build_token_request_body(&[]).unwrap();
        assert!(
            body.is_none(),
            "zero repositories must produce no JSON body so callers without the flag keep working unchanged"
        );
    }

    /// Single repo → `{"repositories": ["myapp"]}`. The minted token will
    /// only have access to that one repo, not every repo on the installation.
    #[test]
    fn build_token_request_body_single_repo() {
        let body = build_token_request_body(&["myapp".to_string()])
            .unwrap()
            .expect("single repo should produce a JSON body");
        assert_eq!(body, serde_json::json!({"repositories": ["myapp"]}));
    }

    /// Multiple repos preserve order and produce a single repositories array.
    #[test]
    fn build_token_request_body_multiple_repos() {
        let body = build_token_request_body(&["myapp".to_string(), "myapp-infra".to_string()])
            .unwrap()
            .expect("multi-repo should produce a JSON body");
        assert_eq!(
            body,
            serde_json::json!({"repositories": ["myapp", "myapp-infra"]})
        );
    }

    /// An empty-string repo must hard-error BEFORE the API call. GitHub
    /// silently degrades `{"repositories": [""]}` to "full installation
    /// scope", which would defeat the entire point of this flag.
    #[test]
    fn build_token_request_body_rejects_empty_string() {
        let err = build_token_request_body(&["".to_string()]).unwrap_err();
        assert!(
            err.to_string().contains("must not be empty"),
            "expected explicit empty-string rejection, got: {err}"
        );
    }

    /// Whitespace-only is functionally equivalent to empty for GitHub's
    /// purposes; reject the same way so neither `--repository ""` nor
    /// `--repository "   "` slips through to widen scope.
    #[test]
    fn build_token_request_body_rejects_whitespace_only() {
        assert!(build_token_request_body(&["   ".to_string()]).is_err());
    }

    /// Mixed-validity input rejects rather than silently dropping the bad
    /// entry — fail loud rather than mint a token with surprising scope.
    #[test]
    fn build_token_request_body_rejects_when_any_entry_is_empty() {
        let err = build_token_request_body(&[
            "myapp".to_string(),
            "".to_string(),
            "myapp-infra".to_string(),
        ])
        .unwrap_err();
        assert!(err.to_string().contains("must not be empty"));
    }

    // ---- non-TTY refusal ----

    /// Piped stdout with no override must be refused.
    #[test]
    fn should_refuse_non_tty_blocks_pipes_without_override() {
        assert!(should_refuse_non_tty(false, false));
    }

    /// A real terminal is always allowed, override or not.
    #[test]
    fn should_refuse_non_tty_allows_terminal() {
        assert!(!should_refuse_non_tty(true, false));
        assert!(!should_refuse_non_tty(true, true));
    }

    /// The escape hatch lets a non-TTY caller through.
    #[test]
    fn should_refuse_non_tty_allows_override() {
        assert!(!should_refuse_non_tty(false, true));
    }

    // ---- env-name mapping ----

    #[test]
    fn env_name_for_strips_prefix_uppercases_and_replaces_separators() {
        // Both `/` and `-` become `_` so the result is a valid POSIX env name
        // that Go's os.Getenv("DATABASE_URL") / ("API_KEY") will find.
        assert_eq!(env_name_for("myapp/database-url", "myapp/"), "DATABASE_URL");
        assert_eq!(
            env_name_for("myapp/stripe-secret-key", "myapp/"),
            "STRIPE_SECRET_KEY"
        );
        assert_eq!(
            env_name_for("myapp/stripe-api-key-id", "myapp/"),
            "STRIPE_API_KEY_ID"
        );
        assert_eq!(env_name_for("myapp/sub/api-key", "myapp/"), "SUB_API_KEY");
        // No prefix match → whole key transformed.
        assert_eq!(env_name_for("plain-key", "other/"), "PLAIN_KEY");
    }

    // ---- export-env-file content ----

    /// A single-line tier-2 secret exports to one `NAME=value` line.
    #[test]
    fn collect_export_lines_single_line_ok() {
        let (_tmp, mut store) = make_test_store();
        store
            .set(
                "app/db-url",
                &SensitiveString::new("postgres://x".to_string()),
                2,
            )
            .unwrap();
        let (lines, skipped) = collect_export_lines(&store, "app/").unwrap();
        assert!(skipped.is_empty());
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].line, "DB_URL=postgres://x");
        assert_eq!(lines[0].env_name, "DB_URL");
    }

    /// A multi-line value (PEM) is written verbatim — this path is the
    /// legitimate systemd/service injection into an owner-only-perms file,
    /// and refusing it would also drop single-line keys like DATABASE_URL.
    /// The non-TTY refusal, not a writer-side check, is what prevents the
    /// agent-spill case for this command.
    #[test]
    fn collect_export_lines_writes_multiline_verbatim() {
        let (_tmp, mut store) = make_test_store();
        let pem = "-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"; // hearth-vault:allow gitleaks:allow
        store
            .set(
                "app/db-url",
                &SensitiveString::new("postgres://x".to_string()),
                2,
            )
            .unwrap();
        store
            .set("app/key", &SensitiveString::new(pem.to_string()), 2)
            .unwrap();
        let (lines, _skipped) = collect_export_lines(&store, "app/").unwrap();
        // Both keys export; the single-line one is not dropped by the PEM's presence.
        assert_eq!(lines.len(), 2);
        let key_line = lines.iter().find(|l| l.env_name == "KEY").unwrap();
        assert_eq!(key_line.line, format!("KEY={pem}"));
        assert!(lines.iter().any(|l| l.env_name == "DB_URL"));
    }

    /// Tier-3 keys are skipped (not exported), never spilled.
    #[test]
    fn collect_export_lines_skips_tier_three() {
        let (_tmp, mut store) = make_test_store();
        store
            .set("app/pubcfg", &SensitiveString::new("ok".to_string()), 2)
            .unwrap();
        store
            .set(
                "app/privkey",
                &SensitiveString::new("secret".to_string()),
                3,
            )
            .unwrap();
        let (lines, skipped) = collect_export_lines(&store, "app/").unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].env_name, "PUBCFG");
        assert_eq!(skipped, vec!["app/privkey".to_string()]);
    }

    // ---- exec env injection ----

    /// exec injects everything below sign-only — including tier-3 use-only,
    /// which is the default tier and must stay usable. Only tier-4 sign-only
    /// keys are withheld. Unlike export-env-file it tolerates multi-line
    /// values (they go to a child env, never a file/stdout).
    #[test]
    fn collect_exec_env_injects_use_only_and_skips_sign_only() {
        let (_tmp, mut store) = make_test_store();
        store
            .set(
                "svc/db-url",
                &SensitiveString::new("postgres://y".to_string()),
                2,
            )
            .unwrap();
        store
            .set(
                "svc/pem",
                &SensitiveString::new("-----BEGIN-----\nline2\n-----END-----".to_string()),
                2,
            )
            .unwrap();
        // Tier 3 (use-only, the default): unprintable, but exec must still
        // inject it — otherwise `import-env` → `exec` silently injects nothing.
        store
            .set(
                "svc/api-token",
                &SensitiveString::new("tok".to_string()),
                TIER_USE_ONLY,
            )
            .unwrap();
        // Tier 4 (sign-only): never leaves the vault process at all.
        store
            .set(
                "svc/signing-key",
                &SensitiveString::new("nope".to_string()),
                TIER_SIGN_ONLY,
            )
            .unwrap();

        let (injected, skipped) = collect_exec_env(&store, "svc/").unwrap();
        assert_eq!(skipped, vec!["svc/signing-key".to_string()]);

        let names: Vec<&str> = injected.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"DB_URL"));
        assert!(
            names.contains(&"API_TOKEN"),
            "tier-3 use-only is the default tier and must be exec-injectable"
        );
        assert!(
            names.contains(&"PEM"),
            "multi-line value is allowed for exec injection"
        );

        let pem = injected.iter().find(|(n, _)| n == "PEM").unwrap();
        assert!(
            pem.1.as_str().contains('\n'),
            "exec preserves the multi-line value verbatim"
        );
    }

    // ---- dotenv parser ----

    #[test]
    fn parse_dotenv_basic_and_export_prefix() {
        let input = "FOO=bar\nexport BAZ=qux\n";
        let pairs = parse_dotenv(input);
        assert_eq!(
            pairs,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAZ".to_string(), "qux".to_string()),
            ]
        );
    }

    #[test]
    fn parse_dotenv_skips_comments_and_blank_lines() {
        let input = "# a comment\n\nFOO=bar\n   \n# another\nBAZ=qux\n";
        let pairs = parse_dotenv(input);
        assert_eq!(
            pairs,
            vec![
                ("FOO".to_string(), "bar".to_string()),
                ("BAZ".to_string(), "qux".to_string()),
            ]
        );
    }

    #[test]
    fn parse_dotenv_quoted_values() {
        let input = "SINGLE='hello world'\nDOUBLE=\"hi there\"\nEMPTY=\"\"\n";
        let pairs = parse_dotenv(input);
        assert_eq!(pairs[0], ("SINGLE".to_string(), "hello world".to_string()));
        assert_eq!(pairs[1], ("DOUBLE".to_string(), "hi there".to_string()));
        assert_eq!(pairs[2], ("EMPTY".to_string(), "".to_string()));
    }

    #[test]
    fn parse_dotenv_equals_inside_value() {
        let input = "URL=postgres://user:pass@host/db?sslmode=require\n"; // hearth-vault:allow gitleaks:allow
        let pairs = parse_dotenv(input);
        assert_eq!(
            pairs[0],
            (
                "URL".to_string(),
                "postgres://user:pass@host/db?sslmode=require".to_string() // hearth-vault:allow gitleaks:allow
            )
        );
    }

    #[test]
    fn parse_dotenv_double_quoted_escapes() {
        let input = "MULTI=\"line one\\nline two\"\nESC=\"a\\\"b\"\n";
        let pairs = parse_dotenv(input);
        assert_eq!(
            pairs[0],
            ("MULTI".to_string(), "line one\nline two".to_string())
        );
        assert_eq!(pairs[1], ("ESC".to_string(), "a\"b".to_string()));
    }

    // ── scan --adopt: .env rewriting ─────────────────────────────────

    fn temp_vault_at(dir: &Path) -> PathBuf {
        dir.join("vault.json")
    }

    /// `adopt_findings` opens the vault via `open_vault`, which (absent a
    /// sealed passphrase) reads `HEARTH_VAULT_PASSPHRASE` before falling
    /// back to an interactive prompt neither test harness nor CI has a TTY
    /// to answer. This sets that env var for the lifetime of the guard and
    /// always restores it on drop (including on panic, since this crate's
    /// dev profile unwinds), so a failing assertion never leaks the
    /// override into a sibling test. Combine with `#[serial(hearth_vault_passphrase_env)]`
    /// on every test that uses it — `std::env` is process-global, and
    /// `cargo test` runs tests in parallel by default.
    struct PassphraseEnvGuard;

    impl PassphraseEnvGuard {
        fn set(passphrase: &str) -> Self {
            // SAFETY: serialized against other env-var mutators of this key
            // via #[serial(hearth_vault_passphrase_env)] on every caller.
            unsafe {
                std::env::set_var("HEARTH_VAULT_PASSPHRASE", passphrase);
            }
            Self
        }
    }

    impl Drop for PassphraseEnvGuard {
        fn drop(&mut self) {
            // SAFETY: see `set` above.
            unsafe {
                std::env::remove_var("HEARTH_VAULT_PASSPHRASE");
            }
        }
    }

    #[test]
    #[serial_test::serial(hearth_vault_passphrase_env)]
    fn adopt_rewrites_env_file_line_and_stores_the_value_in_the_vault() {
        let _env = PassphraseEnvGuard::set("test-pw");
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        let secret = "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1w"; // hearth-vault:allow gitleaks:allow
        fs::write(
            &env_path,
            format!("KEEPME=plain\nOPENAI_API_KEY={secret}\n"),
        )
        .unwrap();

        let findings = hearth_vault::scan::scan_path(&env_path).unwrap();
        assert!(
            !findings.is_empty(),
            "fixture must actually trip a rule for this test to mean anything"
        );

        let vault_path = temp_vault_at(dir.path());
        let outcome = adopt_findings(vault_path.clone(), None, &findings, "myapp/", false).unwrap();

        assert_eq!(outcome.adopted.len(), 1);
        assert!(outcome.skipped_source.is_empty());
        assert!(outcome.errors.is_empty());
        let stored_key = &outcome.adopted[0];
        assert!(stored_key.starts_with("myapp/"));

        // The value actually landed in the vault under the reported key...
        let store = VaultStore::open_at_with_passphrase(vault_path, "test-pw").unwrap();
        assert_eq!(store.get(stored_key).unwrap().unwrap().as_str(), secret);

        // ...and the secret is GONE from the file. Commenting the original
        // line out is not good enough: the plaintext would still be one `cat`
        // away, which is exactly the exposure adopting is meant to remove.
        let rewritten = fs::read_to_string(&env_path).unwrap();
        assert!(rewritten.contains("KEEPME=plain"), "{rewritten}");
        assert!(
            !rewritten.contains(secret),
            "the secret value must not survive anywhere in the file, \
             commented or otherwise: {rewritten}"
        );
        assert!(
            rewritten.contains("OPENAI_API_KEY -> hearth-vault:"),
            "should leave a pointer naming where the value went: {rewritten}"
        );
    }

    #[test]
    #[serial_test::serial(hearth_vault_passphrase_env)]
    fn adopt_skips_source_code_findings_without_rewriting() {
        let _env = PassphraseEnvGuard::set("test-pw");
        let dir = TempDir::new().unwrap();
        let src_path = dir.path().join("config.rs");
        let secret = "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1w"; // hearth-vault:allow gitleaks:allow
        let original = format!("let key = \"{secret}\";\n");
        fs::write(&src_path, &original).unwrap();

        let findings = hearth_vault::scan::scan_path(&src_path).unwrap();
        assert!(!findings.is_empty());

        let vault_path = temp_vault_at(dir.path());
        let outcome = adopt_findings(vault_path, None, &findings, "myapp/", false).unwrap();

        assert!(outcome.adopted.is_empty());
        assert!(!outcome.skipped_source.is_empty());
        // Source code must never be rewritten by --adopt.
        let unchanged = fs::read_to_string(&src_path).unwrap();
        assert_eq!(unchanged, original);
    }

    #[test]
    #[serial_test::serial(hearth_vault_passphrase_env)]
    fn adopt_does_not_overwrite_existing_key_without_force() {
        let _env = PassphraseEnvGuard::set("test-pw");
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join(".env");
        let secret = "sk-proj-aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1w"; // hearth-vault:allow gitleaks:allow
        fs::write(&env_path, format!("OPENAI_API_KEY={secret}\n")).unwrap();

        let vault_path = temp_vault_at(dir.path());
        // Pre-seed the destination key via the vault directly.
        {
            let mut store =
                VaultStore::open_at_with_passphrase(vault_path.clone(), "test-pw").unwrap();
            store
                .set(
                    "myapp/openai/api_key",
                    &SensitiveString::new("pre-existing".to_string()),
                    TIER_USE_ONLY,
                )
                .unwrap();
            store.save().unwrap();
        }

        let findings = hearth_vault::scan::scan_path(&env_path).unwrap();
        let outcome = adopt_findings(vault_path, None, &findings, "myapp/", false).unwrap();

        assert!(outcome.adopted.is_empty());
        assert!(!outcome.skipped_existing.is_empty());
    }

    // ── marker-file resolution ────────────────────────────────────────

    #[test]
    fn find_project_marker_resolves_walking_up_from_a_subdirectory() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".hearth-vault"), "myapp/\n").unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        fs::create_dir_all(&nested).unwrap();

        let found = find_project_marker_from(&nested).expect("marker should be found");
        assert_eq!(found, dir.path().join(".hearth-vault"));
    }

    #[test]
    fn find_project_marker_returns_none_when_absent() {
        let dir = TempDir::new().unwrap();
        let nested = dir.path().join("x").join("y");
        fs::create_dir_all(&nested).unwrap();
        assert!(find_project_marker_from(&nested).is_none());
    }

    #[test]
    fn read_project_prefix_accepts_bare_prefix_form() {
        let dir = TempDir::new().unwrap();
        let marker = dir.path().join(".hearth-vault");
        fs::write(&marker, "myapp/\n").unwrap();
        assert_eq!(read_project_prefix(&marker).unwrap(), "myapp/");
    }

    #[test]
    fn read_project_prefix_accepts_legacy_prefix_equals_form() {
        let dir = TempDir::new().unwrap();
        let marker = dir.path().join(".hearth-vault");
        fs::write(&marker, "prefix = myapp/\n").unwrap();
        assert_eq!(read_project_prefix(&marker).unwrap(), "myapp/");
    }

    #[test]
    fn read_project_prefix_accepts_quoted_and_comment_lines() {
        let dir = TempDir::new().unwrap();
        let marker = dir.path().join(".hearth-vault");
        fs::write(&marker, "# a comment\nprefix=\"myapp/\"\n").unwrap();
        assert_eq!(read_project_prefix(&marker).unwrap(), "myapp/");
    }

    #[test]
    fn parse_project_prefix_line_does_not_mangle_a_literal_prefix_value() {
        // A bare prefix that happens to start with the word "prefix" must
        // survive intact -- only the keyword form ("prefix" followed by
        // whitespace or '=') is stripped.
        assert_eq!(parse_project_prefix_line("prefixed-app/"), "prefixed-app/");
    }
}
