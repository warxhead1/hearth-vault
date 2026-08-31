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
use hearth_vault::redact::Redactor;
use hearth_vault::{RotationState, SensitiveString, TIER_SIGN_ONLY, TIER_USE_ONLY, VaultStore};
use zeroize::{Zeroize, Zeroizing};

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
    /// auto-detection: tpm2, keyring, or systemd-creds.
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
        /// 3 = use-only, never printed but usable via `exec` (default for a
        /// NEW key), 4 = sign-only, never printed and never injected —
        /// `sign` only.
        ///
        /// Omit it when rotating: overwriting an existing key keeps that
        /// key's current tier, so putting a fresh value behind an existing
        /// name cannot silently change who is allowed to read it.
        #[arg(short, long)]
        tier: Option<u8>,
        /// Rotation policy: remind me to replace this every N days. Stored
        /// with the key, so every later `set` of the same name pushes the
        /// due date forward automatically — rotating IS storing a new value,
        /// there is no separate "mark rotated" step to forget. `--rotate-days
        /// 0` clears an existing policy.
        #[arg(long, value_name = "N")]
        rotate_days: Option<u32>,
        /// Pin an exact due date instead of a recurring policy, for
        /// credentials whose lifetime the provider dictates (a 90-day cloud
        /// token). Accepts RFC3339 (`2026-12-01T00:00:00Z`) or a relative
        /// `30d` / `12w`. A negative offset (`-7d`) marks something already
        /// overdue, which is how you flag a credential you know is stale
        /// while you queue up the rotation.
        ///
        /// `allow_hyphen_values` is what lets `-7d` through: without it clap
        /// reads the leading `-` as the start of another flag.
        #[arg(long, value_name = "WHEN", allow_hyphen_values = true)]
        expires: Option<String>,
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
    List {
        /// Machine-readable output, for scripts and dashboards. Metadata
        /// only — there is no flag anywhere that makes `list` emit values.
        #[arg(long)]
        json: bool,
        /// Show only credentials that are overdue for rotation, or due
        /// within N days. Exits 1 if any are listed, so it drops straight
        /// into a cron job or a CI step.
        #[arg(long, value_name = "DAYS", num_args = 0..=1, default_missing_value = "0")]
        due: Option<i64>,
    },
    /// Check if a credential exists
    Has { key: String },
    /// Delete a credential.
    ///
    /// Takes an encrypted snapshot of the whole vault first (see `backup`),
    /// because the recovery mnemonic restores the vault *key*, not entries
    /// you removed — without a snapshot, one mistyped key name is
    /// unrecoverable.
    Delete {
        key: String,
        /// Skip the automatic pre-delete snapshot.
        #[arg(long)]
        no_backup: bool,
    },
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
    /// Initialize a headless machine-local vault without printing a
    /// passphrase or recovery phrase. The random passphrase is sealed to the
    /// selected host backend; the recovery phrase is written only inside an
    /// encrypted hearth-vault bundle addressed to an existing identity.
    InitMachine {
        /// Existing `hearth-vault identity` that alone can open the recovery bundle.
        #[arg(long, value_name = "HV1_IDENTITY")]
        recovery_recipient: String,
        /// New encrypted `.hvs` bundle path. Refuses to overwrite.
        #[arg(long, value_name = "PATH")]
        recovery_output: PathBuf,
    },
    /// Show vault status (backend type, path, permissions, rotations due)
    Status {
        /// Machine-readable output for monitoring.
        #[arg(long)]
        json: bool,
    },
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
    /// Every key under `--prefix` below tier 4 is resolved to an env var
    /// (same name mapping as export-env-file: strip prefix, uppercase, `/`
    /// and `-` → `_`) and added to the child's environment; then the command
    /// is exec'd. Tier 3 (use-only, the default for new secrets) IS injected
    /// here — that is the entire point of this command, and the reason a
    /// tier-3 key can be used without ever being printed. Only tier-4
    /// (sign-only) keys are skipped; use `sign` for those.
    ///
    /// Example:
    ///   hearth-vault exec --prefix myapp/ -- ./start-server --port 8080
    Exec {
        /// Inject keys starting with this prefix (e.g. "myapp/").
        ///
        /// Optional: when omitted, falls back to $HEARTH_VAULT_PREFIX (what
        /// the direnv integration sets), then to the nearest `.hearth-vault`
        /// marker file walking up from the current directory. In a project
        /// with a marker, `hearth-vault exec -- npm run dev` just works —
        /// and an agent does not have to guess or hardcode a prefix.
        #[arg(short, long)]
        prefix: Option<String>,
        /// Scrub every injected secret VALUE (and its URL-percent-encoded
        /// form) out of the child's stdout and stderr before it reaches the
        /// caller, replacing each occurrence with `<vault:KEY_NAME>`.
        ///
        /// OFF BY DEFAULT — equivalent env var: HEARTH_VAULT_REDACT=1. This
        /// kills a real incident class: an API echoing an injected key back
        /// in a response body, or a script that interpolates a DSN password
        /// into its own log line, both land in whatever reads the child's
        /// output (a human terminal, or — the case this exists for — an
        /// agent transcript that gets transmitted off-box).
        ///
        /// Do NOT turn this on for a consumer that CAPTURES exec's output as
        /// the value itself — e.g. `VAR="$(hearth-vault exec ... sh -c
        /// 'printf %s "$VAR"')"`, the pattern tachyonac-engine's
        /// deploy/deploy.sh and scripts/devdb.sh both use. `--redact` would
        /// silently hand that capture the literal string `<vault:VAR>`
        /// instead of the real value, breaking the consumer outright. It is
        /// for the "the child prints logs/output I might read or forward"
        /// case, not the "I need the value back" case — that case is what
        /// plain `exec` (no flag) is for.
        ///
        /// Values under 8 bytes are never redacted (too collision-prone to
        /// distinguish from ordinary output). Forces stdout/stderr to be
        /// captured through a pipe rather than inherited directly from the
        /// terminal — for a fully interactive child (e.g. one reading raw
        /// terminal input/resize events) this can change behavior; plain
        /// `exec` still gives an unmodified TTY passthrough.
        #[arg(long)]
        redact: bool,
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
    ///
    /// This is the one subcommand that talks to the network, so it is the one
    /// subcommand behind a feature flag. Built without `github-app-token`,
    /// there is no HTTP client in the binary at all.
    #[cfg(feature = "github-app-token")]
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
        /// Scan only the files staged in git (`git diff --cached`). This is
        /// what the installed pre-commit hook runs: it checks exactly what
        /// you are about to commit, in the second before it becomes history.
        #[arg(long)]
        staged: bool,
    },
    /// Install hearth-vault's secret scan as a git pre-commit hook in this
    /// repository, so a key can't reach history by accident.
    ///
    /// A secret caught here costs you ten seconds. The same secret caught
    /// after a push costs you a rotation, a force-push that does not really
    /// erase it, and a conversation with whoever mirrors your repo.
    InstallHook {
        /// Repository root (default: current directory)
        path: Option<String>,
        /// Overwrite an existing pre-commit hook (it is backed up first)
        #[arg(long)]
        force: bool,
    },
    /// Print a `direnv` integration snippet for `~/.config/direnv/direnvrc`.
    ///
    /// Note what it does and does not do: entering a project directory
    /// exports HEARTH_VAULT_PREFIX (a *name*, not a secret) so bare
    /// `hearth-vault exec -- <cmd>` works there. It deliberately does not
    /// export your secrets into the interactive shell — that would undo the
    /// entire point of the tool, and direnv makes it far too easy to do by
    /// accident.
    DirenvInit,
    /// Run a short-lived unlock cache so repeated commands don't each pay
    /// the ~120ms Argon2id derivation.
    ///
    /// This replaces `export HEARTH_VAULT_PASSPHRASE=$(hearth-vault prompt)`,
    /// which put your passphrase into an environment variable that every
    /// child process — including coding agents — inherits. The agent holds a
    /// derived wrap key instead, for a bounded time, in a process only you
    /// can talk to.
    ///
    /// Example: hearth-vault agent --daemon && hearth-vault unlock
    Agent {
        /// How long a cached key survives, in seconds.
        #[arg(long, default_value_t = 900)]
        ttl: u64,
        /// Fork into the background instead of running in the foreground.
        #[arg(long)]
        daemon: bool,
        /// Forget every cached key, leaving the agent running.
        #[arg(long)]
        drop: bool,
        /// Shut the agent down.
        #[arg(long)]
        stop: bool,
        /// Report whether an agent is running and how many keys it holds.
        #[arg(long)]
        status: bool,
    },
    /// Prompt for the passphrase once and hand the derived key to a running
    /// agent. Every later command against this vault is then instant until
    /// the agent's TTL expires.
    Unlock,
    /// Forget every key cached by the agent, right now. The panic button,
    /// and what you run when you step away from the machine.
    Lock,
    /// Write an encrypted snapshot of the vault.
    ///
    /// No passphrase needed: the vault file is already encrypted at rest, so
    /// a backup is a copy, and a copy you cannot make without unlocking is a
    /// copy you will not make. Restoring, of course, still needs the
    /// passphrase (or the recovery mnemonic) that the snapshot was made
    /// under — a backup taken before a `change-passphrase` opens with the
    /// OLD one.
    Backup {
        /// Destination directory or file (default: alongside the vault)
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Replace the current vault with a snapshot.
    ///
    /// The snapshot is verified to open with the passphrase you supply
    /// BEFORE anything is overwritten, and the vault being replaced is
    /// itself backed up first. A restore that leaves you with neither vault
    /// is the one outcome this must never produce.
    Restore {
        /// Snapshot file to restore from
        file: String,
    },
    /// Print this vault's public sharing identity — the string a teammate
    /// needs to send you credentials. Not a secret; paste it anywhere.
    ///
    /// The matching private key is derived from your data key and is never
    /// stored, so there is nothing extra to back up and a restored vault
    /// keeps the same identity.
    Identity,
    /// Seal credentials to a teammate's identity, producing a bundle file
    /// that only they can open. Safe to send over Slack, email, or a PR.
    ///
    /// Confirm their fingerprint out of band first: a bundle proves only
    /// that its maker knew the recipient's public key, not who made it.
    ///
    /// Example: hearth-vault share --prefix myapp/ --to hv1pubAbC... --output staging.hvs
    Share {
        /// Share every key under this prefix
        #[arg(short, long)]
        prefix: String,
        /// Recipient's identity string (from their `hearth-vault identity`)
        #[arg(long)]
        to: String,
        /// Bundle file to write (default: stdout is NOT used — a path is
        /// required, because a bundle is a file you send, not something to
        /// paste through a terminal)
        #[arg(short, long)]
        output: String,
        /// Floor the recipient's tier at this value: `--max-tier 4` shares a
        /// signing key they can `sign` with but never inject or print. Tier
        /// is only ever made stricter, never looser.
        #[arg(long)]
        max_tier: Option<u8>,
        /// A note for the recipient (shown by `receive --dry-run`). Never
        /// put a credential in here.
        #[arg(long)]
        note: Option<String>,
    },
    /// Open a bundle a teammate shared with you and store its entries in
    /// your own vault.
    Receive {
        /// Bundle file to open
        file: String,
        /// Show what the bundle contains (key names and tiers, never
        /// values) without storing anything.
        #[arg(long)]
        dry_run: bool,
        /// Store the entries under a different prefix than the sender used.
        #[arg(long)]
        prefix: Option<String>,
        /// Overwrite keys that already exist in your vault
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
    // BOTH streams, not just stdout. Values go to stdout, but the recovery
    // mnemonic banner and every warning go to stderr -- so checking stdout
    // alone let `hearth-vault init 2>mnemonic.log` write the 24 words that
    // unlock the whole vault into a plaintext file from an ordinary
    // interactive terminal. A human at a real terminal has both; a redirect
    // of either is the case this guard exists to refuse.
    let both_are_tty = platform::stdout_is_tty() && platform::stderr_is_tty();
    let allow_override =
        std::env::var("HEARTH_VAULT_ALLOW_NON_TTY").is_ok_and(|v| v != "0" && !v.is_empty());
    if should_refuse_non_tty(both_are_tty, allow_override) {
        anyhow::bail!(
            "`{cmd}` writes a secret value and refuses to run with stdout or stderr redirected \
             (not a terminal). If this is an intentional systemd/CI invocation, set \
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

/// Resolve the secret backend for TPM2/keyring/systemd auto-unseal and `seal`.
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
/// 1. Host-protected auto-unseal (sealed blob next to the vault file,
///    unsealed via TPM2/keyring/systemd-creds — skipped entirely if no such
///    backend is available or nothing was ever sealed).
/// 2. HEARTH_VAULT_PASSPHRASE env var (session caching / SSH / tmux)
/// 3. Interactive prompt via rpassword
fn open_vault(vault_path: PathBuf, backend_name: Option<&str>) -> anyhow::Result<VaultStore> {
    let sealed_path = sealed_passphrase_path(&vault_path);

    if sealed_path.exists() {
        match resolve_backend(backend_name) {
            Ok(hsm) if hsm.tier() <= 2 => match fs::read(&sealed_path) {
                Ok(blob) => match hsm.unseal(&blob, "hearth-vault") {
                    Ok(passphrase_bytes) => {
                        match String::from_utf8(passphrase_bytes.to_vec()) {
                            Ok(passphrase) => {
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
                            // The unseal itself worked, so the boot chain is
                            // fine and re-sealing is the fix — but only if we
                            // say so. Staying quiet here sends the user
                            // hunting the TPM for a problem that isn't there.
                            // Never print the bytes: this is the passphrase.
                            Err(e) => eprintln!(
                                "Auto-unseal produced {} bytes that aren't valid UTF-8 ({e}) — \
                                 the sealed blob predates the current vault format or was written \
                                 by a different build. Re-seal with `hearth-vault seal`. \
                                 Falling back to passphrase.",
                                e.as_bytes().len()
                            ),
                        }
                    }
                    Err(e) => eprintln!("Auto-unseal failed (boot chain changed?): {e}"),
                },
                Err(e) => eprintln!(
                    "Sealed passphrase at {} exists but couldn't be read ({e}) — \
                     falling back to passphrase.",
                    sealed_path.display()
                ),
            },
            Ok(hsm) => {
                // A backend resolved but isn't hardware-backed; auto-unseal
                // isn't meaningful for it. Fall through to passphrase.
                note!(
                    "Backend {} is tier {} (not hardware-backed); skipping auto-unseal.",
                    hsm.name(),
                    hsm.tier()
                );
            }
            Err(e) => note!(
                "No secret backend available for auto-unseal ({e}); falling back to passphrase."
            ),
        }
    }

    // A running agent can supply the derived wrap key, skipping Argon2id.
    // A stale key (the vault was re-salted by `change-passphrase` since it
    // was cached) must not be fatal — fall through to the passphrase, which
    // is what a user who just changed it expects to be asked for.
    #[cfg(unix)]
    if let Some(key) = hearth_vault::agent::try_get(&vault_path) {
        match VaultStore::open_at_with_wrap_key(vault_path.clone(), &key) {
            Ok(store) => {
                note!("Vault unlocked via agent (no passphrase needed).");
                return Ok(store);
            }
            Err(_) => note!("Agent's cached key is stale for this vault; asking for passphrase."),
        }
    }

    let (passphrase, from_prompt) = match std::env::var("HEARTH_VAULT_PASSPHRASE") {
        Ok(p) if !p.is_empty() => (Zeroizing::new(p), false),
        _ => (
            Zeroizing::new(rpassword::prompt_password("Vault passphrase: ")?),
            true,
        ),
    };
    let store = VaultStore::open_at_with_passphrase(vault_path.clone(), &passphrase)?;

    // Having just paid for the derivation and proven the passphrase correct,
    // hand the result to an agent if one is listening. This deliberately
    // covers the env-var path too, so anyone still using the old
    // `HEARTH_VAULT_PASSPHRASE` pattern gets the speedup without changing
    // anything — and has one less reason to keep the passphrase in their
    // environment. Silent and best-effort: running without an agent is
    // normal, and this must never be why a command fails.
    #[cfg(unix)]
    if hearth_vault::agent::is_running()
        && let Ok(key) = VaultStore::derive_wrap_key(&vault_path, &passphrase)
        && hearth_vault::agent::try_put(&vault_path, &key)
        && from_prompt
    {
        note!("Cached in the agent — subsequent commands will not prompt.");
    }
    #[cfg(not(unix))]
    let _ = from_prompt;

    Ok(store)
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
        Commands::InitMachine {
            recovery_recipient,
            recovery_output,
        } => cmd_init_machine(vault_path, backend, &recovery_recipient, &recovery_output)?,
        Commands::Set {
            keys,
            tier,
            rotate_days,
            expires,
        } => cmd_set(vault_path, backend, &keys, tier, rotate_days, expires)?,
        Commands::Import { file, key, tier } => cmd_import(vault_path, backend, &file, &key, tier)?,
        Commands::ImportEnv {
            file,
            prefix,
            tier,
            keep,
            force,
        } => cmd_import_env(vault_path, backend, file, prefix, tier, keep, force)?,
        Commands::Migrate => cmd_migrate()?,
        Commands::List { json, due } => cmd_list(vault_path, backend, json, due)?,
        Commands::Has { key } => cmd_has(vault_path, backend, &key)?,
        Commands::Delete { key, no_backup } => cmd_delete(vault_path, backend, &key, no_backup)?,
        Commands::Rename { from, to } => cmd_rename(vault_path, backend, &from, &to)?,
        Commands::Retier { key, tier } => cmd_retier(vault_path, backend, &key, tier)?,
        Commands::ExportEnv { key, env_name } => {
            cmd_export_env(vault_path, backend, &key, &env_name)?
        }
        Commands::Status { json } => cmd_status(vault_path, backend, json)?,
        Commands::Recover => cmd_recover(vault_path)?,
        Commands::ChangePassphrase => cmd_change_passphrase(vault_path, backend)?,
        Commands::NewRecoveryKey => cmd_new_recovery_key(vault_path)?,
        Commands::Prompt => cmd_prompt(vault_path)?,
        Commands::Seal => cmd_seal(vault_path, backend)?,
        Commands::ExportEnvFile { prefix, output } => {
            cmd_export_env_file(vault_path, backend, &prefix, &output)?
        }
        Commands::Exec {
            prefix,
            redact,
            command,
        } => cmd_exec(vault_path, backend, prefix, redact, &command)?,
        Commands::Sign {
            key,
            algorithm,
            message,
        } => cmd_sign(vault_path, backend, &key, &algorithm, &message)?,
        #[cfg(feature = "github-app-token")]
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
            staged,
        } => cmd_scan(
            vault_path, backend, path, json, adopt, prefix, rules, force, staged,
        )?,
        Commands::ShellInit { shell } => cmd_shell_init(shell),
        Commands::ProjectPrefix => cmd_project_prefix()?,
        Commands::InstallHook { path, force } => cmd_install_hook(path, force)?,
        Commands::DirenvInit => cmd_direnv_init(),
        Commands::Agent {
            ttl,
            daemon,
            drop,
            stop,
            status,
        } => cmd_agent(ttl, daemon, drop, stop, status)?,
        Commands::Unlock => cmd_unlock(vault_path)?,
        Commands::Lock => cmd_lock()?,
        Commands::Backup { output } => cmd_backup(vault_path, output)?,
        Commands::Restore { file } => cmd_restore(vault_path, &file)?,
        Commands::Identity => cmd_identity(vault_path, backend)?,
        Commands::Share {
            prefix,
            to,
            output,
            max_tier,
            note,
        } => cmd_share(vault_path, backend, &prefix, &to, &output, max_tier, note)?,
        Commands::Receive {
            file,
            dry_run,
            prefix,
            force,
        } => cmd_receive(vault_path, backend, &file, dry_run, prefix, force)?,
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

fn cmd_init_machine(
    vault_path: PathBuf,
    backend: Option<&str>,
    recovery_recipient: &str,
    recovery_output: &Path,
) -> anyhow::Result<()> {
    if vault_path.exists() {
        anyhow::bail!("vault already exists at {}", vault_path.display());
    }
    if recovery_output.exists() {
        anyhow::bail!(
            "recovery output already exists at {}; refusing to overwrite",
            recovery_output.display()
        );
    }

    let hsm = resolve_backend(backend)?;
    if hsm.tier() > 2 {
        anyhow::bail!(
            "headless initialization requires a host-protected backend, got {} (tier {})",
            hsm.name(),
            hsm.tier()
        );
    }
    if let Some(parent) = vault_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = recovery_output.parent() {
        fs::create_dir_all(parent)?;
    }

    let random: [u8; 32] = hearth_vault::crypto::random_bytes();
    let passphrase = Zeroizing::new(
        random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>(),
    );
    let sealed_path = sealed_passphrase_path(&vault_path);

    let result = (|| -> anyhow::Result<()> {
        let mut store = VaultStore::open_at_with_passphrase(vault_path.clone(), &passphrase)?;
        let mnemonic = store.generate_recovery_key()?;
        store.save()?;

        let sealed_blob = hsm
            .seal(passphrase.as_bytes(), "hearth-vault")
            .map_err(|e| anyhow::anyhow!("seal failed: {e}"))?;
        platform::write_private(&sealed_path, &sealed_blob)?;

        let recovery_entry = vec![(
            "machine/recovery-mnemonic".to_string(),
            SensitiveString::new(mnemonic.to_string()),
            TIER_USE_ONLY,
        )];
        let bundle = hearth_vault::share::seal(
            &recovery_entry,
            recovery_recipient,
            Some(TIER_USE_ONLY),
            Some("headless machine vault recovery; store separately from the host".to_string()),
        )?;
        let bundle_json = serde_json::to_vec_pretty(&bundle)?;
        platform::write_private(recovery_output, &bundle_json)?;
        Ok(())
    })();

    if let Err(error) = result {
        let _ = fs::remove_file(&vault_path);
        let _ = fs::remove_file(&sealed_path);
        let _ = fs::remove_file(recovery_output);
        return Err(error);
    }

    eprintln!("Machine vault initialized at {}.", vault_path.display());
    eprintln!(
        "Passphrase sealed through {} (tier {}); no secret value was printed.",
        hsm.name(),
        hsm.tier()
    );
    eprintln!(
        "Encrypted recovery bundle written to {}; move it off-host before adding credentials.",
        recovery_output.display()
    );
    Ok(())
}

fn cmd_set(
    vault_path: PathBuf,
    backend: Option<&str>,
    keys: &[String],
    tier: Option<u8>,
    rotate_days: Option<u32>,
    expires: Option<String>,
) -> anyhow::Result<()> {
    if keys.is_empty() {
        anyhow::bail!("provide at least one key name");
    }
    // Parsed before the prompt, not after: discovering that "30dd" is not a
    // duration should not cost you the retyping of a secret.
    let explicit_expiry = expires.as_deref().map(parse_when).transpose()?;

    // Single unlock for all keys
    let mut store = open_vault(vault_path, backend)?;

    let interactive = std::io::stdin().is_terminal();
    let mut stored_tiers: Vec<u8> = Vec::with_capacity(keys.len());

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

        // Rotation must not retier. An explicit --tier always wins; with no
        // flag, an existing key keeps the tier it already has and only a new
        // key gets the tier-3 default. Otherwise `set` on a tier-2 key --
        // the ordinary way to rotate a value -- would quietly promote it to
        // use-only and break whatever was reading it via export-env.
        let key_tier = tier.or_else(|| store.tier_of(key)).unwrap_or(TIER_USE_ONLY);

        let sensitive = SensitiveString::new(value.clone());
        value.zeroize();
        store.set(key, &sensitive, key_tier)?;

        // Order matters: `set` recomputes the due date from any EXISTING
        // policy, so a new policy must be applied after it, and an explicit
        // --expires after that, since it is the more specific instruction.
        if let Some(days) = rotate_days {
            // `--rotate-days 0` is how you clear a policy; a due date zero
            // days out would otherwise mean "overdue immediately".
            store.set_rotation(key, if days == 0 { None } else { Some(days) })?;
        }
        if let Some(ref when) = explicit_expiry {
            store.set_expiry(key, Some(when.clone()))?;
        }

        eprintln!("  \u{2713} {key} (tier {key_tier})");
        stored_tiers.push(key_tier);
    }

    store.save()?;
    eprintln!("Stored {} credential(s).", keys.len());
    for entry in store.list().iter().filter(|e| keys.contains(&e.key)) {
        if let Some(ref due) = entry.expires_at {
            eprintln!("  {} next due {}", entry.key, friendly_date(due));
        }
    }
    if stored_tiers.contains(&TIER_USE_ONLY) {
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

fn cmd_list(
    vault_path: PathBuf,
    backend: Option<&str>,
    json: bool,
    due: Option<i64>,
) -> anyhow::Result<()> {
    let store = open_vault(vault_path, backend)?;
    let mut entries = store.list();

    // `--due N` means "overdue, or coming due within N days". `--due` with
    // no number means overdue only.
    if let Some(window) = due {
        entries.retain(|e| match e.rotation_state() {
            RotationState::Overdue { .. } => true,
            RotationState::Ok { days_left } => days_left <= window,
            RotationState::NoPolicy => false,
        });
    }

    if json {
        let rows: Vec<_> = entries
            .iter()
            .map(|e| {
                serde_json::json!({
                    "key": e.key,
                    "tier": e.tier,
                    "created_at": e.created_at,
                    "updated_at": e.updated_at,
                    "rotate_days": e.rotate_days,
                    "expires_at": e.expires_at,
                    "rotation": rotation_word(e),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
    } else if entries.is_empty() {
        if due.is_some() {
            eprintln!("Nothing due for rotation.");
        } else {
            eprintln!("Vault is empty. Use 'hearth-vault set <key>' to add credentials.");
        }
        return Ok(());
    } else {
        // Dates, not full RFC3339: nanosecond timestamps are 32 characters
        // wide, which blew past the column and left the table ragged. Full
        // precision is still one `--json` away.
        println!(
            "{:<38} {:>4}  {:<12} {:<12} ROTATION",
            "KEY", "TIER", "CREATED", "UPDATED"
        );
        println!("{}", "-".repeat(88));
        for entry in &entries {
            println!(
                "{:<38} {:>4}  {:<12} {:<12} {}",
                entry.key,
                entry.tier,
                friendly_date(&entry.created_at),
                friendly_date(&entry.updated_at),
                rotation_word(entry)
            );
        }
        eprintln!("\n{} credential(s) stored.", entries.len());
    }

    // Non-zero when anything is due, so `hearth-vault list --due 7` is a
    // usable cron/CI check without parsing output.
    if due.is_some() && !entries.is_empty() {
        std::process::exit(1);
    }
    Ok(())
}

/// One-word rotation status for the `list` table and `--json`.
fn rotation_word(entry: &hearth_vault::VaultEntry) -> String {
    match entry.rotation_state() {
        RotationState::NoPolicy => "-".to_string(),
        RotationState::Overdue { days_over: 0 } => "DUE TODAY".to_string(),
        RotationState::Overdue { days_over } => format!("OVERDUE {days_over}d"),
        RotationState::Ok { days_left } => format!("due in {days_left}d"),
    }
}

/// Render an RFC3339 timestamp as a plain date. Rotation cadences are
/// measured in days; the seconds are noise in this context.
fn friendly_date(rfc3339: &str) -> String {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_else(|_| rfc3339.to_string())
}

/// Accept either an absolute RFC3339 instant or a relative `30d` / `12w` /
/// `6m` offset, because both are natural ways to say when a credential dies:
/// a provider gives you a date, a hygiene rule gives you a duration.
fn parse_when(input: &str) -> anyhow::Result<String> {
    let input = input.trim();
    if let Ok(absolute) = chrono::DateTime::parse_from_rfc3339(input) {
        return Ok(absolute.to_rfc3339());
    }
    if let Some(rest) = input.strip_suffix(['d', 'w', 'm', 'y']) {
        let n: i64 = rest.parse().map_err(|_| {
            anyhow::anyhow!("could not read '{input}' as a duration (try 30d, 12w, 6m, 1y)")
        })?;
        let days = match input.chars().last().expect("checked non-empty by strip") {
            'd' => n,
            'w' => n * 7,
            'm' => n * 30,
            _ => n * 365,
        };
        return Ok((chrono::Utc::now() + chrono::Duration::days(days)).to_rfc3339());
    }
    anyhow::bail!(
        "could not read '{input}' as a date — use RFC3339 (2026-12-01T00:00:00Z) \
         or a relative offset (30d, 12w, 6m, 1y)"
    )
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

fn cmd_delete(
    vault_path: PathBuf,
    backend: Option<&str>,
    key: &str,
    no_backup: bool,
) -> anyhow::Result<()> {
    let mut store = open_vault(vault_path.clone(), backend)?;
    if !store.has(key) {
        eprintln!("Key not found: {key}");
        std::process::exit(1);
    }

    // Snapshot before the removal, not after — and only once we know the key
    // exists, so a typo'd name does not litter the disk with snapshots.
    if !no_backup {
        match write_backup(&vault_path, None) {
            Ok(dest) => eprintln!("Snapshot before delete: {}", dest.display()),
            Err(e) => eprintln!("warning: could not snapshot before delete: {e}"),
        }
    }

    store.delete(key)?;
    store.save()?;
    eprintln!("Deleted: {key}");
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

    // Tier 4 is a one-way door, and it has to be, or it is not a tier at all.
    // Its entire promise is "this value is never printed and never injected --
    // only `sign` can use it". A `retier ... --tier 2` that walks that back
    // costs nothing and needs no secret, so without this refusal anything
    // able to run the binary could downgrade a signing key and then export it
    // in the next command. Re-adding the key requires possessing the value
    // again, which is exactly the proof of intent that should be required.
    if prev_tier == TIER_SIGN_ONLY && tier != TIER_SIGN_ONLY {
        anyhow::bail!(
            "refusing to lower '{key}' from tier {TIER_SIGN_ONLY} (sign-only) to tier {tier}.\n\
             Tier {TIER_SIGN_ONLY} means the value is never printed and never injected into any \
             process -- a downgrade would undo that with no proof you hold the value.\n\
             If you genuinely mean to, delete the key and store it again at the tier you want:\n\
             \n    hearth-vault delete {key}\n    hearth-vault set {key} --tier {tier}\n"
        );
    }

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
            "No host-protected backend available (need TPM2, an OS keyring, or root-owned systemd-creds; tier <= 2).\n\
             Current backend: {} (tier {})\n\
             Ensure TPM2 is accessible (/dev/tpmrm0), an OS keyring daemon is running, or use \
             --backend systemd-creds for a headless Linux root service.",
            hsm.name(),
            hsm.tier()
        );
    }

    // Get the passphrase to seal
    let passphrase = rpassword::prompt_password("Vault passphrase to seal: ")?;

    // Verify it opens the vault
    let _store = VaultStore::open_at_with_passphrase(vault_path.clone(), &passphrase)?;
    eprintln!("Passphrase verified against vault.");

    // Seal passphrase to the selected host-protected backend.
    let sealed_blob = hsm
        .seal(passphrase.as_bytes(), "hearth-vault")
        .map_err(|e| anyhow::anyhow!("seal failed: {e}"))?;

    // Write sealed blob to disk
    let sealed_path = sealed_passphrase_path(&vault_path);
    platform::write_private(&sealed_path, &sealed_blob)?;

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
        if let Err(e) = platform::restrict_dir_to_owner(parent) {
            eprintln!(
                "warning: could not restrict permissions on {}: {e}",
                parent.display()
            );
        }
    }

    // Write file. Owner-only from creation and via a rename, so the
    // plaintext is never briefly world-readable and a symlink planted at the
    // output path cannot redirect it (this file is the one place the tool
    // deliberately puts secrets on disk, so it gets the careful path).
    platform::write_private(&path, content.as_bytes())?;

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

/// True when `exec` should scrub injected secret values out of the child's
/// stdout/stderr: either `--redact` was passed, or the equivalent
/// `HEARTH_VAULT_REDACT` env var is set (same "unset/0/empty means no"
/// convention as `HEARTH_VAULT_VERBOSE`, see `verbose()`).
fn redact_requested(flag: bool) -> bool {
    flag || std::env::var("HEARTH_VAULT_REDACT").is_ok_and(|v| v != "0" && !v.is_empty())
}

fn cmd_exec(
    vault_path: PathBuf,
    backend: Option<&str>,
    prefix: Option<String>,
    redact: bool,
    command: &[String],
) -> anyhow::Result<()> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("no command given after `--`"))?;

    let prefix = resolve_prefix(prefix)?;
    let prefix = prefix.as_str();

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

    if redact_requested(redact) {
        note!(
            "--redact: scrubbing {} injected value(s) from `{}`'s stdout/stderr.",
            injected.len(),
            program
        );
        return exec_with_redaction(cmd, &injected);
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

/// Runs `cmd` with stdout/stderr piped (rather than inherited/exec'd)
/// through a [`Redactor`] built from `injected`, so every occurrence of an
/// injected secret value — or its URL-percent-encoded form — is replaced
/// with `<vault:KEY_NAME>` before it reaches this process's own stdout or
/// stderr. Stdin stays inherited (a redirected/interactive child still gets
/// its input normally; only the output side needs scrubbing).
///
/// This intentionally does NOT use `exec()` (unlike the non-redact path):
/// there is no way to intercept a replaced process image's I/O, so this
/// path pays the cost of a real child process (spawn + wait) instead of a
/// process-image replacement. Exit code passes through unchanged; on Unix a
/// child killed by a signal is reported the same way a shell reports it
/// (128 + signal number).
fn exec_with_redaction(
    mut cmd: std::process::Command,
    injected: &[(String, SensitiveString)],
) -> anyhow::Result<()> {
    use std::process::Stdio;

    let redactor = Redactor::new(
        injected
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str().as_bytes())),
    );

    cmd.stdin(Stdio::inherit());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn child: {e}"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| anyhow::anyhow!("child stdout was not piped"))?;
    let child_stderr = child
        .stderr
        .take()
        .ok_or_else(|| anyhow::anyhow!("child stderr was not piped"))?;

    // One thread per stream so a child that fills its stdout pipe while
    // blocked writing to stderr (or vice versa) can never deadlock this
    // process — both streams are always being drained concurrently.
    let out_redactor = redactor.clone();
    let out_thread =
        std::thread::spawn(move || pump_redacted(child_stdout, std::io::stdout(), out_redactor));
    let err_redactor = redactor.clone();
    let err_thread =
        std::thread::spawn(move || pump_redacted(child_stderr, std::io::stderr(), err_redactor));

    // Drain both threads before waiting on the child: the child's pipes
    // must hit EOF (which only happens once the process has exited or
    // closed the fds) before either thread returns, so this ordering does
    // not risk missing output.
    let out_result = out_thread
        .join()
        .map_err(|_| anyhow::anyhow!("stdout redaction thread panicked"))?;
    let err_result = err_thread
        .join()
        .map_err(|_| anyhow::anyhow!("stderr redaction thread panicked"))?;
    out_result?;
    err_result?;

    let status = child.wait()?;

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            std::process::exit(128 + signal);
        }
    }
    std::process::exit(status.code().unwrap_or(1));
}

/// Copies `src` to `dst` in bounded-size chunks, redacting each chunk
/// through `redactor` (with a proper carry-buffer flush at EOF) before it is
/// written out. Used identically for stdout and stderr.
fn pump_redacted<R: std::io::Read, W: std::io::Write>(
    mut src: R,
    mut dst: W,
    redactor: Redactor,
) -> anyhow::Result<()> {
    let mut stream = redactor.stream();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = src.read(&mut buf)?;
        if n == 0 {
            let tail = stream.process(&[], true);
            if !tail.is_empty() {
                dst.write_all(&tail)?;
            }
            dst.flush()?;
            return Ok(());
        }
        let out = stream.process(&buf[..n], false);
        if !out.is_empty() {
            dst.write_all(&out)?;
        }
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
#[cfg(feature = "github-app-token")]
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

#[cfg(feature = "github-app-token")]
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
        // The DER is the private key with the PEM armour removed -- exactly
        // as secret as the PEM string this function is careful to wipe.
        let der_bytes = zeroize::Zeroizing::new(der_bytes);
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

fn cmd_status(vault_path: PathBuf, backend: Option<&str>, json: bool) -> anyhow::Result<()> {
    if json {
        return status_json(vault_path, backend);
    }
    match resolve_backend(backend) {
        Ok(hsm) => println!("HSM backend: {} (tier {})", hsm.name(), hsm.tier()),
        Err(e) => println!(
            "HSM backend: unavailable for inspection ({e}). Use TPM2 or an OS keyring for \
             interactive users; a headless Linux root service may use systemd-creds."
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

    #[cfg(unix)]
    match hearth_vault::agent::control("STATUS") {
        Ok(reply) => println!(
            "Agent: running at {} ({})",
            hearth_vault::agent::socket_path().display(),
            reply.trim_start_matches("OK ")
        ),
        Err(_) => println!("Agent: not running (`hearth-vault agent --daemon` to start one)"),
    }

    // Rotation state lives inside the encrypted body, so reporting it means
    // unlocking. `status` must stay usable without a passphrase — it is the
    // command you run when something is wrong — so this reports only when an
    // unlock is already available, and points elsewhere when it is not.
    match try_open_quietly(&vault_path, backend) {
        Some(store) => {
            let entries = store.list();
            let overdue = entries
                .iter()
                .filter(|e| matches!(e.rotation_state(), RotationState::Overdue { .. }))
                .count();
            let soon = entries
                .iter()
                .filter(|e| matches!(e.rotation_state(), RotationState::Ok { days_left } if days_left <= 7))
                .count();
            let tracked = entries.iter().filter(|e| e.rotate_days.is_some()).count();
            println!(
                "Rotation: {tracked} of {} key(s) have a policy",
                entries.len()
            );
            if overdue > 0 {
                println!("  {overdue} OVERDUE — run `hearth-vault list --due`");
            }
            if soon > 0 {
                println!("  {soon} due within 7 days");
            }
        }
        None => println!("Rotation: locked (run `hearth-vault list --due` to check)"),
    }

    Ok(())
}

/// Open the vault only if it can be done without prompting a human — via a
/// running agent, a sealed passphrase, or `HEARTH_VAULT_PASSPHRASE`. Used by
/// `status`, which must never block on a prompt.
fn try_open_quietly(vault_path: &Path, backend: Option<&str>) -> Option<VaultStore> {
    #[cfg(unix)]
    if let Some(key) = hearth_vault::agent::try_get(vault_path)
        && let Ok(store) = VaultStore::open_at_with_wrap_key(vault_path.to_path_buf(), &key)
    {
        return Some(store);
    }
    if let Ok(passphrase) = std::env::var("HEARTH_VAULT_PASSPHRASE")
        && !passphrase.is_empty()
        && let Ok(store) =
            VaultStore::open_at_with_passphrase(vault_path.to_path_buf(), &passphrase)
    {
        return Some(store);
    }
    // The sealed-passphrase path, if a hardware backend is holding one.
    let sealed = sealed_passphrase_path(vault_path);
    if sealed.exists()
        && let Ok(hsm) = resolve_backend(backend)
        && hsm.tier() <= 2
        && let Ok(blob) = fs::read(&sealed)
        && let Ok(bytes) = hsm.unseal(&blob, "hearth-vault")
        && let Ok(passphrase) = std::str::from_utf8(&bytes)
        && let Ok(store) = VaultStore::open_at_with_passphrase(vault_path.to_path_buf(), passphrase)
    {
        return Some(store);
    }
    None
}

fn status_json(vault_path: PathBuf, backend: Option<&str>) -> anyhow::Result<()> {
    let rotation = try_open_quietly(&vault_path, backend).map(|store| {
        let entries = store.list();
        serde_json::json!({
            "tracked": entries.iter().filter(|e| e.rotate_days.is_some()).count(),
            "total": entries.len(),
            "overdue": entries.iter()
                .filter(|e| matches!(e.rotation_state(), RotationState::Overdue { .. }))
                .map(|e| e.key.clone())
                .collect::<Vec<_>>(),
        })
    });

    let out = serde_json::json!({
        "vault_path": vault_path.display().to_string(),
        "initialized": vault_path.exists(),
        "backend": resolve_backend(backend).map(|h| h.name().to_string()).ok(),
        "agent_running": agent_running(),
        "rotation": rotation,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

/// Whether an unlock agent is answering. Always false where the agent does
/// not exist, so callers need no `cfg`.
fn agent_running() -> bool {
    #[cfg(unix)]
    {
        hearth_vault::agent::is_running()
    }
    #[cfg(not(unix))]
    {
        false
    }
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

/// The files git would include in the next commit: added, copied, modified,
/// renamed — but not deleted, which have no content to scan.
///
/// `-z` and raw bytes rather than lines: a path may legally contain a
/// newline, and a scanner that silently skipped such a file would be a
/// wonderful place to hide a key.
fn staged_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "diff",
            "--cached",
            "--name-only",
            "--diff-filter=ACMR",
            "-z",
        ])
        .output()
        .map_err(|e| anyhow::anyhow!("could not run git: {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "git diff --cached failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }

    // Paths are relative to the repo root, which is not necessarily `root`.
    let top = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|e| anyhow::anyhow!("could not run git: {e}"))?;
    let base = PathBuf::from(String::from_utf8_lossy(&top.stdout).trim().to_string());

    Ok(out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| base.join(String::from_utf8_lossy(s).into_owned()))
        .filter(|p| p.is_file())
        .collect())
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
    staged: bool,
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

    let findings = if staged {
        if adopt {
            anyhow::bail!(
                "--staged and --adopt do not combine: adopting rewrites files, and rewriting \
                 what is already staged would commit something you never reviewed"
            );
        }
        let files = staged_files(&root)?;
        if files.is_empty() {
            eprintln!("Nothing staged.");
            return Ok(());
        }
        hearth_vault::scan::scan_files(files)?
    } else {
        if !root.exists() {
            anyhow::bail!("path not found: {}", root.display());
        }
        hearth_vault::scan::scan_path(&root)?
    };

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

/// Work out which prefix `exec` should use.
///
/// Explicit flag, then `$HEARTH_VAULT_PREFIX` (set by the direnv
/// integration), then the nearest `.hearth-vault` marker. The fallback chain
/// is why `hearth-vault exec -- npm run dev` works with no arguments inside a
/// configured project — and why an agent reading these docs does not have to
/// guess a prefix or hardcode one that will be wrong in the next repo.
fn resolve_prefix(explicit: Option<String>) -> anyhow::Result<String> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Ok(p) = std::env::var("HEARTH_VAULT_PREFIX")
        && !p.is_empty()
    {
        return Ok(p);
    }
    if let Some(marker) = find_project_marker() {
        return read_project_prefix(&marker);
    }
    anyhow::bail!(
        "no prefix given and none discoverable \u{2014} pass --prefix <name>/, set \
         $HEARTH_VAULT_PREFIX, or create a project marker: `echo \"<name>/\" > .hearth-vault`"
    )
}

// ── backup / restore ────────────────────────────────────────────────────

/// Read a passphrase, preferring `$HEARTH_VAULT_PASSPHRASE` when set.
///
/// `rpassword` opens the controlling terminal directly, so it fails outright
/// with "no such device" under a pipe, in CI, or from a systemd unit. Every
/// prompt a script might legitimately need to answer routes through here.
fn read_passphrase(prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    if let Ok(p) = std::env::var("HEARTH_VAULT_PASSPHRASE")
        && !p.is_empty()
    {
        return Ok(Zeroizing::new(p));
    }
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

/// Copy the (already encrypted) vault file to a timestamped snapshot.
///
/// `dest` may be a directory or an explicit file path; `None` means "next to
/// the vault". Returns where it landed.
fn write_backup(vault_path: &Path, dest: Option<&Path>) -> anyhow::Result<PathBuf> {
    if !vault_path.exists() {
        anyhow::bail!("no vault at {} to back up", vault_path.display());
    }
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    // Directory or file? An existing directory is unambiguous. For a path
    // that does not exist yet, an extensionless one is taken as a directory
    // to create: `--output ~/backups` on a machine where that folder does
    // not exist yet should not silently produce a *file* called `backups`
    // that the next backup then refuses to overwrite.
    let target = match dest {
        Some(p) if p.is_dir() || p.extension().is_none() => p.join(format!("vault-{stamp}.json")),
        Some(p) => p.to_path_buf(),
        None => vault_path.with_file_name(format!("vault-{stamp}.json")),
    };
    if target.exists() {
        anyhow::bail!("refusing to overwrite existing file {}", target.display());
    }

    // Read-then-write-private rather than fs::copy: copy preserves the
    // source mode on some platforms and not others, and a backup of a
    // secrets file created world-readable for even an instant is a bug.
    let contents = Zeroizing::new(fs::read(vault_path)?);
    if let Some(parent) = target.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    platform::write_private(&target, &contents)
        .map_err(|e| anyhow::anyhow!("failed to write backup: {e}"))?;
    Ok(target)
}

fn cmd_backup(vault_path: PathBuf, output: Option<String>) -> anyhow::Result<()> {
    let dest = output.map(PathBuf::from);
    let target = write_backup(&vault_path, dest.as_deref())?;
    eprintln!("Backup written: {}", target.display());
    eprintln!(
        "It is encrypted with the passphrase in force at this moment \u{2014} store it anywhere, \
         but remember that a later `change-passphrase` does NOT re-key this file."
    );
    Ok(())
}

fn cmd_restore(vault_path: PathBuf, file: &str) -> anyhow::Result<()> {
    let source = PathBuf::from(file);
    if !source.exists() {
        anyhow::bail!("no such snapshot: {}", source.display());
    }

    // Prove the snapshot opens BEFORE touching the live vault. Restoring an
    // unopenable file over a working vault would destroy both copies at
    // once, which is the one failure this command must not have.
    let passphrase = read_passphrase("Passphrase for the snapshot being restored: ")?;
    let probe = VaultStore::open_at_with_passphrase(source.clone(), &passphrase)
        .map_err(|e| anyhow::anyhow!("snapshot did not open, nothing was changed: {e}"))?;
    let count = probe.list().len();
    drop(probe);

    if vault_path.exists() {
        let saved = write_backup(&vault_path, None)?;
        eprintln!("Current vault saved to {}", saved.display());
    }

    let contents = Zeroizing::new(fs::read(&source)?);
    platform::write_private(&vault_path, &contents)
        .map_err(|e| anyhow::anyhow!("failed to write restored vault: {e}"))?;

    // Any cached wrap key belongs to the vault that was just replaced.
    #[cfg(unix)]
    if agent_running() {
        let _ = hearth_vault::agent::control("DROP");
    }

    eprintln!(
        "Restored {count} credential(s) to {} from {}",
        vault_path.display(),
        source.display()
    );
    Ok(())
}

// ── agent ───────────────────────────────────────────────────────────────

#[cfg(unix)]
fn cmd_agent(ttl: u64, daemon: bool, drop: bool, stop: bool, status: bool) -> anyhow::Result<()> {
    use hearth_vault::agent;

    if stop {
        println!("{}", agent::control("STOP")?);
        return Ok(());
    }
    if drop {
        println!("{}", agent::control("DROP")?);
        return Ok(());
    }
    if status {
        match agent::control("STATUS") {
            Ok(reply) => println!("{} at {}", reply, agent::socket_path().display()),
            Err(_) => {
                println!("no agent running");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    if daemon {
        // fork() rather than a thread: the parent must be able to exit and
        // return the shell prompt while the child keeps the socket open.
        // SAFETY: fork in a single-threaded process that immediately either
        // returns (parent) or runs the server loop (child). No allocator
        // state is shared across the boundary in a way that can deadlock.
        match unsafe { libc::fork() } {
            -1 => anyhow::bail!("fork failed: {}", std::io::Error::last_os_error()),
            0 => {
                // SAFETY: setsid detaches the child from the controlling
                // terminal so it survives the shell that started it.
                unsafe { libc::setsid() };
                // Must come before serve(): holding the inherited stdout
                // keeps the parent shell's pipe open, and `agent --daemon`
                // looks like it hung.
                agent::detach_stdio();
                let _ = agent::serve(std::time::Duration::from_secs(ttl));
                std::process::exit(0);
            }
            _ => {
                // Wait for the socket to answer before returning, so that
                // `hearth-vault agent --daemon && hearth-vault unlock` cannot
                // race the agent's own startup.
                for _ in 0..100 {
                    if agent::is_running() {
                        eprintln!(
                            "agent started at {} (ttl {ttl}s)",
                            agent::socket_path().display()
                        );
                        return Ok(());
                    }
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                anyhow::bail!("agent did not come up within 2s");
            }
        }
    }

    agent::serve(std::time::Duration::from_secs(ttl))
}

#[cfg(not(unix))]
fn cmd_agent(_: u64, _: bool, _: bool, _: bool, _: bool) -> anyhow::Result<()> {
    anyhow::bail!(
        "the unlock agent is Unix-only (it needs an AF_UNIX socket). On Windows, seal the \
         passphrase to the OS keyring instead \u{2014} `hearth-vault seal` \u{2014} which \
         auto-unlocks with no per-command cost."
    )
}

fn cmd_unlock(vault_path: PathBuf) -> anyhow::Result<()> {
    #[cfg(not(unix))]
    {
        let _ = vault_path;
        anyhow::bail!("the unlock agent is Unix-only; use `hearth-vault seal` on Windows.")
    }
    #[cfg(unix)]
    {
        use hearth_vault::agent;
        if !agent::is_running() {
            anyhow::bail!(
                "no agent is running \u{2014} start one first: `hearth-vault agent --daemon`"
            );
        }
        if !vault_path.exists() {
            anyhow::bail!("no vault at {}", vault_path.display());
        }

        let passphrase = read_passphrase("Vault passphrase: ")?;
        // Open once to verify the passphrase before caching it. Caching an
        // unverified key would turn one typo into fifteen minutes of
        // confusing "cached key does not open this vault" fallbacks.
        VaultStore::open_at_with_passphrase(vault_path.clone(), &passphrase)
            .map_err(|e| anyhow::anyhow!("not unlocked: {e}"))?;
        let key = VaultStore::derive_wrap_key(&vault_path, &passphrase)?;
        if agent::try_put(&vault_path, &key) {
            eprintln!("Unlocked. Commands against this vault will not prompt until the TTL ends.");
            Ok(())
        } else {
            anyhow::bail!("agent refused the key")
        }
    }
}

fn cmd_lock() -> anyhow::Result<()> {
    #[cfg(not(unix))]
    {
        anyhow::bail!("the unlock agent is Unix-only.")
    }
    #[cfg(unix)]
    {
        println!("{}", hearth_vault::agent::control("DROP")?);
        Ok(())
    }
}

// ── sharing ─────────────────────────────────────────────────────────────

fn cmd_identity(vault_path: PathBuf, backend: Option<&str>) -> anyhow::Result<()> {
    let store = open_vault(vault_path, backend)?;
    let seed = store.share_identity_seed()?;
    let identity = hearth_vault::share::public_identity(&seed);
    println!("{identity}");
    eprintln!(
        "fingerprint: {}",
        hearth_vault::share::fingerprint(&identity)
    );
    eprintln!(
        "This is public. Send it to a teammate so they can `hearth-vault share --to` you; \
         confirm the fingerprint over a channel other than the one carrying the bundle."
    );
    Ok(())
}

fn cmd_share(
    vault_path: PathBuf,
    backend: Option<&str>,
    prefix: &str,
    to: &str,
    output: &str,
    max_tier: Option<u8>,
    note: Option<String>,
) -> anyhow::Result<()> {
    let store = open_vault(vault_path, backend)?;
    let entries = store.entries_with_prefix(prefix);
    if entries.is_empty() {
        anyhow::bail!("no keys under prefix '{prefix}'");
    }

    let bundle = hearth_vault::share::seal(&entries, to, max_tier, note)?;
    let json = serde_json::to_vec_pretty(&bundle)?;

    // Owner-only even though the bundle is encrypted: the file is going to
    // be moved around by hand, and a 644 secrets-adjacent file invites
    // exactly the casual copy this tool exists to prevent.
    let path = PathBuf::from(output);
    platform::write_private(&path, &json)
        .map_err(|e| anyhow::anyhow!("failed to write bundle: {e}"))?;

    let shared: Vec<&str> = entries
        .iter()
        .filter(|(_, _, t)| *t != hearth_vault::TIER_SIGN_ONLY)
        .map(|(k, _, _)| k.as_str())
        .collect();
    let skipped = entries.len() - shared.len();

    eprintln!("Sealed {} key(s) to {}:", shared.len(), bundle.to);
    for key in shared {
        eprintln!("  {key}");
    }
    if skipped > 0 {
        eprintln!(
            "  ({skipped} tier-{} sign-only key(s) not shareable)",
            hearth_vault::TIER_SIGN_ONLY
        );
    }
    eprintln!("Bundle: {}", path.display());
    eprintln!(
        "Only the holder of that identity can open it. Confirm their fingerprint out of band \
         before sending \u{2014} a bundle proves the sender knew their public key, not who they are."
    );
    Ok(())
}

fn cmd_receive(
    vault_path: PathBuf,
    backend: Option<&str>,
    file: &str,
    dry_run: bool,
    prefix: Option<String>,
    force: bool,
) -> anyhow::Result<()> {
    let raw = fs::read(file).map_err(|e| anyhow::anyhow!("cannot read bundle {file}: {e}"))?;
    let bundle: hearth_vault::share::Bundle =
        serde_json::from_slice(&raw).map_err(|e| anyhow::anyhow!("not a bundle file: {e}"))?;

    let mut store = open_vault(vault_path, backend)?;
    let seed = store.share_identity_seed()?;
    let (entries, note) = hearth_vault::share::open(&bundle, &seed)?;

    if let Some(note) = note {
        eprintln!("Note from sender: {note}");
    }

    let rename = |key: &str| match prefix {
        Some(ref p) => format!("{p}{}", key.rsplit('/').next().unwrap_or(key)),
        None => key.to_string(),
    };

    if dry_run {
        eprintln!("{} key(s) in this bundle:", entries.len());
        for e in &entries {
            eprintln!("  {} (tier {})", rename(&e.key), e.tier);
        }
        eprintln!("Nothing was stored. Re-run without --dry-run to accept.");
        return Ok(());
    }

    let mut stored = 0usize;
    let mut skipped = Vec::new();
    for entry in &entries {
        let key = rename(&entry.key);
        if store.has(&key) && !force {
            skipped.push(key);
            continue;
        }
        store.set(&key, &entry.value, entry.tier)?;
        eprintln!("  \u{2713} {key} (tier {})", entry.tier);
        stored += 1;
    }

    if stored > 0 {
        store.save()?;
    }
    eprintln!("Stored {stored} credential(s) from {file}.");
    if !skipped.is_empty() {
        eprintln!(
            "Skipped {} existing key(s) (pass --force to overwrite): {}",
            skipped.len(),
            skipped.join(", ")
        );
    }
    Ok(())
}

// ── git hook / direnv ───────────────────────────────────────────────────

/// The pre-commit hook body. Deliberately tiny and dependency-free: a hook
/// that breaks when the tool is missing would train people to `--no-verify`,
/// which is worse than having no hook at all.
const PRE_COMMIT_HOOK: &str = r#"#!/bin/sh
# Installed by `hearth-vault install-hook`.
#
# Scans the files you are about to commit for secret-shaped strings. Exits
# non-zero (blocking the commit) if it finds any.
#
# If hearth-vault is not on PATH this does nothing rather than blocking your
# commit -- a hook that fails when the tool is absent teaches people to pass
# --no-verify, and a bypassed hook protects nobody.
command -v hearth-vault >/dev/null 2>&1 || exit 0

if ! hearth-vault scan --staged; then
    echo
    echo "A secret-shaped string is staged. Options:"
    echo "  * store it:   hearth-vault set <name>          (then read it via env at runtime)"
    echo "  * adopt .env: hearth-vault scan --adopt --prefix <project>/"
    echo "  * false hit:  add a 'hearth-vault:allow' comment on that line"
    echo "  * override:   git commit --no-verify           (be sure)"
    exit 1
fi
"#;

fn cmd_install_hook(path: Option<String>, force: bool) -> anyhow::Result<()> {
    let root = PathBuf::from(path.unwrap_or_else(|| ".".to_string()));
    let git_dir = root.join(".git");
    if !git_dir.exists() {
        anyhow::bail!("{} is not a git repository", root.display());
    }

    // Worktrees and submodules have a `.git` FILE pointing elsewhere; hooks
    // live in the common dir, not next to the file.
    let hooks_dir = if git_dir.is_file() {
        let pointer = fs::read_to_string(&git_dir)?;
        let target = pointer
            .trim()
            .strip_prefix("gitdir:")
            .ok_or_else(|| anyhow::anyhow!("unreadable .git pointer in {}", root.display()))?
            .trim();
        let resolved = root.join(target);
        resolved.join("hooks")
    } else {
        git_dir.join("hooks")
    };
    fs::create_dir_all(&hooks_dir)?;

    let hook = hooks_dir.join("pre-commit");
    if hook.exists() {
        let existing = fs::read_to_string(&hook).unwrap_or_default();
        if existing.contains("hearth-vault scan --staged") {
            eprintln!("Already installed: {}", hook.display());
            return Ok(());
        }
        if !force {
            anyhow::bail!(
                "{} already exists \u{2014} inspect it, then re-run with --force (the existing \
                 hook is backed up, not discarded)",
                hook.display()
            );
        }
        let backup = hook.with_extension("pre-hearth-vault");
        fs::rename(&hook, &backup)?;
        eprintln!("Existing hook moved to {}", backup.display());
    }

    fs::write(&hook, PRE_COMMIT_HOOK)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755))?;
    }
    eprintln!("Installed pre-commit hook: {}", hook.display());
    eprintln!("Test it: `hearth-vault scan --staged`");
    Ok(())
}

fn cmd_direnv_init() {
    print!(
        r#"# hearth-vault direnv integration.
#
# Add to ~/.config/direnv/direnvrc:
#     eval "$(hearth-vault direnv-init)"
# Then in a project's .envrc:
#     use hearth_vault
#
# What this exports: HEARTH_VAULT_PREFIX -- a NAME, not a secret. With it set,
# `hearth-vault exec -- <cmd>` needs no --prefix inside this project.
#
# What it deliberately does NOT do: export your secrets into the interactive
# shell. direnv makes that a two-line temptation, and it would undo the whole
# point -- every process you launch from that shell, every agent, every `env`
# dump in a bug report would carry your credentials. Secrets stay in the child
# process `exec` creates, and nowhere else.
use_hearth_vault() {{
    local prefix="${{1:-}}"
    if [ -z "$prefix" ] && [ -f .hearth-vault ]; then
        prefix="$(hearth-vault project-prefix 2>/dev/null || true)"
    fi
    if [ -z "$prefix" ]; then
        log_error "use hearth_vault: no prefix given and no .hearth-vault marker found"
        return 1
    fi
    export HEARTH_VAULT_PREFIX="$prefix"
    watch_file .hearth-vault
    log_status "hearth-vault: prefix $prefix (run commands with: hearth-vault exec -- <cmd>)"
}}
"#
    );
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
    #[cfg(feature = "github-app-token")]
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
    #[cfg(feature = "github-app-token")]
    #[test]
    fn build_token_request_body_single_repo() {
        let body = build_token_request_body(&["myapp".to_string()])
            .unwrap()
            .expect("single repo should produce a JSON body");
        assert_eq!(body, serde_json::json!({"repositories": ["myapp"]}));
    }

    /// Multiple repos preserve order and produce a single repositories array.
    #[cfg(feature = "github-app-token")]
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
    #[cfg(feature = "github-app-token")]
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
    #[cfg(feature = "github-app-token")]
    #[test]
    fn build_token_request_body_rejects_whitespace_only() {
        assert!(build_token_request_body(&["   ".to_string()]).is_err());
    }

    /// Mixed-validity input rejects rather than silently dropping the bad
    /// entry — fail loud rather than mint a token with surprising scope.
    #[cfg(feature = "github-app-token")]
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
