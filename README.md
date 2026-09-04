# hearth-vault

A local, encrypted secrets vault built for a world where coding agents run
commands on your behalf. If you have ever watched an AI agent paste an API
key into a chat transcript, log line, or tool-call payload because that was
the only way to hand it the credential, this tool exists to make that
unnecessary: agents can *use* your secrets without ever *seeing* them.

`hearth-vault` stores your credentials in a single encrypted file on disk and
gives you three ways to put them to work without printing the value anywhere
an agent, a log aggregator, or a terminal scrollback could capture it:

- inject them into a child process's environment (`exec`)
- sign a message with a private key that never leaves the vault process (`sign`)
- mint a short-lived GitHub App installation token from a private key that is
  never exported (`github-app-token`)

## Quickstart

If you already have a `.env` file, this is the fastest path from there to a
vault-backed project:

```
cargo install --locked --git https://github.com/warxhead1/hearth-vault
hearth-vault init
hearth-vault import-env .env --prefix myapp/
hearth-vault exec --prefix myapp/ -- npm run dev
```

`init` creates the vault and asks for a passphrase (and prints a one-time
BIP39 recovery mnemonic — write it down, it is the only backup path).
`import-env` reads `.env`, stores each `KEY=value` pair as `myapp/key` (tier
3 by default), then deletes the file. `exec` resolves every injectable
secret under the given prefix to an environment variable, execs the given
command with those variables injected, and never prints the values itself —
they exist only in the child process's memory for the lifetime of that
process.

If your secrets aren't in one tidy `.env` file — scattered across several
files, or you're not sure what you have — start with `hearth-vault scan`
instead, and see **[MIGRATING.md](MIGRATING.md)** for the full walkthrough
(finding secrets, adopting them, per-project setup, choosing a tier, and
keeping a repo clean going forward). To add secrets one at a time instead,
`hearth-vault set myapp/api_key` prompts for the value with hidden input; it
is never passed as a command-line argument or echoed back.

## Why this exists

Most secrets tooling was designed for a human typing into a terminal, or for
a CI system reading a value once at the start of a pipeline. Neither model
fits an AI coding agent that runs dozens of shell commands per session, many
of which need a credential, and whose entire input/output stream may be
logged, summarized, or forwarded to a third-party model. Every place a
`GITHUB_TOKEN` or an `OPENAI_API_KEY` gets printed to stdout, embedded in a
shell history, or pasted into a prompt is a place it can leak — not through
malice, just through the normal mechanics of how agents work.

`hearth-vault` treats "the value only ever exists inside a process that needs
it" as the default, not an advanced feature.

## The tier model

Every secret is stored under one of four tiers:

- **Tier 1 — keyring-class, exportable.** Backed by the OS credential store
  (Keychain / Credential Manager / libsecret) when available. Can be read
  back with `export-env` / `export-env-file`.
- **Tier 2 — software-vault, exportable.** Encrypted in the vault file
  itself. Can also be read back with `export-env` / `export-env-file`.
- **Tier 3 — use-only. This is the default for new secrets.** `export-env`
  and `export-env-file` refuse to emit a tier-3 value — it is never
  printed. **`exec` still injects it.** This is the point of the tool:
  `exec` puts the value straight into a child process's environment without
  ever putting it on a stream the caller reads, so "unprintable" and
  "unusable by `exec`" are different things. A tier-3 secret is exactly what
  you want for the default agent workflow — `hearth-vault exec --prefix
  myapp/ -- <command>` injects it, the agent driving that command never sees
  the raw value, and the command itself gets a normal environment variable.
  `sign` and `github-app-token` can also use a tier-3 key from inside the
  vault process.
- **Tier 4 — sign-only. Never printed, and never injected by `exec`
  either.** The value never leaves the vault process under any command.
  Only `sign` and `github-app-token` can use it — they read it internally,
  produce a signature or a derived token, and that derived output is the
  only thing that reaches the caller. Use this for private keys you only
  ever need to sign or mint tokens with, never to hand to a process
  directly.

Because tier 3 is the default, storing a new secret does not by itself grant
any command the ability to print it — but `exec` will still use it, which is
what makes the default safe *and* usable. To make a secret exportable
(tier 1/2) you have to say so explicitly:

```
hearth-vault set myapp/api_key --tier 2
```

or move an existing entry to a different tier in place:

```
hearth-vault retier myapp/api_key --tier 2
```

Default to tier 3. Use tier 2 only when a specific downstream tool genuinely
needs the raw value on stdout or in a file it reads itself (not via `exec`
env injection). Use tier 4 for signing keys — an RSA signing key, a GitHub
App private key — that should never be handed to a process at all, only used
internally by `sign` / `github-app-token`.

## The non-TTY rule

Any command that would put a secret value on stdout or into a file refuses
to run when stdout is not a TTY:

```
hearth-vault export-env myapp/api_key --env-name MYAPP_API_KEY | cat
# error: refusing to run — stdout is not a TTY
```

This applies to `export-env`, `export-env-file`, `sign`, `github-app-token`,
`prompt`, and the recovery-mnemonic print in `init` / `recover`. It does
*not* apply to `exec`, because `exec` never writes the secret to a stream
the caller reads at all — it goes straight into the child process's
environment.

The reasoning: an AI agent's tool calls are pipes, not terminals. A human
running one of these commands interactively is sitting at a TTY; a script or
an agent invoking the same binary through a tool-call wrapper is not. Rather
than trying to fingerprint which environment variables indicate "this
caller is an agent" (a list that would need updating forever), the tool uses
the one structural signal that is actually reliable: is anyone at a keyboard
watching this output right now. If you need one of these commands in a
non-interactive context you control — systemd, CI — set:

```
HEARTH_VAULT_ALLOW_NON_TTY=1
```

## Commands

```
init                    First-time setup: create the vault, set a passphrase,
                         print a one-time BIP39 recovery mnemonic.
init-machine --recovery-recipient HV1_IDENTITY --recovery-output FILE
                         Headless initialization: generate a random passphrase,
                         seal it to the selected host backend, and write the
                         recovery mnemonic only inside a recipient-encrypted
                         `.hvs` bundle. No secret is printed.
set <key>... [--tier] [--rotate-days N] [--expires WHEN]
                         Store one or more secrets (hidden-input prompt).
                         Tier defaults to 3 (use-only); an existing key keeps
                         its tier. `--rotate-days N` attaches a rotation
                         policy, after which every later `set` of that key
                         advances the due date by itself. `--expires` pins an
                         exact date (RFC3339, or a relative `30d`/`12w`/`6m`,
                         or a negative `-7d` to flag something already stale).
import <file> --key K   Store a secret whose value is the contents of a file.
                         Tier defaults to 3.
import-env [file] --prefix P [--tier] [--keep] [--force]
                         Bulk-import a dotenv file (default: ./.env). Parses
                         `KEY=value` / `export KEY=value`, quoted values,
                         `#` comments, blank lines. Each pair is stored as
                         `<prefix>KEY` at tier 3 by default, then the source
                         file is deleted unless `--keep` is passed. `--force`
                         overwrites keys that already exist in the vault.
migrate                 Move a legacy `~/.hearth/vault.json` (v1 format)
                         into the current on-disk format at the standard
                         platform data directory.
scan [path] [--json] [--adopt] [--prefix P] [--rules] [--force] [--staged]
                         Scan a directory (default: current directory) for
                         likely secrets by value shape (cloud/API key
                         formats, PEM headers, connection strings, JWTs,
                         high-entropy generic values), not by variable name.
                         Output is redacted. Exits 1 if it finds anything, 0
                         otherwise, so it works as a pre-commit or CI gate.
                         `--adopt` moves findings from `.env`-style files
                         into the vault under `--prefix` and rewrites those
                         files; findings in source code are reported only,
                         never rewritten. `--rules` lists what `scan`
                         detects. `--force` (with `--adopt`) overwrites
                         existing vault keys. `--staged` scans only what git
                         has staged, which is what `install-hook` wires into
                         your pre-commit hook. See MIGRATING.md.
list [--json] [--due [N]]
                         List stored key names, tiers, dates, and rotation
                         status. Never shows values. `--due` filters to
                         overdue keys (`--due 7` for the coming week) and
                         exits 1 if any are listed, so it drops into cron or
                         CI with no output parsing.
has <key>               Exit 0 if the key exists, non-zero otherwise.
delete <key> [--no-backup]
                         Remove a secret, taking an encrypted snapshot of the
                         vault first (the recovery mnemonic restores the
                         vault key, not entries you deleted).
rename <from> <to>      Rename a secret in place.
retier <key> --tier N   Change a secret's tier (1, 2, 3, or 4).
export-env <key> --env-name NAME
                         Print `export NAME=value`. Refuses on tier 3/4 and
                         when stdout is not a TTY.
export-env-file --prefix P --output FILE
                         Write every tier-1/2 key under prefix P as
                         KEY=value lines to FILE (0600 permissions).
                         Intended for systemd ExecStartPre.
exec [--prefix P] [--redact] -- <command...>
                         `--prefix` is optional: it falls back to
                         $HEARTH_VAULT_PREFIX, then to the nearest
                         `.hearth-vault` marker.
                         Inject every tier-1/2/3 key under prefix P into the
                         child's environment (name mapping: strip prefix,
                         uppercase, `/` and `-` -> `_`) and exec the
                         command. Tier-4 keys are skipped. This is the
                         agent-safe consumption path, and the one
                         value-bearing command not subject to the non-TTY
                         rule.
                         `--redact` (or HEARTH_VAULT_REDACT=1): scrub every
                         injected value out of the child's stdout/stderr
                         before it reaches you, replacing it with
                         `<vault:KEY_NAME>`. OFF by default -- see
                         "Redacting a child's output" below before turning
                         it on for a script that captures exec's output as
                         the value.
                         `--warn-unsealed` (or HEARTH_VAULT_WARN_UNSEALED=1):
                         after starting the child, check whether IT has
                         sealed its own `/proc/<pid>/environ` and print a
                         stderr warning if not. OFF by default, never fatal
                         -- see "Sealing a secret-holding process" below for
                         why `hearth-vault` cannot do this sealing FOR the
                         child, only tell you it hasn't happened.
seal-check [--pid P|--unit U|--all] [--prefix P] [--json]
                         Audit whether an ALREADY-RUNNING process (not one
                         you just launched with `exec`) has sealed itself.
                         `--pid`: one process. `--unit NAME`: resolve a
                         systemd --user unit's MainPID. `--all`: every
                         process running as you. Reports SEALED or READABLE
                         per process; a READABLE one is further checked for
                         whether any of its exposed environment variable
                         NAMES match one this vault would generate --
                         never a value, only a name. Exits 1 if it finds a
                         READABLE process holding a vault-managed name (wire
                         this into a periodic check or CI), 0 otherwise.
                         Linux-only. See "Sealing a secret-holding process."
sign --key K --algorithm ALG --message M
                         Sign M with the private key stored at K. Algorithms:
                         RSA-PSS-SHA256, RS256, RS512. Prints a base64
                         signature (JWT-style base64url for RS256/RS512).
                         Works for tier 3 and tier 4 keys.
github-app-token --installation-id ID [--json] [--repository NAME]...
                         Mint a 1-hour GitHub App installation token by
                         signing a JWT internally from a stored private key
                         and exchanging it with GitHub. The private key
                         never leaves the vault process; only the resulting
                         token is printed. Works for tier 3 and tier 4 keys.
status [--json]         Show backend type, vault path, permissions, agent
                         state, and how many keys are due for rotation.
backup [--output PATH]  Write an encrypted snapshot. Needs no passphrase —
                         the vault file is already encrypted — so there is no
                         excuse not to take one.
restore <file>          Replace the vault with a snapshot. Verifies the
                         snapshot opens before touching anything, and backs
                         up what it replaces.
agent [--ttl N] [--daemon|--stop|--drop|--status]
                         Short-lived unlock cache, ssh-agent style. Holds a
                         derived wrap key (not your passphrase, not the data
                         key) for `--ttl` seconds so repeated commands skip
                         the ~120ms Argon2id derivation. Unix only.
unlock                  Prompt once and hand the derived key to the agent.
lock                    Make the agent forget everything, immediately.
identity                Print this vault's public sharing identity. Not a
                         secret — send it to whoever wants to share with you.
share --prefix P --to ID --output FILE [--max-tier N] [--note TEXT]
                         Seal every key under P to a teammate's identity,
                         producing a bundle only they can open. Tier-4 keys
                         are refused; `--max-tier` hands over a strictly
                         weaker capability than you hold.
receive <file> [--dry-run] [--prefix P] [--force]
                         Open a bundle addressed to you and store its
                         entries. `--dry-run` shows key names and tiers
                         without storing or printing anything.
install-hook [path] [--force]
                         Install `scan --staged` as this repo's git
                         pre-commit hook.
direnv-init             Print a direnv integration snippet. Exports the
                         project's prefix (a name), never its secrets.
recover                 Recover vault access using the 24-word recovery
                         mnemonic.
change-passphrase       Change the vault passphrase.
new-recovery-key        Generate a fresh 24-word recovery mnemonic,
                         replacing any existing one. Needed after `migrate`,
                         since a v1 vault's recovery phrase can't be
                         represented in the current format. Printed once,
                         requires the current passphrase.
prompt                  Print a passphrase prompt for session caching, e.g.
                         `export HEARTH_VAULT_PASSPHRASE=$(hearth-vault prompt)`.
                         Prefer `agent` + `unlock`: that env var is inherited
                         by every process you spawn, agents included.
seal                    Seal the vault passphrase to TPM2, the OS keyring, or
                         root-owned systemd credentials for auto-unlock.
shell-init [bash|zsh|fish]
                         Print a snippet for your shell rc file that defines
                         an `hv` wrapper (`hv npm run dev` runs the command
                         through `exec` for the current project's prefix).
                         Does not export anything into your interactive
                         shell itself.
project-prefix          Print the prefix from the nearest `.hearth-vault`
                         marker file, walking up from the current directory.
```

If you have secrets scattered across `.env` files, shell rc exports, and
source code rather than one tidy file, see
**[MIGRATING.md](MIGRATING.md)** for the full path from there to a
vault-backed project, including `scan`, `--adopt`, and per-project setup
with `shell-init` / `project-prefix`.

## Backends by platform

`hearth-vault` picks the strongest backend it can find at startup, or you can
force one with `--backend`:

| OS      | Tier 1 (default when available)      | Tier 2 fallback |
|---------|---------------------------------------|------------------|
| Linux   | TPM2 (opt-in `tpm2` build feature) or the Secret Service via the OS keyring (`os-keyring` feature, on by default) | `systemd-creds` host sealing for root-owned headless services; otherwise interactive software vault |
| macOS   | Keychain (`os-keyring`)               | software vault |
| Windows | Credential Manager (`os-keyring`)     | software vault |

The `tpm2` feature links `libtss2-esys`, a C library, so it is not compiled
in by default — a plain install never needs it. Enable it explicitly by
appending `--features tpm2` to the install command above, on Linux where a
TPM2 chip is present. The OS keyring needs no system packages: the
Linux backend speaks D-Bus directly (zbus, pure Rust) rather than linking
libsecret.

For a headless Linux service running as root with neither TPM nor Secret
Service, `--backend systemd-creds` uses `systemd-creds --with-key=host` to
seal the vault passphrase. This is host-bound OS protection, not hardware
protection: root compromise can recover it, and a host key on unencrypted
media does not protect against full-disk acquisition. Use `init-machine` so
the random passphrase is never printed and the recovery mnemonic is delivered
only as a bundle encrypted to a separately held Hearth Vault identity.

### If the OS keyring hangs or gets skipped

A **locked** keyring answers reads instantly but blocks writes while waiting
on an unlock prompt — and in an SSH session, a CI job, or an agent tool call
there is nobody to answer it. `hearth-vault` will not wait forever: keyring
reads and writes are time-bounded (30s by default; set
`HEARTH_VAULT_KEYRING_TIMEOUT_SECS` to change it) and you get an error naming
the cause instead of a wedged terminal.

To see exactly which step is at fault:

```sh
cargo run --example keyring_probe
```

Then unlock your keyring (Linux: your keyring UI or `secret-tool`; macOS:
Keychain Access) and retry, or use a different tier.

The vault file itself lives at the OS-standard application-data directory
(`$XDG_DATA_HOME/hearth-vault/vault.json` on Linux, `~/Library/Application
Support/hearth-vault/vault.json` on macOS, `%APPDATA%\hearth-vault\vault.json`
on Windows), overridable with `--vault-path` or the `HEARTH_VAULT_HOME`
environment variable.

## Storage format

The vault is one AEAD blob (AES-256-GCM) over the entire vault body — secret
values, names, tiers, and timestamps are all encrypted together, so there is
no plaintext inventory of key names on disk and no way to swap ciphertext
between two entries. The blob is decrypted with a random 256-bit data key,
which is itself independently wrapped by two things: your passphrase
(Argon2id) and, if you generate one, a 24-word BIP39 recovery mnemonic. See
`SECURITY.md` for the full cryptographic detail.

## Using it with coding agents

The point of the tool is that an agent can *use* your credentials without
*seeing* them, and that only works if the agent knows which commands are safe.
Three drop-in files do that, and none of them require the agent to be clever:

- **[`AGENTS.md`](AGENTS.md)** — the convention Codex, Cursor, Aider and
  others read automatically. Copy it into your own project's root (or append
  it to the one you already have).
- **[`skills/hearth-vault/SKILL.md`](skills/hearth-vault/SKILL.md)** — a
  Claude Code skill. Install it per-project or for every project:

  ```sh
  mkdir -p ~/.claude/skills/hearth-vault
  cp skills/hearth-vault/SKILL.md ~/.claude/skills/hearth-vault/
  ```

- **[`USAGE.md`](USAGE.md)** — recipes for humans: replacing a `.env` file,
  shell-rc wiring that does not export secrets into every process, CI,
  rotation, docker compose.

The short version of all three: agents run `hearth-vault exec -- <command>`
and `hearth-vault sign`; they never run `export-env`, never `cat` a `.env`,
and never put a value in a variable they might later echo.

### Redacting a child's output

Vault injection keeps a secret out of the environment you can see — but the
child process you exec'd can still print it right back: an API that echoes
an injected key in a response body, a script that interpolates a DSN
password into its own log line, a stack trace with a secret baked into a
URL. Whatever reads that output next (a human terminal, or an agent whose
whole transcript gets sent off-box) now has the value too.

`hearth-vault exec --redact --prefix P -- <command...>` (equivalently,
`HEARTH_VAULT_REDACT=1`) scrubs every injected secret's value — and its
URL-percent-encoded form, where that differs from the raw value — out of
the child's stdout and stderr, replacing each occurrence with
`<vault:KEY_NAME>`. It is binary-safe and streaming: a value split across
two chunks of output is still caught, and if one secret's value happens to
be a substring of another's, the longer one wins outright rather than
getting shredded around a false match. Values under 8 bytes are never
redacted — anything shorter collides too easily with ordinary output.

**`--redact` is OFF by default, and stays that way for a reason.** Some
consumers deliberately capture `exec`'s output *as* the value:

```sh
DATABASE_URL="$(hearth-vault exec --prefix myapp/ -- sh -c 'printf %s "$DATABASE_URL"')"
```

Turn on `--redact` for that invocation and the capture gets the literal
string `<vault:DATABASE_URL>` instead of the real value — which is exactly
what you want for a value you are about to *hand to a human or an agent to
read*, and exactly what breaks a deploy script relying on the value itself.
Reach for `--redact` when the child's output is something you (or an
agent) might read or forward; leave it off when the output *is* the
credential you asked `exec` to hand back.

One more trade-off: `--redact` forces the child's stdout/stderr to be
captured through a pipe instead of inherited straight from your terminal.
For a fully interactive program (one reading raw terminal input, resize
events, etc.) that can change behavior; plain `exec` (no flag) still gives
an unmodified TTY passthrough.

### Sealing a secret-holding process

**Real incident, 2026-09-04:** an AI coding agent read a live credential
straight out of `/proc/<pid>/environ` of a process `hearth-vault exec`
had launched — the SAME uid, no privilege escalation, just `cat
/proc/<pid>/environ` (or `ps eww -p <pid>`, which shows the same thing).
`hearth-vault` was not compromised; the injected value was sitting in
plain sight in a place any other process running as you can already read.

**`hearth-vault` cannot fix this for you.** The natural instinct is "have
`exec`'s parent process call `prctl(PR_SET_DUMPABLE, 0)` before starting
the child." Measured directly: it does not survive `execve`. The kernel
resets `dumpable` to `1` on a normal exec, so anything the parent sealed
about itself has no effect on the child's own process image. **Only the
child calling this on itself, after its own exec, actually closes
`/proc/<pid>/environ` (and `/mem`, `/maps`) to another same-UID reader** —
measured: `stat -c %U /proc/<pid>/environ` flips from your username to
`root`, and `ps eww -p <pid>` stops showing the value.

Add this as close to the top of your process's `main()`/entrypoint as
possible — before anything touches the injected secret:

**Go** (no new dependency — `syscall.SYS_PRCTL`):

```go
// Linux only. PR_SET_DUMPABLE = 4.
if runtime.GOOS == "linux" {
    syscall.RawSyscall(syscall.SYS_PRCTL, 4 /* PR_SET_DUMPABLE */, 0, 0)
}
```

**Rust** (`libc` crate, already a near-universal transitive dependency):

```rust
#[cfg(target_os = "linux")]
{
    // SAFETY: prctl(PR_SET_DUMPABLE, 0) takes no pointer arguments and
    // cannot fault; best-effort, so a nonzero (failure) return is ignored.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0); }
}
```

**C:**

```c
#include <sys/prctl.h>
#ifdef __linux__
    prctl(PR_SET_DUMPABLE, 0);
#endif
```

**Python** (via `ctypes`, no dependency):

```python
import sys
if sys.platform == "linux":
    import ctypes
    PR_SET_DUMPABLE = 4
    ctypes.CDLL("libc.so.6", use_errno=True).prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)
```

**Node.js** has no built-in `prctl` binding; shell out to a tiny helper or
accept the exposure — there is no in-process option without a native
add-on.

**What this buys you, and what it does not:**

- Closes `/proc/<pid>/environ`, `/mem`, and `/maps` to every OTHER process
  running as you — the exact mechanism behind the incident above.
- Disables core dumps for that process. For a secret-holding process this
  is a feature, not a side effect: a crash can no longer write your
  injected secrets to a core file on disk.
- Blocks `gdb`/`delve`/`strace -p` attach from the process owner too — a
  real debugging cost, worth knowing about before you hit it at 2am.
- Does **NOT** protect `/proc/<pid>/cmdline` (argv) — a secret passed as a
  command-line argument is exposed regardless of sealing. Never put a
  secret in argv; that rule doesn't go away.
- Does **NOT** stop a same-UID attacker who can simply run `hearth-vault
  exec` (or `hearth-vault agent` + `unlock`) themselves — sealing closes
  one concrete, measured hole in an already-running process; it is not a
  substitute for controlling what an agent with shell access is allowed to
  run at all (see "Limitations" below).

**Verifying it worked:**

```sh
hearth-vault exec --prefix myapp/ --warn-unsealed -- ./start-server
```

prints a stderr warning naming the exposure if the child you just started
did not seal itself. To audit something already running (a systemd unit,
a long-lived daemon you didn't just launch):

```sh
hearth-vault seal-check --unit myapp.service
hearth-vault seal-check --all --prefix myapp/
```

`seal-check` reports SEALED or READABLE per process, and for a READABLE
one, whether any of its exposed environment variable *names* match a name
this vault would generate — never a value, only a name. Both commands are
best-effort and Linux-only (the underlying probe needs `/proc`); on other
platforms `--warn-unsealed` is a silent no-op and `seal-check` refuses
outright rather than reporting something it cannot actually check.

## Limitations

Read this section before deciding this tool is sufficient for your threat
model. It is not a substitute for judgment about what you run.

- **The exact-value protections only catch the exact value.** `exec`,
  `export-env`, and friends stop a secret from appearing verbatim on a
  stream you or an agent can read. They cannot stop an agent (or malicious
  child process) that has already received a secret in its environment from
  re-encoding it, deriving something from it, or exfiltrating it through a
  side channel — network access, a written file, base64, a slightly
  transformed copy. If the child process you `exec` into is untrusted, tier
  3 use-only secrets don't cover it either, because signing and token-minting
  still hand *derived* material (a signature, a token) back to the caller.
- **The software tier is only as strong as your passphrase.** Tier 2 and the
  passphrase wrap on tier 1 both ultimately reduce to Argon2id over whatever
  passphrase you chose. A weak or reused passphrase is a weak vault,
  regardless of the KDF parameters protecting it.
- **Windows tier-1 support is keyring only.** There is no TPM-backed
  (CNG/Windows Hello for Business) tier-1 implementation yet — Windows gets
  Credential Manager as its strongest backend, not a hardware root of trust.
- **This project has not had an external security audit.** It uses
  well-reviewed primitives (AES-256-GCM, Argon2id, HKDF, BLAKE3, BIP39) and a
  straightforward key hierarchy, but "built on good primitives" and
  "independently audited" are different claims. Treat it accordingly for
  high-value secrets until an audit has happened.
- **`scan` finds exact values and known shapes, not everything.** It matches
  literal secret values already in the vault plus a fixed set of recognizable
  formats (cloud/API key prefixes, PEM headers, connection strings, JWTs, a
  high-entropy generic pattern). It has no way to catch a secret that's been
  derived, re-encoded, or partially transformed, and it is not a substitute
  for reviewing what you commit.
- **Sharing gives you confidentiality, not sender authenticity.** A bundle
  proves its maker knew the recipient's public key; it does not prove who
  made it. Confirm a teammate's fingerprint out of band, the way you would an
  SSH host key. Sharing is also a copy and cannot be revoked — un-sharing
  means rotating at the provider.
- **The unlock agent does not defend against a process running as you.**
  Its socket is `0600` in a `0700` directory and every peer is checked with
  `SO_PEERCRED`, which keeps other *users* out. Anything with your uid can
  already read `/proc/<pid>/environ` of the children `exec` creates. The
  agent is strictly better than the `HEARTH_VAULT_PASSPHRASE` env var it
  replaces — bounded lifetime, not inherited, holds a per-vault wrap key
  rather than the passphrase — and it is not a substitute for tier 4.
  Unix only.
- **Rotation dates are a reminder, not an enforcement.** Nothing stops you
  using an overdue credential, and the vault has no way to know whether the
  old value was actually revoked at the provider. Replacing a value here is
  half of a rotation; the other half happens on someone else's dashboard.
- **A compromised machine defeats this tool, by design of the threat model
  it targets.** See `SECURITY.md` for exactly what is and is not in scope.

## License

Licensed under either of [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE) at your option.
