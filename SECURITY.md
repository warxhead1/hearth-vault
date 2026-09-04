# Security Policy

## Threat model

### In scope — what this defends against

- **Secrets ending up in an AI agent's transcript, tool-call log, or a
  third-party model's context window.** The `exec`, `sign`, and
  `github-app-token` commands exist specifically so an agent can drive a
  credentialed operation without ever receiving the credential itself on a
  stream it reads or forwards.
- **Secrets living in plaintext in `.env` files, shell history, or shell
  scripts.** Storing a value in the vault instead removes it from those
  locations; `set` reads from hidden-input prompt, never a CLI argument.
- **Secrets committed to git.** Values never need to touch a working tree;
  `.gitignore` in this repository itself excludes `vault.json` and related
  artifacts for the same reason.
- **A stolen vault file at rest.** The vault file is a single AES-256-GCM
  blob; without the passphrase or the recovery mnemonic, an attacker with a
  copy of `vault.json` has ciphertext and nothing else — no plaintext key
  names, no partial structure to attack entry-by-entry.
- **Accidental disclosure through routine command output.** The non-TTY
  refusal (see `README.md`) targets the specific case of a value getting
  printed to a pipe an agent or script forwards elsewhere, as opposed to a
  human watching a terminal.

### Out of scope — what this does NOT defend against

- **A fully compromised machine.** If an attacker has arbitrary code
  execution as your user, they can read `HEARTH_VAULT_PASSPHRASE` from your
  environment, key-log your passphrase entry, or wait for you to run `exec`
  and read the secret out of the child process's memory before it exits.
  Vault encryption at rest protects the file on disk; it does not protect a
  live, unlocked vault process from the OS user that owns it.
- **A malicious or compromised child process you `exec` into.** `exec`
  injects secrets into the *environment you asked it to run*. If that
  command is itself malicious, or is compromised (a supply-chain attack in a
  dependency it loads), it received the secret in good faith and can do
  whatever it wants with it. `hearth-vault` cannot audit what the child does
  with a value once handed over.
- **An agent that can run arbitrary commands as you.** If an agent has shell
  access to run `hearth-vault exec` or `hearth-vault sign` at all, it can
  drive any operation those commands support. Tier 3 stops an agent from
  reading a raw key value out of the vault; it does not stop the agent from
  using that key's *capability* (signing arbitrary messages, minting tokens)
  if it can invoke the command that wraps it. Scope what an agent is allowed
  to run, not just what secrets it can see.
- **Memory scraping by root, or a kernel-level attacker.** Zeroization on
  drop (`SensitiveString`, `zeroize` throughout) reduces the window a secret
  sits in process memory, but it does not defend against a privileged
  process reading another process's memory directly, a core dump captured
  before `disable_core_dumps()` takes effect, or a swapped page written to
  disk by the OS.
- **A weak passphrase.** No amount of KDF tuning turns a guessable
  passphrase into a strong one. The software tier's security ceiling is set
  by your passphrase.
- **Another process running as your own user.** This bounds the unlock
  agent specifically. Its socket keeps *other users* out (`0600` in a `0700`
  directory, plus an `SO_PEERCRED` uid check). The agent is a strict
  improvement on the `HEARTH_VAULT_PASSPHRASE` environment variable it
  replaces — bounded lifetime, not inherited by children, invisible to `ps`
  and `environ`, and holding a per-vault wrap key rather than the
  passphrase — and it is not a same-machine isolation boundary.

  **UPDATED 2026-09-04** (an earlier version of this bullet said flatly that
  "anything running as you can already read `/proc/<pid>/environ` of the
  children `exec` creates" — that is still true of an UNSEALED consumer and
  is narrowed, not retracted, below; the same day, a same-UID AI coding agent
  read a live credential straight out of `/proc/<engine-pid>/environ` for a
  process launched via `hearth-vault exec --prefix tachyonac/`):

  - **An unsealed consumer is still fully exposed, unchanged from before.**
    `hearth-vault exec`'s parent process CANNOT close this for the child it
    launches: `prctl(PR_SET_DUMPABLE, 0)` does not survive `execve` (measured
    directly — the kernel resets `dumpable` to 1 on a normal exec), so only
    the child calling it again, itself, after its own exec, has any effect.
    Any process that hasn't adopted this — which is most of them today — has
    its full environment (including whatever `exec` injected) readable by
    any other process running as you: `cat /proc/<pid>/environ`, `ps eww -p
    <pid>`, an AI agent's shell tool. See README.md "Sealing a
    secret-holding process" for the fix, and use `hearth-vault exec
    --warn-unsealed` or `hearth-vault seal-check` to find out which of your
    consumers this applies to.
  - **A sealed consumer closes `/proc/<pid>/{environ,mem,maps}` to same-UID
    readers** (measured: `stat -c %U /proc/<pid>/environ` flips from the
    real user to `root`; `ps eww -p <pid>` stops showing the value), which is
    the actual fix for the incident above. It does NOT close everything:
    `/proc/<pid>/cmdline` (argv) stays readable regardless of sealing — never
    put a secret in argv — and a same-UID attacker who cannot read the
    sealed process's memory can still simply run `hearth-vault exec` (or
    `hearth-vault agent` + `unlock`) themselves to obtain the same
    capability the sealed process holds. Sealing closes one concrete,
    measured hole; it is not a substitute for "an agent that can run
    arbitrary commands as you" two bullets below, which remains fully out of
    scope.
  - **An ancestor of a sealed process is unaffected by the child's own
    seal.** Sealing is per-process, not inherited backwards: the vault
    process and the systemd-unit's shell wrapper (if any) each need their
    own call to be closed off, and `hearth-vault` itself already does this
    (`disable_core_dumps()`, first line of `main()`) — measured: its own
    `/proc/<pid>/environ`, and the persisted `hearth-vault agent --daemon`
    child (survives via `fork()`, which inherits the dumpable flag, unlike
    `execve`), are both `root`-owned while running.
- **Who sent you a share bundle.** Bundle confidentiality is real: only the
  holder of the target identity can open one, and tampering fails closed.
  Sender authenticity is *not* provided — an ephemeral sender key means a
  bundle proves only that its maker knew the recipient's public key. Anyone
  can send you a bundle claiming to be anyone, so confirm a fingerprint out
  of band before `receive`, exactly as you would an SSH host key. Signed
  bundles are a reasonable future addition; claiming this already does it
  would be worse than saying it does not.
- **Anything after a value reaches a teammate.** Sharing is a copy. There is
  no revocation, no expiry on a bundle, and no way to un-send one. The only
  way to withdraw a shared credential is to rotate it at the provider.
- **Whether a rotation actually happened.** `--rotate-days` and `--expires`
  track a date. They cannot know whether the old value was revoked upstream,
  and nothing prevents an overdue credential from being used. A vault-side
  rotation is half of a rotation.

## Cryptography

- **AEAD:** AES-256-GCM. Every encryption call is bound to a fixed,
  purpose-specific AAD string (`hv2:wrap:passphrase`, `hv2:wrap:recovery`,
  `hv2:vault`) so a ciphertext from one context can never be replayed as
  valid input to another.
- **Key derivation from passphrase:** Argon2id, `m=65536` KiB (64 MiB),
  `t=3`, `p=4`. These parameters are stored per-vault in the vault file
  itself (not hardcoded into the binary), so a future version can raise them
  for new vaults without breaking the ability to read older ones.
- **Subkey derivation:** HKDF-SHA3-256, used to derive context-bound subkeys
  from a master key rather than reusing one key across purposes.
- **Integrity hashing:** BLAKE3, used where a fast keyed/unkeyed hash is
  needed outside the AEAD boundary.
- **Recovery:** a 24-word BIP39 mnemonic (with its standard checksum) is
  generated at `init` time and independently wraps the vault's data key,
  exactly like the passphrase does. Either one alone is sufficient to
  recover the vault; losing both means the vault is unrecoverable by design
  — there is no backdoor key.
- **Key hierarchy:** a random 256-bit data key encrypts the entire vault
  body (entry names included, not just values) as one AEAD blob. The
  passphrase and the recovery mnemonic each wrap that data key
  independently, so changing your passphrase rewraps the data key without
  touching or re-encrypting any stored entry.
- **Sharing:** X25519 ECDH to an ephemeral sender key, HKDF-SHA3-256 over
  the shared secret salted with `epk ‖ recipient_pub`, then AES-256-GCM
  under the `hv1:share:v1` AAD. A vault's X25519 identity is derived from
  its data key via HKDF (`share-identity-x25519`), so there is no second
  private key to store, back up, or lose, and a restored backup keeps the
  same public identity. The ephemeral sender key means two bundles to the
  same recipient share no key material and the sender's own identity is not
  revealed by the bundle. **Bundles are confidential but not
  sender-authenticated** — see the threat model below.

## The unlock agent

`hearth-vault agent` caches the passphrase-derived **wrap key** — not the
passphrase, and not the data key. Both exclusions are deliberate:

- **Not the passphrase.** The secret a human is likely to have reused
  elsewhere never leaves the process that read it, and a compromised agent
  cannot be used to change the passphrase of record or answer a prompt
  somewhere else.
- **Not the data key.** A wrap key is bound to the current
  `wrap.passphrase.salt`, so `change-passphrase` re-salts and invalidates
  every cached copy the instant it runs. A cached data key would survive a
  passphrase change, which is exactly the wrong behaviour.

Access control is the socket: `0600`, inside a `0700` directory under
`$XDG_RUNTIME_DIR` (tmpfs, cleared at logout), with every connection checked
against `SO_PEERCRED`/`getpeereid` to confirm the peer's uid is ours. Keys
expire on a per-entry TTL (default 900s) and `lock` clears them immediately.

This is a same-user boundary, not a same-machine one — see the threat model.
Unix only: Windows has no `AF_UNIX` in std, and its answer to the same
problem is `seal` against the OS keyring, which has no per-invocation KDF
cost to amortise in the first place.

## Network behaviour — no telemetry, no phone home

`hearth-vault` has **no analytics, no crash reporting, no update check, and no
license or activation call**. It does not open a socket at startup, on `init`,
on `set`, on `exec`, or on any other command you might run a hundred times a
day.

There is exactly **one** command in the whole tool that touches the network:
`github-app-token`, which POSTs to `api.github.com` to exchange a signed JWT
for a GitHub App installation token. That is the operation you asked for; it
cannot happen unless you type it.

You do not have to take that on faith. Three checks, in increasing strength:

```sh
# 1. Every outbound URL in the source. Expect exactly one hit.
grep -rn 'https\?://' src/ --include='*.rs'

# 2. The HTTP client is a build feature. Compile without it and there is no
#    HTTP client in the binary at all -- nothing to call, whatever the code says.
cargo build --no-default-features --features os-keyring
cargo tree --no-default-features --features os-keyring -e normal | grep -i reqwest   # no output

# 3. Watch it. Nothing should appear except when you run github-app-token.
strace -f -e trace=network hearth-vault set demo/key      # Linux
```

CI runs checks 1 and 2 on every push (the `no-network-build` job), so a new
call site added anywhere in the tree fails the build rather than shipping
quietly.

Two honest caveats:

- The OS-keyring tier talks to your **local** credential store over D-Bus
  (Linux) or a platform API (macOS/Windows). That is IPC on your own machine,
  not network traffic, but it will show up in a syscall trace.
- `exec` runs the command **you** name with secrets in its environment. If that
  command phones home, it does so with your credential. `hearth-vault` cannot
  police what a child process does; see the threat model above.

## Release artifacts — what is and isn't guaranteed

Every tagged release is built by GitHub Actions from the tagged commit, on a
stock runner of the target architecture. Nothing is cross-compiled, so each
binary was produced by the real toolchain for the platform it claims. The
workflow is [`.github/workflows/release.yml`](.github/workflows/release.yml)
— plain and readable on purpose, because the build pipeline for a secrets
tool should be auditable without trusting a release-automation framework.

**Verify what you download.** Each artifact ships a `.sha256`, and the
release carries a combined `SHA256SUMS`:

```sh
sha256sum -c --ignore-missing SHA256SUMS
```

Two things these artifacts do **not** currently give you:

- **They are not code-signed.** macOS Gatekeeper and Windows SmartScreen
  will warn on first run. Signing needs an Apple Developer ID and an
  Authenticode certificate held as repository secrets; neither is set up
  yet. Until then, checksum verification is the check that matters — or
  build from source:
  `cargo install --locked --git https://github.com/warxhead1/hearth-vault`.
- **The build is not reproducible.** An identical rebuild is not
  bit-for-bit guaranteed, so a checksum proves *what CI produced*, not
  independently *what the source implies*.

### What tier 2 needs at runtime

The OS-keyring tier stores the secret in the platform credential store, and
that store has to actually be there and unlocked:

- **Linux** — a Secret Service daemon (GNOME Keyring, KWallet, …) on the
  session bus. `hearth-vault` talks D-Bus directly via zbus, so there is no
  libsecret to install and even the static `x86_64-unknown-linux-musl`
  artifact supports this tier. On a headless box with no such daemon, the
  keyring reports unavailable and the software tier is used instead.
- **macOS** — the default Keychain. **Windows** — Credential Manager.

A **locked** keyring is the awkward case: it answers reads immediately but
blocks writes waiting on an unlock prompt, which an SSH session, a CI job, or
an agent tool call cannot answer. Rather than hang, every keyring operation
runs under a deadline (30s by default,
`HEARTH_VAULT_KEYRING_TIMEOUT_SECS` to change) and fails with a message
naming the cause.

TPM2 (tier 1) is a separate opt-in build feature and is in no prebuilt
artifact at all; it must be compiled in with `--features tpm2`.

## What is verified, on what, and by whom

Being explicit about this matters more than a green badge: a test that
silently skips reads exactly like a test that passed.

| Claim | Where it is proven | Strength |
|---|---|---|
| Builds + full test suite | Linux, macOS, Windows on every push | real |
| Tier 2 on macOS Keychain | macOS CI, real Keychain | real |
| Tier 2 on Windows Credential Manager | Windows CI | real |
| Tier 2 on Linux Secret Service | Linux CI, gnome-keyring on a private D-Bus | real |
| Tier 1 TPM2 seal/unseal | Linux CI, **swtpm simulator** | logic only |
| Tier 1 on real TPM hardware | opt-in self-hosted runner (`selfhosted.yml`) | real, but only when a maintainer runs it |
| PCR0 actually resists a firmware change | **nowhere** — needs a reboot into changed firmware | manual |
| Vault file permissions (Unix mode) | Linux + macOS CI | real |
| Vault file DACL (Windows) | Windows CI, verified independently with `icacls` | real |
| No HTTP client without the feature | Linux CI dependency-graph assertion | real |
| Static musl artifact is really static | Linux CI, `ldd` dependency check | real |

The tier-2 tests are deliberately two-instance (seal with one backend handle,
unseal with a second): a single-instance roundtrip passes against an in-memory
mock, which is how a mock backend once masqueraded as a working keyring on
every platform at once. `HEARTH_VAULT_REQUIRE_KEYRING=1` and
`HEARTH_VAULT_REQUIRE_TPM2=1` turn "no backend here" from a skip into a
failure, so a job cannot pass having exercised nothing.

## Adversarial review

An independent adversarial pass (an AI agent driven with a falsify-these-nine-
claims brief, 2026-08-15, against commit `36dc654`) went looking for ways to
get a secret out. Findings were re-verified by hand before anything was
changed; several did not survive that check, and the ones that did are listed
here with what happened to them.

**Fixed as a result:**

- **The non-TTY guard only inspected stdout.** The recovery mnemonic banner
  and all prompts go to *stderr*, so `hearth-vault init 2>mnemonic.log` from
  an ordinary terminal wrote the 24 words that unlock the entire vault into a
  plaintext file, guard satisfied. Both streams are now required.
- **Tier 4 was not a one-way door.** `retier <key> --tier 2` walked a
  sign-only key back to exportable with no prompt, no TTY requirement and no
  proof the caller ever held the value — so anything able to run the binary
  could downgrade a signing key and export it on the next line. Leaving tier 4
  is now refused outright; deleting and re-adding the key is the path, because
  that requires possessing the value.
- **Vault writes were neither atomic nor owner-only from creation.** The old
  path truncated the destination in place and applied permissions *after*
  writing, so a crash mid-save destroyed every secret in the vault, and the
  content existed briefly at the process umask (commonly world-readable). It
  also followed a symlink planted at the destination. All secret-bearing
  writes now go through one helper that creates a temp file at 0600, fsyncs,
  and renames into place.
- **KDF parameters were taken from the vault file unbounded.** They have to be
  used *before* anything can be authenticated, so a hostile file could ask for
  `m = u32::MAX` (about 4 TiB) or `t = u32::MAX` (never returns). Now range-
  checked at the single point every derivation funnels through.
- **The secret scanner missed unquoted assignments entirely.** Its generic
  rule required quotes around the value, so a `.env` file — the one input the
  whole migration story starts from — full of live credentials reported clean.
  Unquoted `KEY=value` is now matched in env-style files (scoped there because
  in source code a bare `token = x` is an ordinary assignment; letting it
  loose produced ~60 false positives on this repository alone).
- **`scan` silently skipped files over 1 MiB.** "No secrets found" over an
  unread 4 MiB `.env.backup` is the worst answer this tool can give. Skips are
  now printed.
- **Zeroization had holes.** The fix was structural rather than a list of
  patches: `decrypt_aes256gcm` now returns `Zeroizing<Vec<u8>>`, so every
  decryption in the crate -- vault body, wrapped data key, PEM private key --
  is wiped on drop whether or not the caller remembers. The remaining
  hand-carried copies were wrapped too: the serialized vault body on its way
  into the encryptor, the hex-encoded master key crossing into the keyring,
  the decoded private-key DER, and the recovery mnemonic (now returned as
  `Zeroizing<String>`).
- **The scanner's overlap de-duplication was quadratic.** Every candidate
  match was compared against every span already claimed on that line, so one
  pathological line with tens of thousands of secret-shaped tokens turned a
  scan into a hang. It is a byte map now: linear in the matched text.
- **Directories holding secrets were not restricted.** A 0600 vault inside a
  0755 directory still lets another local user list it, see its mtime, and --
  if the directory is writable -- rename or replace files in it. The vault
  directory and any `export-env-file` output directory are now tightened to
  0700 (and the equivalent protected DACL on Windows) when they are looser
  than that. A mode that is already private, including a deliberate 0750 with
  a trusted group, is left alone, and a directory whose mode cannot be
  changed warns rather than failing the save. On Windows this is a no-op: the
  first attempt installed the file-style protected DACL on the directory and
  made every subsequent write into it fail (Windows CI caught it), and the
  risk it addresses -- a loose parent directory -- is a Unix mode-bit
  problem. The vault file on Windows already carries its own owner-only DACL.

**Reviewed and deliberately not changed:**

- *"`exec -- printenv TOKEN` prints a tier-3 secret."* Correct, and by design:
  `exec` hands the value to the command you named. It is documented in the
  threat model above and in README's Limitations. A tool that gives a child
  process a credential cannot also stop that child from printing it.
- *"Recovery rotation persists before the new phrase is displayed."* True, and
  the safer of the two orders: if the display is lost the vault still opens
  with the passphrase, whereas displaying first would risk showing a phrase
  that was never stored.
- *v1 migration decrypts with empty AAD.* Deliberate and documented in the
  code: it reads data written before AAD existed. The related observation is
  real though — v1 stored tier metadata unauthenticated, so anyone who could
  write to a v1 vault file could have altered a tier before you migrated.
  **If you are migrating a v1 vault, check `hearth-vault list` tiers
  afterwards.**

Everything the review raised that was verifiable has been fixed or is
explained above. That is still not a substitute for a paid external audit,
which this project has not had.

The structural caveats that remain are the ones in the threat model, not
oversights: zeroization narrows the window a secret sits in memory but cannot
defend against a privileged process reading that memory or the OS swapping the
page out, and nothing here constrains what a command you `exec` into does with
a credential once it has one.

## Reporting a vulnerability

Please do not open a public GitHub issue for a security vulnerability.

Use [GitHub's private security advisory feature](https://github.com/warxhead1/hearth-vault/security/advisories/new)
on this repository to report it. That gives us a private channel to discuss,
reproduce, and fix the issue before any public disclosure, and lets you
request CVE assignment through GitHub once a fix is ready.

If you believe you have found an issue that involves an actual leaked
credential (yours or someone else's), do not include the credential value
itself in the report — describe the mechanism, and rotate the credential
separately.

We do not currently run a paid bug bounty program.
