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

### The musl build has no OS keyring

`x86_64-unknown-linux-musl` is the static, runs-on-any-distro artifact, and
it is built with `--no-default-features`. That is deliberate rather than an
oversight: the OS-keyring tier reaches the Secret Service over D-Bus via
libsecret, which is dynamically loaded and cannot be linked into a static
binary. A musl build advertising keyring support would fail at runtime on
exactly the minimal systems it exists for.

So on the musl artifact, **tier 2 (OS keyring) is unavailable** —
passphrase and recovery-mnemonic wrapping work normally. TPM2 (tier 1) is a
separate opt-in feature and is in no prebuilt artifact at all. If you want
the OS-keyring tier on Linux, use a `-gnu` build.

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
