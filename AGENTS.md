# Instructions for coding agents working in a hearth-vault project

You (Codex, Cursor, Aider, Claude Code, or any other agent with shell access)
are working in a project that stores its credentials in `hearth-vault`
instead of a `.env` file or shell exports. These rules exist because your
tool-call output — stdout, stderr, any file you read — is typically captured,
logged, and forwarded to a model provider. A secret value that reaches your
output has left the machine. Follow this exactly.

## The one rule

**Never read, echo, cat, print, log, or write a secret value anywhere.** Not
in a shell command's output, not in a code sample, not in a commit message,
not in a comment "for reference." If a value from the vault appears in
anything you are about to output, stop and use a different approach from
this document instead.

## Running something that needs credentials

Use `exec`. It injects secrets into the *child process's* environment; you
receive only the exit code and whatever non-secret output that process
produces. You never receive the value itself.

```sh
# In a project with a `.hearth-vault` marker, --prefix is optional and you
# should omit it rather than guess:
hearth-vault exec -- npm run dev

hearth-vault exec --prefix myapp/ -- npm run dev
hearth-vault exec --prefix myapp/ -- python manage.py migrate
# Note the single quotes and the `sh -c`: the env var is expanded by the
# CHILD, after injection. Double quotes would make your own shell expand
# $API_KEY to an empty string before hearth-vault ever ran.
hearth-vault exec --prefix myapp/ -- sh -c 'curl -H "Authorization: Bearer $API_KEY" https://api.example.com/status'
```

The prefix maps to env var names by stripping the prefix, uppercasing, and
turning `/` and `-` into `_` (`myapp/database-url` -> `DATABASE_URL`). If the
project has a `.hearth-vault` marker file at its root, the prefix is its
contents — read it (`cat .hearth-vault` is safe; it holds a plain string, not
a secret) instead of guessing.

If you need to sign something with a private key, or mint a GitHub App
token, without the key material ever existing outside the vault process:

```sh
hearth-vault sign --key myapp/signing-key --algorithm RS256 --message "<data>"
hearth-vault github-app-token --installation-id 123456789
```

Both print only the derived output (a signature, a token) — never the key.

## Adding a NEW secret

You cannot see the value and must not try to. Tell the human operating the
session to run this themselves, in their own terminal:

```sh
hearth-vault set myapp/new_service_key
```

They will be prompted for the value with hidden input. Once they confirm
it's stored, you write the application code that reads it from the
environment at runtime — you never see or need the literal value to do that.
Do the same for a file-based credential:

```sh
hearth-vault import /path/to/downloaded-cert.pem --key myapp/tls_cert
```

If a `.env` file exists in the project and you're asked to migrate it, direct
the human to run (do not run this yourself if it would put values through
your own output — `import-env` does not print the values, so this one is
safe for you to run):

```sh
hearth-vault import-env .env --prefix myapp/
```

## Writing application code that consumes vault-injected env vars

Read from the environment once, at process startup. Never log the raw value
at any point — not in a debug print, not in an error message, not in a
stack trace. If a request against the credential fails, log that it failed,
not what was sent.

**Rust:**

```rust
let api_key = std::env::var("API_KEY")
    .expect("API_KEY not set — run via `hearth-vault exec --prefix myapp/`");
// never: println!("using key {api_key}");
let client = build_client(&api_key);
```

**Python:**

```python
import os

api_key = os.environ["API_KEY"]  # KeyError if missing -- fail loudly, don't default to ""
# never: print(f"key: {api_key}") or logger.debug(f"...{api_key}")
client = build_client(api_key=api_key)
```

**Node:**

```javascript
const apiKey = process.env.API_KEY;
if (!apiKey) throw new Error("API_KEY not set — run via hearth-vault exec");
// never: console.log(`using key ${apiKey}`);
const client = buildClient({ apiKey });
```

In all three: no default-empty-string fallback (that turns a missing
credential into a confusing downstream failure instead of a clear one at
startup), and no redaction-after-the-fact — the discipline is to never put
the value where it would need redacting.

## Rotation

Rotating a credential is the same action as storing one: `hearth-vault set
<key>` keeps the key's tier and moves its due date forward by itself. There
is no "mark as rotated" step, so do not build one or ask the human for one.

```sh
hearth-vault list --due       # what is overdue (exit 1 if anything is)
hearth-vault list --due 7     # what comes due within a week
```

Both are safe for you to run: names and dates only. The `set` itself is the
human's job, since it needs the new value.

Say plainly when a rotation is *not* finished: replacing the value in the
vault does nothing about the old one, which stays live at the provider until
someone revokes it there.

## Handing a credential to a teammate

Never paste a value into a message, a ticket, or a PR. Seal it instead —
the value is encrypted to the recipient and neither of you sees it:

```sh
hearth-vault identity                      # your public identity; not a secret
hearth-vault share --prefix myapp/ --to <their-identity> --output bundle.hvs
hearth-vault receive bundle.hvs --dry-run  # key names + tiers, never values
hearth-vault receive bundle.hvs            # store them
```

Tell the human to confirm the recipient's fingerprint over a different
channel first: a bundle proves its maker knew the recipient's public key,
not who the maker was. Tier-4 keys are refused outright.

Do not open a `.hvs` file to inspect it — use `--dry-run`.

## If commands keep prompting for a passphrase

Ask the human to start the unlock agent. Do **not** work around it by
setting `HEARTH_VAULT_PASSPHRASE` in your own shell — that variable is
inherited by every process you spawn, which is exactly the exposure this
tool exists to prevent.

```sh
hearth-vault agent --daemon    # human runs this once
hearth-vault unlock            # human types the passphrase once
```

## If a secret leaks into your own output or the transcript

Stop what you're doing. Do not attempt to fix it by deleting the message —
if you are talking to a model provider, the value has already left the
machine over the network the moment it appeared in your context. Assume it
is compromised.

1. Tell the human immediately: which secret, and roughly how it happened
   (e.g. "I ran `cat .env` and the output included `API_KEY=...`").
2. Rotate it. If it's already in the vault at a printable tier:
   ```sh
   hearth-vault set myapp/api_key          # store a new value at the same key (human runs this)
   hearth-vault exec --prefix myapp/ -- ./scripts/smoke-test.sh   # verify the new value works
   ```
   If it was never in the vault (e.g. leaked straight from a `.env` file),
   the human rotates it at the origin (the provider's dashboard) first, then
   stores the new value: `hearth-vault set myapp/api_key`.
3. Confirm the old value is fully retired at the provider (revoked API key,
   rotated database password) — not just replaced in the vault. A vault
   rotation does nothing if the leaked value is still live upstream.

## Forbidden commands (from an agent's own shell)

- `hearth-vault export-env ...` / `export-env-file ...` — these print or
  write the raw value; that's exactly what you must not receive. They also
  refuse by default when stdout isn't a TTY, which your shell is not — but
  do not work around that refusal with `HEARTH_VAULT_ALLOW_NON_TTY=1`. That
  variable exists for human-controlled CI/systemd invocations, not for you
  to unblock yourself.
- `hearth-vault prompt` — prints the vault passphrase itself.
- `cat`/`less`/`head`/`tail`/any read of `vault.json` directly, or of any
  file you know to hold exported secret material.
- `export FOO=$(hearth-vault ...)` in your own shell session, or any command
  that would set a secret as a shell variable you might subsequently echo,
  log, or pass to another tool call.
- Retiering a key to make it exportable (`hearth-vault retier <key> --tier
  2`) purely so you can read it. If a task seems to require this, that's a
  sign the task should be redesigned around `exec`/`sign`, not a reason to
  weaken the tier.

## Allowed commands (safe for an agent to run directly)

- `hearth-vault exec --prefix <p> -- <command>` — the primary path.
- `hearth-vault sign ...`, `hearth-vault github-app-token ...` — derived
  output only.
- `hearth-vault list`, `hearth-vault has <key>`, `hearth-vault status` —
  metadata only, never values.
- `hearth-vault import-env <file> --prefix <p>` — migrates a `.env` file
  into the vault without printing any of its values.
- `hearth-vault scan [path]` — reports secret-shaped strings by redacted
  match, never a usable value; safe to run and safe to act on its (redacted)
  report. `--staged` limits it to what is staged for commit.
- `hearth-vault install-hook` — installs the pre-commit scan in this repo.
  Safe and worth suggesting when you notice a repo without it.
- `hearth-vault list --due [N]`, `hearth-vault list --json` — rotation state,
  metadata only.
- `hearth-vault identity`, `hearth-vault share ...`, `hearth-vault receive
  <file> [--dry-run]` — sharing; values stay encrypted end to end.
- `hearth-vault backup` — an encrypted snapshot. Needs no passphrase, prints
  no values.
- `hearth-vault project-prefix`, `cat .hearth-vault` — read the project's
  prefix marker, which holds no secret material.
