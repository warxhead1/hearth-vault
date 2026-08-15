---
name: hearth-vault
description: Use when handling credentials, API keys, tokens, or .env files in a project that uses hearth-vault -- running a command that needs a secret, adding a new credential, migrating a .env file, rotating a leaked or expiring secret, or writing code that reads a vault-injected environment variable.
---

# hearth-vault

This project stores credentials in `hearth-vault`, not `.env` files or shell
exports. Your tool output is captured and forwarded off-box; a secret value
that reaches it has leaked. The rule that matters: **never let a raw secret
value appear in anything you output** — no `cat`, no `echo`, no print
statement, no code sample, no commit.

## Decision table

| You need to... | Do this | Never do this |
|---|---|---|
| Run a command that needs a credential | `hearth-vault exec --prefix <p> -- <command>` | Read the value and pass it as an argument or inline env var |
| Sign a request or mint a token from a private key | `hearth-vault sign --key <k> --algorithm <alg> --message <m>` or `hearth-vault github-app-token --installation-id <id>` | Export the private key and sign it yourself |
| Add a brand-new secret | Tell the human to run `hearth-vault set <key>`, then write code that reads the env var it produces | Ask the human to paste the value to you, or run `set` with the value piped in from something you generated and can see |
| Migrate an existing `.env` file | `hearth-vault import-env .env --prefix <p>` (safe for you to run yourself — never prints values) | `cat .env` first "to see what's there" |
| Check whether a key exists | `hearth-vault has <key>` / `hearth-vault list` | `hearth-vault export-env <key> ...` |
| Find secrets scattered in the repo | `hearth-vault scan [path]` (redacted output, safe to run) | Grep for likely key patterns yourself and print matches |
| Read a project's key prefix | `cat .hearth-vault` or `hearth-vault project-prefix` (plain string, not a secret) | Guess the prefix or hardcode one |
| Write code consuming a vault-injected var | `os.environ["X"]` / `process.env.X` / `std::env::var("X")` read once at startup, never logged | Print/log the value anywhere, including in error paths |

## Commands

```sh
# Run something that needs credentials — the only value-bearing path you should use directly
hearth-vault exec --prefix myapp/ -- <command...>

# Derived-output-only operations (private key never leaves the vault process)
hearth-vault sign --key myapp/signing-key --algorithm RS256 --message "<data>"
hearth-vault github-app-token --installation-id 123456789

# Metadata, never values
hearth-vault list
hearth-vault has myapp/api_key
hearth-vault status

# Migrate a .env file without ever seeing its contents
hearth-vault import-env .env --prefix myapp/

# Scan for secrets by shape (redacted report, exit 1 if it finds something)
hearth-vault scan
```

Env var name mapping used by both `exec` and `export-env-file`: strip the
prefix, uppercase, `/` and `-` -> `_`. `myapp/database-url` under prefix
`myapp/` becomes `DATABASE_URL`.

## Tiers (informational — you generally don't choose these)

- Tier 1/2 = exportable (`export-env` works). Tier 3 (default) = use-only,
  `export-env` refuses but `exec`/`sign` still work. Tier 4 = sign-only,
  never injected anywhere, only usable by `sign`/`github-app-token`.
- Do not retier a key to make it exportable just so you can read it. If a
  task seems to need that, the task should route through `exec` or `sign`
  instead — flag it to the human rather than working around the tier.

## Forbidden

- `hearth-vault export-env` / `export-env-file` — prints or writes the raw
  value. Refuses by default off-TTY; do not bypass with
  `HEARTH_VAULT_ALLOW_NON_TTY=1` to unblock yourself — that variable is for
  human-controlled CI/systemd use, not for an agent to self-authorize around
  the refusal.
- `hearth-vault prompt` — prints the vault passphrase.
- Reading `vault.json` or any exported-secret file directly.
- `export FOO=$(hearth-vault ...)` in your own shell, or any pattern that
  would put a secret into a variable you might subsequently echo or forward.
- Writing a secret literal into source, a config file, a log line, or a
  commit — including "example" values copied from a real one.

## Leak response procedure

If a secret value appears in your own output or context for any reason:

1. **Stop.** Do not continue the task as if nothing happened.
2. **Tell the human immediately** — name the secret and how it happened
   (e.g. "ran `cat .env`, output contained `API_KEY=...`"). Assume it is
   compromised the moment it left the machine.
3. **Rotate it:**
   ```sh
   hearth-vault set myapp/api_key                                   # human runs this with the new value
   hearth-vault exec --prefix myapp/ -- ./scripts/smoke-test.sh     # verify the new value works
   ```
   If the leaked value was never in the vault, the human must revoke/rotate
   it at the origin provider first, then store the new value the same way.
4. **Confirm the old value is dead upstream**, not just replaced locally — a
   vault-side rotation does nothing if the leaked credential is still live
   at the provider.

## Reference

Full command list and tier rationale: `README.md`. Migrating a project's
existing secrets: `MIGRATING.md`. Practical recipes (CI, rc-file wiring,
rotation, docker compose): `USAGE.md`. Directive version of this file for
non-Claude agents: `AGENTS.md`.
