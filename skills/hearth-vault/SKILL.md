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
| Rotate a credential | Tell the human to run `hearth-vault set <key>` (the due date advances by itself); check what is due with `hearth-vault list --due` | Retier a key so you can read the old value "to compare" |
| Give a teammate a credential | `hearth-vault share --prefix <p> --to <their-identity> --output bundle.hvs` | Paste a value into a message, a ticket, or a PR |
| Accept a shared bundle | `hearth-vault receive bundle.hvs --dry-run`, then without the flag | Open the bundle file to "check" what is in it |
| Commands feel slow / keep prompting | Tell the human to run `hearth-vault agent --daemon && hearth-vault unlock` | `export HEARTH_VAULT_PASSPHRASE=...` in your shell |

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
hearth-vault scan --staged        # just what is staged for commit

# Rotation state (metadata only)
hearth-vault list --due           # overdue; exit 1 if anything is listed
hearth-vault list --due 7         # due within a week
hearth-vault list --json          # machine-readable metadata, never values

# Sharing (values are encrypted to the recipient; you never see one)
hearth-vault identity                                    # your public identity
hearth-vault share --prefix myapp/ --to <identity> --output bundle.hvs
hearth-vault receive bundle.hvs --dry-run                # names + tiers only
```

`--prefix` is optional for `exec` when the project has a `.hearth-vault`
marker or `HEARTH_VAULT_PREFIX` is set — prefer bare `hearth-vault exec --
<cmd>` over guessing a prefix.

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
- `export HEARTH_VAULT_PASSPHRASE=...` to stop being prompted. If commands
  are prompting, ask the human to start the unlock agent
  (`hearth-vault agent --daemon`, then `hearth-vault unlock`) — never park
  the passphrase in an environment your processes inherit.
- Opening a `.hvs` bundle file, or any backup/snapshot, to inspect it. Use
  `hearth-vault receive <file> --dry-run`, which reports names and tiers
  only.
- Reading `vault.json` or any exported-secret file directly.
- `export FOO=$(hearth-vault ...)` in your own shell, or any pattern that
  would put a secret into a variable you might subsequently echo or forward.
- Writing a secret literal into source, a config file, a log line, or a
  commit — including "example" values copied from a real one.

## Rotation

Rotating is just storing a new value: `hearth-vault set <key>` keeps the
key's tier and advances its due date automatically. There is no separate
"mark rotated" command, and you should not invent one.

- Check what needs attention: `hearth-vault list --due` (exit 1 = something
  is due). Safe for you to run; it prints names and dates, never values.
- The human runs the `set` — you never see or supply the new value.
- **A vault-side rotation is not a rotation.** If the old value leaked, it
  stays live at the provider until someone revokes it there. Say so
  explicitly rather than reporting the rotation as complete.

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
