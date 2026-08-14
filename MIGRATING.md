# Migrating existing secrets into hearth-vault

This is for the case that is actually common: you have a `.env` file or three,
a handful of `export FOO=...` lines in `~/.zshrc`, and maybe a hardcoded API
key in a script you wrote in a hurry — and you have been letting coding
agents run commands in these repos. This guide gets you from that state to
per-project vault-backed secrets.

## 1. Why this matters

A secret sitting in a `.env` file is one `cat` away from ending up in an
agent's transcript, because "read the config" is a completely ordinary thing
for an agent to do while debugging or exploring a repo. A secret exported in
your shell rc file is worse, and less visible: every child process your
shell spawns inherits it, including every agent you launch from that shell,
every script that agent runs, and every subprocess *those* spawn. You did not
hand the agent the key on purpose — it received it automatically, as
ambient environment, and there is no log line marking the moment it did.
Neither of these requires anything to go wrong. It's just how `.env` files
and shell exports work.

## 2. Find what you have

```
hearth-vault scan
```

Run with no arguments, this scans the current directory for things that look
like secrets by shape, not by variable name — AWS access keys, GitHub
tokens, Anthropic keys, Stripe live keys, Slack bot tokens, PEM private-key
headers, connection strings with inline credentials, JWTs, and a
generic high-entropy `key = "..."` pattern. It does not rely on a variable
being named `API_KEY`; it looks at what the value itself looks like. Output
is redacted — `scan` never prints a full secret value, even the ones it
finds.

Pass a path to scan somewhere other than the current directory:

```
hearth-vault scan ~/projects/myapp
```

Add `--json` for machine-readable output (useful once you start scripting
around this — see §6). To see exactly what `scan` looks for and how it's
detected, run:

```
hearth-vault scan --rules
```

`scan` exits 1 when it finds anything and 0 when it doesn't, which is what
makes it usable as a gate later (§6). For now, just read the report.

## 3. Adopt it

```
hearth-vault scan --adopt --prefix myapp/
```

For findings in `.env`-style files, `--adopt` stores each value in the vault
under `myapp/` and rewrites the file so the plaintext value is no longer
there. For findings in source code, `--adopt` only reports them — it does
not touch your `.py`, `.js`, `.go`, etc. files. That's deliberate: rewriting
a config file is safe because the only thing that reads it is your own
tooling, but rewriting source code means guessing at your language's import
conventions, string-escaping rules, and surrounding logic, and getting it
wrong breaks a build silently. A `.env` line is data; a source-code hit is
data embedded in code you have to understand to change safely. When `scan`
flags something in source, treat it as a to-do: move the value into the
vault by hand with `hearth-vault set`, then update the source to read the
resulting environment variable instead of the literal.

Use `--force` if a key already exists in the vault and you want `--adopt` to
overwrite it. Without a `--prefix`, `--adopt` still needs somewhere to put
each entry, so decide on a prefix (see the next section) before you run it
for real, or just pass one — it isn't destructive to change your mind later
with `hearth-vault rename`.

## 4. Per-project setup

### The `.hearth-vault` marker

`hearth-vault project-prefix` walks up from `$PWD` looking for a
`.hearth-vault` marker file and prints the prefix it finds. Create one at
your project root containing the prefix you want that project to use:

```
echo "myapp/" > .hearth-vault
```

Commit it — it contains no secret material, just a string. This is what
lets `shell-init`'s `hv` wrapper (below) know which prefix to inject without
you typing `--prefix` on every command.

### Choosing a prefix convention

Pick something that maps 1:1 to a project or service and stick with it —
`<repo-name>/`, e.g. `myapp/`, `internal-api/`. Nested prefixes work too
(`myapp/staging/`, `myapp/prod/`) if you need to separate environments; `exec`
and `export-env-file` both match by prefix, so `myapp/` alone injects
everything under it, staging and prod included, while `myapp/prod/` scopes
tighter.

### `shell-init` and the `hv` wrapper

```
hearth-vault shell-init bash >> ~/.bashrc
```

(substitute `zsh` or `fish` for your shell). This appends a snippet that
defines an `hv` wrapper — it does **not** export anything into your
interactive shell. Once sourced, `hv <command...>` runs `<command...>`
through `hearth-vault exec` for the current project's prefix, so instead of
typing the full `exec --prefix ... --` invocation every time, you run:

```
hv npm run dev
```

### Worked example — Node

Before: `myapp/.env` contains

```
API_KEY=...
DATABASE_URL=postgres://...
```

read by `require('dotenv').config()` at startup.

After:

```
cd myapp
hearth-vault scan --adopt --prefix myapp/
echo "myapp/" > .hearth-vault
```

`.env` is gone (or emptied, per §3); `myapp/API_KEY` and
`myapp/DATABASE_URL` are in the vault at tier 3. Drop the `dotenv` call and
run the app through the vault instead:

```
hv npm run dev
```

Inside the process, `process.env.API_KEY` and `process.env.DATABASE_URL`
are populated exactly as before — the prefix `myapp/` is stripped and the
rest is uppercased (`api_key` → `API_KEY`), so nothing downstream of
`process.env` needs to change.

### Worked example — Python

Before: `pyapp/.env` contains

```
OPENAI_API_KEY=...
DB_PASSWORD=...
```

read by `python-dotenv`'s `load_dotenv()`.

After:

```
cd pyapp
hearth-vault scan --adopt --prefix pyapp/
echo "pyapp/" > .hearth-vault
```

Drop `load_dotenv()` and run through the wrapper:

```
hv python manage.py runserver
```

`os.environ["OPENAI_API_KEY"]` and `os.environ["DB_PASSWORD"]` are populated
the same way — `pyapp/openai_api_key` → `OPENAI_API_KEY`,
`pyapp/db_password` → `DB_PASSWORD`.

## 5. Choosing a tier

| You need... | Tier |
|---|---|
| the default — a value only ever consumed by a child process you `exec` into (the common case; this is what agents should be using) | 3 (default) |
| the raw value on stdout or in a file, because a specific tool genuinely can't take it as an env var | 2 |
| a signing key (RSA private key, GitHub App private key) that should never be readable and never leave the vault process, only used via `sign` / `github-app-token` | 4 |
| the OS credential store as the primary backend, with the value still exportable | 1 |

Leave new secrets at tier 3 unless you have a specific reason to move them.
`import-env` and `scan --adopt` both default to tier 3.

## 6. Keeping it clean

`scan` exits 1 when it finds something, so it works unmodified as either a
pre-commit hook or a CI step.

Pre-commit (`.git/hooks/pre-commit` or your pre-commit-framework config):

```
#!/bin/sh
hearth-vault scan || {
    echo "hearth-vault scan found a likely secret — see above" >&2
    exit 1
}
```

CI (any runner — adapt to your syntax):

```yaml
- name: scan for secrets
  run: hearth-vault scan
```

Both rely on the same exit code: 0 means clean, 1 means it found something
and the commit/build should stop.

If `scan` flags something that genuinely isn't a secret — a test fixture, an
example key in documentation — add a `hearth-vault:allow` comment on the
matching line rather than disabling the scan or the rule wholesale:

```
EXAMPLE_KEY = "sk-ant-not-a-real-key"  # hearth-vault:allow
```

## 7. What this does not protect against

Be clear-eyed about the boundary:

- **An agent with shell access can run `hearth-vault exec` itself.** If an
  agent can run arbitrary commands as you, it can run the same `exec`
  invocation you would, and everything under that prefix flows into
  whatever it execs. Tier 3 stops a value from being *read directly*, not
  from being *used* by anything that can invoke the command wrapping it.
- **The child process can print its own environment.** `exec` never prints
  the secret itself, but nothing stops the command you exec into from doing
  `echo $API_KEY` or `printenv` on its own. That's a property of the
  process you chose to run, not something `hearth-vault` mediates once the
  value is in its environment.
- **This catches exact values and known shapes, not everything.** `scan`
  matches literal secret values and a fixed set of recognizable formats
  (§2). It has no way to catch a secret an agent has already derived,
  re-encoded (base64, hex, a partial substring), or transformed before it
  ends up somewhere.
- **A compromised machine is out of scope entirely.** If an attacker has
  code execution as your user, they can read `HEARTH_VAULT_PASSPHRASE` from
  your environment or capture the secret out of a child process's memory
  while `exec` is running. See `SECURITY.md` for the full threat model.

## 8. Rolling back

Nothing here is one-way. To get a value back out as a plain environment
variable or file:

```
hearth-vault retier myapp/api_key --tier 2
hearth-vault export-env myapp/api_key --env-name API_KEY
```

`export-env` only works at tier 1 or 2 and only at an interactive terminal
(§ the non-TTY rule in `README.md`) — that's deliberate, same reasoning as
everywhere else in this tool: a human at a keyboard can see the value; a
script or agent reading a pipe should not. If you want it in a file instead
of on stdout, use `export-env-file --prefix myapp/ --output <path>` after
retiering.
