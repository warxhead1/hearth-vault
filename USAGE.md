# hearth-vault usage recipes

Practical, copy-pasteable. For the full command reference and the tier model
rationale, see `README.md`; for finding secrets scattered across an existing
project, see `MIGRATING.md`. This file is the "how do I actually do X" doc.

## First 60 seconds

```sh
cargo install --locked --git https://github.com/warxhead1/hearth-vault
hearth-vault init
```

(Prebuilt binaries for Linux, macOS and Windows are on the Releases page if
you would rather not build. Not yet on crates.io.)

`init` creates the vault, prompts twice for a passphrase (hidden input), and
prints a one-time 24-word BIP39 recovery mnemonic. Write it down — it is the
only way back in if you forget the passphrase, and it is never shown again.

Store your first secret:

```sh
hearth-vault set myapp/api_key
# Value for myapp/api_key: <hidden input, not echoed>
```

New secrets default to tier 3 (use-only): the value can never be printed by
`export-env`/`export-env-file`, but it can still be used. Use it:

```sh
# Single quotes + `sh -c`, so the CHILD expands $API_KEY. With double quotes
# your own shell expands it first, to nothing.
hearth-vault exec --prefix myapp/ -- sh -c 'curl -H "Authorization: Bearer $API_KEY" https://api.example.com'
```

`exec` resolves every key under `myapp/` to an env var (`myapp/api_key` ->
`API_KEY`: prefix stripped, uppercased, `/` and `-` -> `_`), injects it into
the child process's environment, and execs `curl`. The value never touches
your shell, your terminal scrollback, or anything reading your tool output.

## Replacing a `.env` file

The common case: a project has a `.env` file loaded by `dotenv`/`python-dotenv`/
`docker compose --env-file`, and you want the equivalent without the file.

```sh
hearth-vault import-env .env --prefix myapp/
```

This parses `KEY=value`, `export KEY=value`, quoted values, `#` comments, and
blank lines; stores each pair as `myapp/KEY` at tier 3; deletes `.env`; and
adds `.env` to the nearest `.gitignore` (harmless if it's already there).
Keep the source file instead of deleting it with `--keep`; overwrite existing
vault keys with `--force`.

### Node

Before, `myapp/.env`:

```
API_KEY=sk-...
DATABASE_URL=postgres://user:pass@localhost/myapp  # hearth-vault:allow (doc example)
```

read by `require('dotenv').config()` at startup. After:

```sh
cd myapp
hearth-vault import-env .env --prefix myapp/
```

Delete the `dotenv` call, then run through `exec` instead of `node server.js`:

```sh
hearth-vault exec --prefix myapp/ -- node server.js
hearth-vault exec --prefix myapp/ -- npm run dev
```

`process.env.API_KEY` and `process.env.DATABASE_URL` are populated exactly as
before. Nothing downstream of `process.env` changes.

### Python

Before, `pyapp/.env`:

```
OPENAI_API_KEY=sk-...
DB_PASSWORD=hunter2
```

read by `python-dotenv`'s `load_dotenv()`. After:

```sh
cd pyapp
hearth-vault import-env .env --prefix pyapp/
```

Drop `load_dotenv()`, run through `exec`:

```sh
hearth-vault exec --prefix pyapp/ -- python manage.py runserver
hearth-vault exec --prefix pyapp/ -- gunicorn app:app
```

`os.environ["OPENAI_API_KEY"]` and `os.environ["DB_PASSWORD"]` are populated
the same way.

### docker compose

`exec` injects into whatever process it starts, and `docker compose` forwards
its own environment into containers declared with `environment: - API_KEY`
(no literal value in the compose file):

```sh
hearth-vault import-env .env --prefix myapp/
hearth-vault exec --prefix myapp/ -- docker compose up
```

Do not use `docker compose --env-file` pointed at a plaintext file
regenerated from the vault — that recreates the problem this tool removes.
Let compose inherit the variables `exec` already injected.

## Wiring into `.bashrc`/`.zshrc` without exporting secrets everywhere

**Anti-pattern, do not do this:**

```sh
# ~/.zshrc — DO NOT DO THIS
eval "$(hearth-vault export-env myapp/api_key --env-name API_KEY)"
```

Anything `export`ed in a shell rc file is inherited by every child process
that shell spawns from then on — every script, every coding agent you launch
from that terminal, every subprocess those spawn — and lands in
`/proc/<pid>/environ` for each of them. Any agent that runs a bare `env` or
`printenv` sees it directly. A `.env` file only leaks if something reads it
off disk; an exported shell variable leaks by default, silently, to
everything downstream.

**Correct alternative — a per-command wrapper:**

```sh
eval "$(hearth-vault shell-init zsh)"   # or bash / fish
```

Add that line to your rc file. It defines an `hv` function that runs `exec`
for exactly one command and lets the injected variables die with it — nothing
is exported into the interactive shell itself:

```sh
hv npm run dev
hv python manage.py runserver
hv ./deploy.sh
```

`hv` reads the prefix from the nearest `.hearth-vault` marker file (see
below), so you don't type `--prefix` every time.

### Per-project prefix marker

```sh
echo "myapp/" > .hearth-vault
```

Commit this file — it holds only a prefix string, no secret material.
`hearth-vault project-prefix` walks up from `$PWD` to find it, and that's
what `hv` (from `shell-init`) uses under the hood:

```sh
hv() {
    hearth-vault exec --prefix "$(hearth-vault project-prefix)" -- "$@"
}
```

Different directories with different `.hearth-vault` markers get different
prefixes automatically — direnv-style per-directory behavior with no extra
tool: `cd` into a project, run `hv <command>`, get that project's secrets.

## CI

Same rule applies in CI: never print the secret, run the thing that needs it
through `exec`.

**GitHub Actions:**

```yaml
- name: Install hearth-vault
  run: cargo install --locked --git https://github.com/warxhead1/hearth-vault

- name: Run migrations
  env:
    HEARTH_VAULT_HOME: ${{ runner.temp }}/vault
    HEARTH_VAULT_PASSPHRASE: ${{ secrets.HEARTH_VAULT_PASSPHRASE }}
  run: |
    hearth-vault import-env .env.ci --prefix myapp/ --keep
    hearth-vault exec --prefix myapp/ -- ./scripts/migrate.sh
```

`HEARTH_VAULT_PASSPHRASE` unlocks the vault non-interactively (no prompt);
keep the actual vault file itself out of the repo — either commit an
already-populated encrypted `vault.json` as a CI-only artifact (fine, it's
ciphertext) with `HEARTH_VAULT_HOME` pointed at its directory, or rebuild it
in a setup step from CI-managed secrets.

**Makefile target:**

```makefile
.PHONY: dev
dev:
	hearth-vault exec --prefix myapp/ -- $(RUN)

.PHONY: migrate
migrate:
	hearth-vault exec --prefix myapp/ -- alembic upgrade head
```

Never pipe `export-env`/`export-env-file` output into a build step's log —
both refuse outright off-TTY unless `HEARTH_VAULT_ALLOW_NON_TTY=1` is set,
which is an explicit opt-out for a controlled path (systemd, a CI runner you
trust), not something to reach for by default.

## Silencing a false positive in `scan`

`hearth-vault scan` matches by shape, so documentation examples, test
fixtures and sample connection strings will trip it. Mark the line rather
than turning the scan off:

```
DATABASE_URL=postgres://user:pass@localhost/example  # hearth-vault:allow
```

`gitleaks:allow` is honoured identically, so a repo already annotated for
gitleaks needs no second pass. There is no ignore FILE by design: an
allowlist that lives away from the line it excuses is one nobody rereads.

If you find yourself annotating a real credential to make the scan quiet,
that is the tool working. Move the value into the vault instead.

## Rotation

### Rotate a credential end to end

```sh
hearth-vault set myapp/api_key_new   # store the new value under a temp name
hearth-vault exec --prefix myapp/ -- ./scripts/smoke-test.sh   # verify it works
hearth-vault delete myapp/api_key                 # drop the old value
hearth-vault rename myapp/api_key_new myapp/api_key   # promote the new one
```

Or, if the app already reads the same key name and you just need to swap the
value in place:

```sh
hearth-vault set myapp/api_key   # overwrites in place
```

Overwriting an existing key keeps that key's current tier: rotating a value
never changes who is allowed to read it. Pass `--tier` explicitly if you do
want to move it.

### Rotate the vault passphrase

```sh
hearth-vault change-passphrase
```

Prompts for the current passphrase (or the recovery mnemonic, offered as an
alternative unlock path), then a new passphrase twice. This only rewraps the
vault's internal data key — no entry is re-encrypted, and the recovery
mnemonic keeps working unchanged afterward.

### Rotate the recovery mnemonic

```sh
hearth-vault new-recovery-key
```

Prints a fresh 24-word phrase and invalidates the old one immediately. Do
this any time you suspect the old phrase was seen by someone else, and
always after `hearth-vault recover` (which rotates it for you automatically,
since running `recover` means the old phrase was just typed in and should be
treated as spent).

## Team / multi-machine

There is no shared vault. Each developer runs their own `hearth-vault init`
on their own machine and imports/sets their own copies of the team's shared
credentials — the vault file (`vault.json`) is a local encrypted blob, not a
sync target.

- **Never commit `vault.json`.** Already excluded by `.gitignore`
  (`vault.json`); mirror that in any project keeping a vault path inside its
  repo via `--vault-path`/`HEARTH_VAULT_HOME`.
- **Write down the recovery mnemonic offline** (password manager, printed
  copy in a safe) the moment `init` prints it — the only recovery path; lose
  both the passphrase and the mnemonic and the vault is gone by design.
- **New teammate**: don't paste values in Slack. Screen-share while they run
  `hearth-vault set <key>` themselves, or issue them their own scoped
  short-lived credentials from the provider instead of reusing yours.
- **Machine migration**: `hearth-vault export-env-file --prefix myapp/
  --output export.env` on the old machine (tier 1/2 only, 0600 perms),
  transfer over a trusted channel, `hearth-vault import-env export.env
  --prefix myapp/` on the new one, shred the intermediate file.

## Common mistakes

- **`export FOO=$(hearth-vault get FOO)` in a shell rc file.** There is no
  `get` subcommand precisely to stop this pattern; use `hv <command>` or
  `hearth-vault exec` instead. See above.
- **Piping `export-env` output anywhere.** `hearth-vault export-env KEY
  --env-name NAME | somewhere` refuses — stdout isn't a TTY. That refusal is
  the feature, not a bug to work around with `HEARTH_VAULT_ALLOW_NON_TTY=1`
  unless you specifically mean a controlled CI/systemd path.
- **Leaving new secrets at tier 3 and then being surprised `export-env`
  refuses.** That's correct behavior — tier 3 is use-only by design. Either
  consume it through `exec`/`sign`, or `hearth-vault retier <key> --tier 2`
  if a specific tool genuinely needs the raw value.
- **Storing a signing key at tier 2 instead of tier 4.** A private key you
  only ever use with `sign`/`github-app-token` should be tier 4 (sign-only,
  never injected by `exec` either) — there's no reason for it to ever be
  exportable or handed to a child process directly.
- **Passing a secret value as a CLI argument to anything**, including to
  `hearth-vault` itself. `set` and `import` deliberately never take the
  value as an argument (hidden-input prompt / a file path instead) because a
  CLI argument lands in `ps` output and shell history.
- **Assuming `exec` sandboxes the child process.** It does not. Any command
  you `exec` into receives the real values in its environment and can do
  anything with them, including print them itself (`printenv`) or send them
  over the network. Scope what you `exec` into, not just which secrets exist.
- **Forgetting `.hearth-vault` needs to be created once per project.** Without
  it, `hearth-vault project-prefix` (and therefore the `hv` wrapper) has
  nothing to find; run `echo "myapp/" > .hearth-vault` once, and commit it.
