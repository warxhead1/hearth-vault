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

Bare `hearth-vault exec` finds the marker too, so `--prefix` is optional
everywhere inside a configured project:

```sh
hearth-vault exec -- npm run dev
```

### direnv

If you already use direnv, add it to `~/.config/direnv/direnvrc`:

```sh
eval "$(hearth-vault direnv-init)"
```

then in a project's `.envrc`:

```sh
use hearth_vault
```

This exports `HEARTH_VAULT_PREFIX` — a **name**, not a secret — so `exec`
picks the right prefix in that directory. It deliberately does not load your
credentials into the interactive shell; that is the anti-pattern at the top
of this section, and direnv makes it a two-line temptation. See
`examples/integrations/envrc`.

## Stop retyping your passphrase (the unlock agent)

Opening the vault costs one Argon2id derivation, ~120 ms. That is invisible
once and irritating fifty times, and the old workaround —

```sh
export HEARTH_VAULT_PASSPHRASE=$(hearth-vault prompt)   # don't
```

— puts your passphrase in an environment variable that **every child process
inherits, including every coding agent you launch from that shell**.

Use the agent instead:

```sh
hearth-vault agent --daemon        # start it (default TTL: 15 minutes)
hearth-vault unlock                # type the passphrase once
hearth-vault exec -- npm run dev   # instant, no prompt
hearth-vault lock                  # forget everything, now
```

Measured on a desktop: **134 ms → 3 ms per command**, with no passphrase
anywhere in your environment.

What the agent actually holds is a derived *wrap key*, not your passphrase
and not the vault's data key. That means `change-passphrase` invalidates
every cached copy instantly, and the secret you reuse elsewhere never leaves
the process that read it. The socket is `0600` inside a `0700` directory in
`$XDG_RUNTIME_DIR`, and every connection is checked with `SO_PEERCRED`.

It defends against other *users*, not against another process running as
you — anything with your uid can already read `/proc/<pid>/environ` of the
children `exec` creates. It is strictly better than the env var it replaces;
it is not a substitute for tier 4.

Add `--ttl 3600` for a longer session. Unix only: on Windows, `hearth-vault
seal` gives you auto-unlock with no per-command cost at all.

## Stopping secrets at the commit

```sh
hearth-vault install-hook
```

Installs a pre-commit hook that scans exactly what you are about to commit
and blocks it if a secret-shaped string is in there:

```
$ git commit -m "add config"
== dotenv-assignment — Unquoted secret assignment in an env file ==
  .env:1  kT7b…(40 chars)  (suggested key: myapp/secret)

A secret-shaped string is staged. Options:
  * store it:   hearth-vault set <name>
  * adopt .env: hearth-vault scan --adopt --prefix <project>/
  * false hit:  add a 'hearth-vault:allow' comment on that line
  * override:   git commit --no-verify
```

The hook does nothing if `hearth-vault` is not on `PATH`, rather than
failing — a hook that breaks builds for teammates who have not installed the
tool just teaches everyone to pass `--no-verify`, and a bypassed hook
protects nobody.

Run the same check by hand, or in CI, with `hearth-vault scan --staged`.

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

### Let the vault track when things are due

Attach a policy once and the vault does the remembering:

```sh
hearth-vault set myapp/api_key --rotate-days 90    # every 90 days
hearth-vault set myapp/cloud_token --expires 2026-12-01T00:00:00Z  # provider's date
hearth-vault set myapp/legacy_key --expires 30d    # or a relative offset
```

The due date moves forward on its own every time you store a new value —
rotating *is* storing, so there is no "mark as rotated" step to forget:

```
$ hearth-vault list
KEY                                    TIER  CREATED      UPDATED      ROTATION
----------------------------------------------------------------------------------------
myapp/api_key                             3  2026-05-02   2026-08-15   due in 89d
myapp/legacy_key                          3  2026-01-08   2026-01-08   OVERDUE 41d
myapp/no_policy                           3  2026-03-11   2026-03-11   -
```

Check it from cron or CI — the exit code is the answer, so nothing has to
parse the output:

```sh
hearth-vault list --due      # overdue only;    exit 1 if anything is listed
hearth-vault list --due 7    # due within a week
hearth-vault list --json     # metadata for a dashboard (never values)
```

See `examples/integrations/rotate-check.sh` for a ready-made cron script.

Keys stored before you set a policy simply report `-` and are never counted
as overdue. `--rotate-days 0` clears a policy.

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

## Sharing with a teammate

There is still no shared vault and no server — but you can hand a teammate
specific credentials without either of you ever seeing a value in a chat
window.

They run this once and send you the output (it is public, not a secret):

```sh
hearth-vault identity
# hv1pubBFfHaX4RZtuza...
# fingerprint: 3e:ba:49:8b:3f:ff:6e:cd
```

You seal the keys they need to that identity:

```sh
hearth-vault share --prefix staging/ --to hv1pubBFfHaX4RZtuza... \
    --output staging.hvs --note "rotate after the migration lands"
```

`staging.hvs` is safe to send over Slack, email, or a PR comment: only the
holder of that identity can open it. They then:

```sh
hearth-vault receive staging.hvs --dry-run   # see key names and tiers, no values
hearth-vault receive staging.hvs             # store them
```

**Confirm the fingerprint over a different channel before you send.** A
bundle proves its maker knew the recipient's public key — not who the maker
was. Treat a pasted identity exactly like an SSH host key.

Two more things worth knowing:

- `--max-tier N` hands over a *weaker* capability than you hold. `--max-tier
  4` shares a signing key the recipient can `sign` with but can never inject
  or print. Tier is only ever made stricter, never looser.
- **Tier 4 keys are never shareable at all.** That tier promises the material
  does not leave the process holding it, and a bundle is that material
  leaving.
- Sharing is a **copy, and it is not revocable**. The only way to un-share is
  to rotate the credential at the provider.

## Backups

The vault file is already encrypted, so a backup is just a copy — and no
passphrase is needed to make one:

```sh
hearth-vault backup                       # next to the vault
hearth-vault backup --output ~/backups    # somewhere you sync
```

`delete` takes one automatically before removing anything, because the
recovery mnemonic restores the vault *key*, not entries you deleted.

```sh
hearth-vault restore ~/backups/vault-20260815T154828Z.json
```

`restore` proves the snapshot opens **before** it touches your live vault,
and backs up what it is about to replace. A snapshot is encrypted with the
passphrase that was in force when it was taken — a later `change-passphrase`
does not re-key old snapshots.

## Multi-machine

The vault file (`vault.json`) is a local encrypted blob, not a sync target.

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
