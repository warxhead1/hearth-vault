# Runnable integration examples

Copy the one you need and change the prefix. Each file is the whole
integration — there is no framework to install and nothing to import.

| File | What it wires up |
|---|---|
| `myapp.service` | systemd unit that starts a service with vault secrets injected |
| `myapp-envfile.service` | systemd unit for a service that insists on an `EnvironmentFile` |
| `docker-compose.yml` | Compose stack whose secrets come from the vault, not a `.env` |
| `github-actions.yml` | CI that mints a short-lived GitHub App token instead of storing a PAT |
| `Makefile` | `make dev` / `make test` with credentials, no `.env` anywhere |
| `envrc` | Per-project prefix via direnv (exports a *name*, never a secret) |
| `rotate-check.sh` | Cron/CI check that fails when a credential is overdue |

## The rule all of them follow

Secrets enter a **child process's environment** and nothing else. None of
these write a value to a log, a file that outlives the process, or a shell
you type in. When a value must touch disk (the `EnvironmentFile` case,
because some services give you no other option), it lands in `/run` —
tmpfs, owner-only, gone at reboot — and is deleted as soon as it is read.
