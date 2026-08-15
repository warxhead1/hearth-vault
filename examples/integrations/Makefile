# Project Makefile with credentials and no .env file.
#
# One variable defines how anything touching a secret runs. Every target that
# needs credentials goes through it, so there is exactly one place to audit
# and nowhere for a `cat .env` to creep back in.
#
# The prefix comes from the .hearth-vault marker, so this Makefile is
# copy-pasteable between projects unchanged.

VAULT := hearth-vault exec --

.PHONY: dev test migrate psql check-secrets

dev:
	$(VAULT) npm run dev

test:
	$(VAULT) pytest -q

migrate:
	$(VAULT) alembic upgrade head

# Note the single quotes: $$DATABASE_URL is expanded by the CHILD shell,
# after injection. Double quotes would make make/your shell expand it to
# empty before hearth-vault ever ran.
psql:
	$(VAULT) sh -c 'psql "$$DATABASE_URL"'

# Wire into CI: fails if a secret-shaped string is sitting in the repo.
check-secrets:
	hearth-vault scan .
