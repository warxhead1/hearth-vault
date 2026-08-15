#!/bin/sh
# Fail when a credential is overdue for rotation, or comes due soon.
#
# `list --due N` exits non-zero if anything is listed, so this needs no
# output parsing. Run it from cron, a CI job, or a login shell.
#
#   0 6 * * *  /path/to/rotate-check.sh || notify-send "Vault rotation due"
#
# Needs a vault it can open without a human: seal the passphrase to this
# machine first (`hearth-vault seal`), or run it where an unlock agent is
# already live.
set -eu

WINDOW="${1:-7}"

if hearth-vault list --due "$WINDOW" >/dev/null 2>&1; then
    echo "No credentials due within ${WINDOW} days."
    exit 0
fi

echo "Credentials due for rotation within ${WINDOW} days:"
hearth-vault list --due "$WINDOW" || true
echo
echo "Rotate one with:  hearth-vault set <key>"
echo "(storing a new value moves its due date forward automatically)"
exit 1
