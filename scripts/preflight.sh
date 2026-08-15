#!/usr/bin/env bash
# Run every gate CI runs, before pushing. CI's Linux/macOS/Windows jobs all
# share the same fmt+clippy+test steps, so a failure here fails all three --
# and a green run here means the only things CI can still tell you are the
# genuinely platform-specific ones (Windows DACL/icacls, macOS Keychain).
#
# Install as a pre-push hook:  git config core.hooksPath .githooks
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> cargo fmt --check"
cargo fmt --check

# --all-targets matters: tests and benches are where dead-code and
# duplicate-attribute errors hide, and CI uses it.
echo "==> cargo clippy --all-targets -D warnings"
cargo clippy --all-targets -- -D warnings

echo "==> cargo clippy --no-default-features"
cargo clippy --all-targets --no-default-features -- -D warnings

echo "==> cargo test --all-targets"
cargo test --all-targets

# Windows has no libsecret and a completely separate ACL path, so it is the
# platform most likely to break from a Linux-only edit. Cross-compiling
# catches type errors there without waiting on a CI runner.
if rustup target list --installed | grep -qx x86_64-pc-windows-gnu; then
    echo "==> cargo clippy --target x86_64-pc-windows-gnu"
    cargo clippy --all-targets --target x86_64-pc-windows-gnu -- -D warnings
else
    echo "==> SKIP windows cross-check (rustup target add x86_64-pc-windows-gnu)"
fi

# A secrets tool that ships a secret is the worst possible bug, so scan with
# our own scanner AND gitleaks -- they have different rule sets, and this repo
# is full of credential-SHAPED test fixtures that must stay non-credentials.
echo "==> self-scan"
cargo run --quiet -- scan . || { echo "FAIL: hearth-vault scan found secrets"; exit 1; }
if command -v gitleaks >/dev/null; then
    echo "==> gitleaks"
    gitleaks detect --no-banner --redact
else
    echo "==> SKIP gitleaks (not installed)"
fi

echo
echo "preflight OK"
