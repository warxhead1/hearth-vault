#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

command -v cargo >/dev/null 2>&1 || {
  echo "Rust is required to set up hearth-vault." >&2
  exit 1
}

cargo fetch --locked
echo "hearth-vault source dependencies are ready; no vault was opened or initialized."
