#!/usr/bin/env bash
# tests/configs/validate-configs.sh
# Lance la validation des YAML de configs/base/ contre leur schéma.
# Loopback only, idempotent.

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT/control"

if ! command -v pnpm >/dev/null 2>&1; then
  echo "[validate-configs] pnpm absent, skip" >&2
  exit 0
fi

pnpm --silent validate-configs
