#!/usr/bin/env bash
# tests/attacks/slowloris/scenario.sh
#
# Exécute le test Go reproducteur de Slowloris.
# Loopback only — le test ouvre des connexions vers 127.0.0.1
# uniquement, sur un port éphémère.
#
# Cf. proxy/mitigations/slowloris/slowloris_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestSlowloris' ./mitigations/slowloris/...
