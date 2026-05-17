#!/usr/bin/env bash
# tests/attacks/large-header/scenario.sh
#
# Exécute les tests Go reproducteurs de large-header.
# Loopback only : httptest.NewServer bind 127.0.0.1 sur un port
# éphémère.
#
# Cf. proxy/mitigations/largeheader/largeheader_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_LargeHeader' ./mitigations/largeheader/...
