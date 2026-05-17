#!/usr/bin/env bash
# tests/attacks/slow-post/scenario.sh
#
# Exécute les tests Go reproducteurs de slow-post.
# Loopback only : test handler invoqué via httptest, aucun socket
# externe. Drip reader avec horloge fakée.
#
# Cf. proxy/mitigations/slowpost/slowpost_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_SlowPost' ./mitigations/slowpost/...
