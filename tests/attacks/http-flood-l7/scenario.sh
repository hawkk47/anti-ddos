#!/usr/bin/env bash
# tests/attacks/http-flood-l7/scenario.sh
#
# Exécute les tests Go reproducteurs de http-flood-l7.
# Loopback only — les tests utilisent un Limiter en mémoire avec
# horloge injectée, aucune socket réseau n'est ouverte.
#
# Cf. proxy/mitigations/httpflood/httpflood_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_Flood' ./mitigations/httpflood/...
