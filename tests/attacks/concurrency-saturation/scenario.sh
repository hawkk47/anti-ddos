#!/usr/bin/env bash
# tests/attacks/concurrency-saturation/scenario.sh
#
# Exécute les tests Go reproducteurs de saturation in-flight.
# Loopback only : httptest.NewServer sur 127.0.0.1, aucun socket externe.
#
# Vérifie qu'un burst de 50 requêtes concurrentes atteint TOUTES le
# handler (peak in-flight >= N) SANS mitigation, puis qu'avec
# max_in_flight=5 le peak observé reste <= 5 et que le surplus reçoit
# 503 Service Unavailable + header Retry-After.
#
# AVERTISSEMENT : load shedding global, pas per-tenant ni per-IP. Filet
# de protection ; ne remplace pas le rate-limit per-IP en amont. Voir
# docs/threat-model.md#concurrency-saturation.
#
# Cf. proxy/mitigations/concurrency/concurrency_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_ConcurrencyCap' ./mitigations/concurrency/...
