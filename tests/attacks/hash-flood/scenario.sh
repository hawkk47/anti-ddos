#!/usr/bin/env bash
# tests/attacks/hash-flood/scenario.sh
#
# Exécute les tests Go reproducteurs de hash-flood (famille CVE-2011-3414).
# Loopback only : httptest.NewServer sur 127.0.0.1, aucun socket externe.
# Vérifie qu'une URL avec >max_query_params est rejetée (HTTP 400) avant
# d'atteindre l'upstream et que le compteur Prometheus s'incrémente.
#
# Cf. proxy/mitigations/hashflood/hashflood_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_HashFlood' ./mitigations/hashflood/...
