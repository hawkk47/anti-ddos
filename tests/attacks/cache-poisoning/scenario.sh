#!/usr/bin/env bash
# tests/attacks/cache-poisoning/scenario.sh
#
# Exécute les tests Go reproducteurs de cache-poisoning
# (J. Kettle, "Practical Web Cache Poisoning", Black Hat USA 2018).
# Loopback only : httptest.NewServer sur 127.0.0.1, aucun socket externe.
#
# Vérifie qu'une requête avec X-Forwarded-Host: evil.example
# atteint l'upstream et y est réfléchie SANS mitigation, puis qu'avec
# action=strip le header est silencieusement retiré (200 OK upstream
# voit le host légitime), et qu'avec action=deny la requête est
# rejetée 400 avant forward.
#
# Cf. proxy/mitigations/cachepoison/cachepoison_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_CachePoison' ./mitigations/cachepoison/...
