#!/usr/bin/env bash
# tests/attacks/credential-stuffing/scenario.sh
#
# Exécute les tests Go reproducteurs de credential stuffing.
# Loopback only : httptest.NewServer sur 127.0.0.1, aucun socket externe.
#
# Vérifie qu'un burst de 50 POST /login (avec une IP attaquante unique)
# atteint l'upstream SANS mitigation, puis qu'avec action=deny seuls
# 5 essais (le burst) passent et 45 sont rejetés en 429 + Retry-After,
# et qu'avec action=log les 50 passent mais 45 sont comptés dans
# mitigation_credential_stuffing_logged_total.
#
# AVERTISSEMENT : rate-limit per-IP. Inefficace contre un stuffing
# distribué (botnet, proxies résidentiels). Voir
# docs/threat-model.md#credential-stuffing.
#
# Cf. proxy/mitigations/credstuff/credstuff_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_CredStuff' ./mitigations/credstuff/...
