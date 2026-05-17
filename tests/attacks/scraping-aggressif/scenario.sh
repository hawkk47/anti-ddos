#!/usr/bin/env bash
# tests/attacks/scraping-aggressif/scenario.sh
#
# Exécute les tests Go reproducteurs de scraping agressif.
# Loopback only : httptest.NewServer sur 127.0.0.1, aucun socket externe.
#
# Vérifie qu'une requête avec User-Agent "python-requests/2.31" atteint
# l'upstream SANS mitigation, puis qu'avec action=deny elle est rejetée
# en 403 avant forward, et qu'avec action=log elle passe (200 OK) tout
# en étant comptée dans mitigation_scraping_logged_total.
#
# AVERTISSEMENT : détection signature-only, trivialement contournable
# par un attaquant déterminé. Voir docs/threat-model.md#scraping-aggressif.
#
# Cf. proxy/mitigations/scraping/scraping_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_Scraping' ./mitigations/scraping/...
