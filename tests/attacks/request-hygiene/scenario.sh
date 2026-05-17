#!/usr/bin/env bash
# tests/attacks/request-hygiene/scenario.sh
#
# Exécute les tests Go reproducteurs d'hygiène HTTP.
# Loopback only : httptest.NewServer sur 127.0.0.1, aucun socket externe.
#
# Vérifie qu'une requête avec méthode `FOOBAR`, une combinaison
# `Content-Length` + `Transfer-Encoding`, un `Content-Length` dupliqué,
# une URI > max_uri_length ou un Host vide :
#   - SANS mitigation : atteint le handler upstream brut ;
#   - AVEC mitigation : est rejetée en 400 Bad Request, sans header
#     explicatif côté client (defense in depth).
#
# AVERTISSEMENT : la mitigation est un *gate* binaire (pas de
# normalisation). Pour un upstream légacy potentiellement vulnérable
# au smuggling malgré le front Go, prévoir une normalisation
# additionnelle. Voir docs/threat-model.md#request-hygiene.
#
# Cf. proxy/mitigations/requesthygiene/requesthygiene_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_RequestHygiene' ./mitigations/requesthygiene/...
