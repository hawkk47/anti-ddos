#!/usr/bin/env bash
# tests/attacks/http2-rapid-reset/scenario.sh
#
# Exécute les tests Go reproducteurs de http2-rapid-reset (CVE-2023-44487).
# Loopback only : net.Listen sur 127.0.0.1:0, aucun socket externe.
# Vérifie qu'une rafale de streams open+RST sur une même TCP est
# détectée et que la connexion est fermée par le proxy.
#
# Cf. proxy/mitigations/http2reset/http2reset_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_RapidReset' ./mitigations/http2reset/...
