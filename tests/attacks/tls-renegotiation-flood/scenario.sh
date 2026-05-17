#!/usr/bin/env bash
# tests/attacks/tls-renegotiation-flood/scenario.sh
#
# Exécute les tests Go reproducteurs de tls-renegotiation-flood.
# Loopback only : net.Listen sur 127.0.0.1:0, aucun socket externe.
# Vérifie qu'un flood de handshakes TCP est capé au burst configuré.
#
# Cf. proxy/mitigations/tlsreneg/tlsreneg_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_HandshakeFlood' ./mitigations/tlsreneg/...
