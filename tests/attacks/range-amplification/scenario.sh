#!/usr/bin/env bash
# tests/attacks/range-amplification/scenario.sh
#
# Exécute les tests Go reproducteurs de range-amplification (CVE-2011-3192,
# "Apache Killer", S. Kingsley 2011). Loopback only : httptest.NewServer
# sur 127.0.0.1, aucun socket externe.
# Vérifie qu'une requête avec un Range: bytes=0-0,0-1,...,0-N (N grand)
# est rejetée HTTP 416 avant d'atteindre l'upstream, et que le compteur
# Prometheus mitigation_range_amp_blocked_total s'incrémente.
#
# Cf. proxy/mitigations/rangeamp/rangeamp_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_RangeAmp' ./mitigations/rangeamp/...
