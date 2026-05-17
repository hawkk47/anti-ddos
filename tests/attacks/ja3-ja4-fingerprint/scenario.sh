#!/usr/bin/env bash
# tests/attacks/ja3-ja4-fingerprint/scenario.sh
#
# Exécute les tests Go reproducteurs du fingerprinting TLS (JA3 + JA4).
# Loopback only : les tests construisent des *tls.ClientHelloInfo en
# mémoire, aucun socket réseau.
#
# Vérifie qu'avec un ClientHello "Chrome-like" :
#   - SANS mitigation (Enabled=false) : empreintes calculées
#     (observabilité) mais aucune décision de blocage.
#   - AVEC mitigation (Enabled=true, JA3 dans la blocklist) :
#     GetConfigForClient renvoie ErrBlocked → handshake aborté.
#
# AVERTISSEMENT : la mitigation est **dormante** tant que le data plane
# ne termine pas TLS (mode h2c actuel). Voir
# docs/threat-model.md#ja3-ja4-fingerprint pour les limites
# (utls / curl-impersonate, ECH, faux positifs).
#
# Cf. proxy/mitigations/tlsfingerprint/tlsfingerprint_test.go

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
cd "$REPO_ROOT/proxy"

CGO_ENABLED=0 go test -count=1 -run '^TestReproducer_TLSFingerprint' ./mitigations/tlsfingerprint/...
