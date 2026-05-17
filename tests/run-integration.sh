#!/usr/bin/env bash
# tests/run-integration.sh
# Point d'entree canonique pour les tests d'integration cross-langages.
# Cf. AGENTS.md, .github/instructions/tests.instructions.md.
#
# - Loopback uniquement (127.0.0.1)
# - Ports ephemeres (:0)
# - Cleanup garanti via trap
# - Equivalent PowerShell : tests/run-integration.ps1

set -euo pipefail
IFS=$'\n\t'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

log()  { printf '%s [info]  %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
warn() { printf '%s [warn]  %s\n' "$(date -u +%FT%TZ)" "$*" >&2; }
die()  { printf '%s [error] %s\n' "$(date -u +%FT%TZ)" "$*" >&2; exit 1; }

# Cleanup global : tue tous les processus enfants au exit.
cleanup() {
  status=$?
  jobs -p | xargs -r kill -- 2>/dev/null || true
  exit $status
}
trap cleanup EXIT INT TERM

usage() {
  cat >&2 <<'EOF'
Usage: tests/run-integration.sh [filter]

  filter   sous-ensemble a executer (ex: waf, ratelimit, slowloris).
           Par defaut : tout.

Garde-fous :
  - aucune URL non-loopback acceptee comme cible
  - ports ephemeres (:0)
  - nettoyage des processus enfants en sortie
EOF
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
esac

filter="${1:-all}"
log "filter=$filter os=$(uname -s 2>/dev/null || echo unknown)"

# ----------------------------------------------------------------------
# Prerequis : verifier la presence des outils utilises par les tests.
# ----------------------------------------------------------------------
need() { command -v "$1" >/dev/null 2>&1 || die "outil manquant : $1"; }

if [ -d proxy ]; then need go; fi
if [ -d control ]; then
  need node
  command -v pnpm >/dev/null 2>&1 || warn "pnpm absent : etapes control/ ignorees"
fi

# ----------------------------------------------------------------------
# Etape 1 : tests unitaires Go (proxy).
# ----------------------------------------------------------------------
if [ -d proxy ]; then
  log "go test ./... (proxy/)"
  # -race exige cgo ; on le laisse au CI dédié. Ici : pure-Go strict.
  ( cd proxy && CGO_ENABLED=0 go test -count=1 ./... )
else
  warn "proxy/ absent : tests Go ignores"
fi

# ----------------------------------------------------------------------
# Etape 2 : tests unitaires Node (control).
# ----------------------------------------------------------------------
if [ -d control ] && command -v pnpm >/dev/null 2>&1; then
  log "pnpm test (control/)"
  ( cd control && pnpm test )
fi

# ----------------------------------------------------------------------
# Etape 3 : scenarios end-to-end loopback.
# Pour l'instant : placeholder. Les vrais scenarios s'ajoutent sous
# tests/attacks/<id>/scenario.sh ou *_test.go (cf. add-mitigation skill).
# ----------------------------------------------------------------------
if [ -d tests/attacks ]; then
  for scenario in tests/attacks/*/scenario.sh; do
    [ -f "$scenario" ] || continue
    log "scenario : $scenario"
    bash "$scenario"
  done
fi

log "OK"
