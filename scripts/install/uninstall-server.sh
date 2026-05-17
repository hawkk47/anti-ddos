#!/usr/bin/env bash
# Désinstalle les services anti-ddos. Ne supprime ni les configs ni l'état
# par défaut (utiliser --purge pour tout enlever, après confirmation).

set -euo pipefail
IFS=$'\n\t'

log()  { printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "info"  "$*" >&2; }
die()  { printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "error" "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
Usage: uninstall-server.sh [--dry-run] [--yes] [--purge] [--prefix DIR]

Arrête et désactive les services anti-ddos. Par défaut conserve
/etc/anti-ddos, /var/lib/anti-ddos et /var/log/anti-ddos.

Options :
  --dry-run     affiche les actions (défaut)
  --yes         applique réellement
  --purge       supprime aussi /etc/anti-ddos, /var/lib/anti-ddos, /var/log/anti-ddos
  --prefix DIR  préfixe d'installation (défaut /opt/anti-ddos)
EOF
}

DRY_RUN=1
PURGE=0
PREFIX="/opt/anti-ddos"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --yes)     DRY_RUN=0 ;;
    --purge)   PURGE=1 ;;
    --prefix)  PREFIX="${2:?--prefix requires a path}"; shift ;;
    --help|-h) usage; exit 0 ;;
    *)         usage; die "argument inconnu : $1" ;;
  esac
  shift
done

[[ "$EUID" -eq 0 ]] || die "doit être lancé en root"
command -v systemctl >/dev/null 2>&1 || die "systemd requis"

# Validation forte sur PREFIX avant tout rm.
: "${PREFIX:?}"
[[ "$PREFIX" == /opt/* || "$PREFIX" == /usr/local/* ]] \
  || die "préfixe refusé pour suppression : $PREFIX"

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] $*"
  else
    log "+ $*"
    "$@" || true
  fi
}

for svc in anti-ddos-control anti-ddos-proxy; do
  if systemctl list-unit-files | grep -q "^${svc}\.service"; then
    run systemctl disable --now "$svc.service"
    run rm -f "/etc/systemd/system/${svc}.service"
  fi
done
run systemctl daemon-reload

run rm -rf "$PREFIX"

if [[ "$PURGE" -eq 1 ]]; then
  if [[ "$DRY_RUN" -eq 0 ]]; then
    read -r -p "Confirmer la suppression de /etc/anti-ddos, /var/lib/anti-ddos, /var/log/anti-ddos ? [yes/N] " ans
    [[ "$ans" == "yes" ]] || die "annulé"
  fi
  run rm -rf /etc/anti-ddos /var/lib/anti-ddos /var/log/anti-ddos
  if id -u anti-ddos >/dev/null 2>&1; then
    run userdel anti-ddos
  fi
fi

log "désinstallation $( [[ "$DRY_RUN" -eq 1 ]] && echo "(dry-run)" || echo "terminée" )"
