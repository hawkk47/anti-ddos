#!/usr/bin/env bash
# Installer serveur anti-ddos pour Linux (systemd).
# Idempotent : peut être relancé pour mettre à jour les binaires.
# Aucune action destructive par défaut — utiliser --yes pour appliquer.

set -euo pipefail
IFS=$'\n\t'

# ---------- helpers ----------
log()  { printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "info"  "$*" >&2; }
warn() { printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "warn"  "$*" >&2; }
die()  { printf '%s [%s] %s\n' "$(date -u +%FT%TZ)" "error" "$*" >&2; exit 1; }

usage() {
  cat >&2 <<'EOF'
Usage: install-server.sh [--dry-run] [--yes] [--prefix DIR] [--no-control]

Installe le data plane (Go) et optionnellement le control plane (Node.js)
comme services systemd, dans le préfixe donné (par défaut /opt/anti-ddos).

Options :
  --dry-run         affiche les actions sans rien modifier (défaut)
  --yes             applique réellement les actions
  --prefix DIR      préfixe d'installation (défaut /opt/anti-ddos)
  --no-control      n'installe pas le control plane (data plane seul)
  --help            affiche ce message

Prérequis :
  - droits root
  - Go >= 1.22 dans le PATH (pour compiler le data plane)
  - Node.js >= 20 + pnpm (pour compiler le control plane)
EOF
}

# ---------- parsing ----------
DRY_RUN=1
PREFIX="/opt/anti-ddos"
WITH_CONTROL=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)    DRY_RUN=1 ;;
    --yes)        DRY_RUN=0 ;;
    --prefix)     PREFIX="${2:?--prefix requires a path}"; shift ;;
    --no-control) WITH_CONTROL=0 ;;
    --help|-h)    usage; exit 0 ;;
    *)            usage; die "argument inconnu : $1" ;;
  esac
  shift
done

# ---------- vérifs ----------
[[ "$EUID" -eq 0 ]] || die "doit être lancé en root (sudo)"
command -v systemctl >/dev/null 2>&1 || die "systemd requis"
command -v go        >/dev/null 2>&1 || die "go >= 1.22 requis dans le PATH"
[[ "$WITH_CONTROL" -eq 0 ]] || command -v node >/dev/null 2>&1 \
  || die "node >= 20 requis (ou passez --no-control)"
[[ "$WITH_CONTROL" -eq 0 ]] || command -v pnpm >/dev/null 2>&1 \
  || die "pnpm requis (ou passez --no-control)"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/../.." && pwd)"

USER_NAME="anti-ddos"
ETC_DIR="/etc/anti-ddos"
STATE_DIR="/var/lib/anti-ddos"
LOG_DIR="/var/log/anti-ddos"

run() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    log "[dry-run] $*"
  else
    log "+ $*"
    "$@"
  fi
}

# ---------- compilation ----------
log "build data plane (CGO_ENABLED=0)"
(
  cd "$REPO_ROOT/proxy"
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "$REPO_ROOT/proxy/anti-ddos-proxy" ./cmd/proxy
)
[[ -x "$REPO_ROOT/proxy/anti-ddos-proxy" ]] || die "build data plane échoué"

if [[ "$WITH_CONTROL" -eq 1 ]]; then
  log "build control plane"
  ( cd "$REPO_ROOT/control" && pnpm install --frozen-lockfile && pnpm build )
  [[ -f "$REPO_ROOT/control/dist/index.js" ]] || die "build control plane échoué"
fi

# ---------- création user + arborescence ----------
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  run useradd --system --no-create-home --shell /usr/sbin/nologin "$USER_NAME"
else
  log "user $USER_NAME déjà présent"
fi

run install -d -m 0755 -o "$USER_NAME" -g "$USER_NAME" "$PREFIX"
run install -d -m 0755 -o "$USER_NAME" -g "$USER_NAME" "$PREFIX/bin"
run install -d -m 0750 -o root         -g "$USER_NAME" "$ETC_DIR"
run install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "$STATE_DIR"
run install -d -m 0750 -o "$USER_NAME" -g "$USER_NAME" "$LOG_DIR"

# ---------- binaires ----------
run install -m 0755 -o "$USER_NAME" -g "$USER_NAME" \
  "$REPO_ROOT/proxy/anti-ddos-proxy" "$PREFIX/bin/anti-ddos-proxy"

if [[ "$WITH_CONTROL" -eq 1 ]]; then
  run install -d -m 0755 -o "$USER_NAME" -g "$USER_NAME" "$PREFIX/control"
  # cp -r dans un mode idempotent : on copie dist + package.json + node_modules
  for d in dist package.json node_modules; do
    if [[ -e "$REPO_ROOT/control/$d" ]]; then
      run cp -a "$REPO_ROOT/control/$d" "$PREFIX/control/"
    fi
  done
  run chown -R "$USER_NAME:$USER_NAME" "$PREFIX/control"
fi

# ---------- env (sans secret) ----------
if [[ ! -f "$ETC_DIR/proxy.env" ]]; then
  run install -m 0640 -o root -g "$USER_NAME" \
    "$SCRIPT_DIR/proxy.env.example" "$ETC_DIR/proxy.env"
else
  log "$ETC_DIR/proxy.env existe déjà — non modifié"
fi
if [[ "$WITH_CONTROL" -eq 1 && ! -f "$ETC_DIR/control.env" ]]; then
  run install -m 0640 -o root -g "$USER_NAME" \
    "$SCRIPT_DIR/control.env.example" "$ETC_DIR/control.env"
else
  [[ "$WITH_CONTROL" -eq 0 ]] || log "$ETC_DIR/control.env existe déjà — non modifié"
fi

# ---------- units systemd ----------
run install -m 0644 -o root -g root \
  "$SCRIPT_DIR/anti-ddos-proxy.service" "/etc/systemd/system/anti-ddos-proxy.service"
if [[ "$WITH_CONTROL" -eq 1 ]]; then
  run install -m 0644 -o root -g root \
    "$SCRIPT_DIR/anti-ddos-control.service" "/etc/systemd/system/anti-ddos-control.service"
fi

run systemctl daemon-reload
run systemctl enable anti-ddos-proxy.service
if [[ "$WITH_CONTROL" -eq 1 ]]; then
  run systemctl enable anti-ddos-control.service
fi

# ---------- résumé ----------
cat >&2 <<EOF

  Installation $( [[ "$DRY_RUN" -eq 1 ]] && echo "(dry-run)" || echo "appliquée" ) sous $PREFIX.

  Prochaines étapes :
    1. Éditer $ETC_DIR/proxy.env (et $ETC_DIR/control.env si applicable).
    2. Si exposé hors loopback : renseigner ANTIDDOS_CTRL_API_TOKEN
       et ANTIDDOS_PROXY_ADMIN_TOKEN (>= 16 caractères).
    3. systemctl start anti-ddos-proxy$( [[ "$WITH_CONTROL" -eq 1 ]] && echo " anti-ddos-control" )
    4. systemctl status anti-ddos-proxy
    5. journalctl -u anti-ddos-proxy -f

EOF
