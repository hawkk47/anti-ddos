# Installation serveur — Linux & Windows

Scripts pour déployer le data plane et le control plane comme services
système (systemd sous Linux, Windows Service sous Windows), à parité de
comportement (cf. [ADR 0002](../../docs/adr/0002-portability-windows-linux.md)).

## Layout installé

| Cible        | Linux                              | Windows                                          |
|--------------|------------------------------------|--------------------------------------------------|
| Binaires     | `/opt/anti-ddos/bin/`              | `C:\Program Files\anti-ddos\bin\`                |
| Control plane| `/opt/anti-ddos/control/`          | `C:\Program Files\anti-ddos\control\`            |
| Configs/env  | `/etc/anti-ddos/`                  | `C:\ProgramData\anti-ddos\etc\`                  |
| État         | `/var/lib/anti-ddos/`              | `C:\ProgramData\anti-ddos\state\`                |
| Logs         | `/var/log/anti-ddos/`              | `C:\ProgramData\anti-ddos\logs\`                 |
| Service DP   | `systemctl … anti-ddos-proxy`      | `Get-Service anti-ddos-proxy`                    |
| Service CP   | `systemctl … anti-ddos-control`    | `Get-Service anti-ddos-control`                  |

## Linux (systemd)

Prérequis : root, `go >= 1.22`, `node >= 20`, `pnpm`, `systemd`.

```bash
# 1. dry-run — affiche ce qui sera fait
sudo ./scripts/install/install-server.sh

# 2. application
sudo ./scripts/install/install-server.sh --yes

# 3. édition de la config (jamais de secret commité)
sudo $EDITOR /etc/anti-ddos/proxy.env
sudo $EDITOR /etc/anti-ddos/control.env

# 4. démarrage
sudo systemctl start anti-ddos-proxy anti-ddos-control
sudo systemctl status anti-ddos-proxy
sudo journalctl -u anti-ddos-proxy -f
```

Désinstallation :

```bash
sudo ./scripts/install/uninstall-server.sh --yes         # garde configs/état
sudo ./scripts/install/uninstall-server.sh --yes --purge # tout supprimer
```

## Windows (Service)

Prérequis : PowerShell 5.1+, admin, `go >= 1.22`, `node >= 20`, `pnpm`.

```powershell
# 1. dry-run
.\scripts\install\install-server.ps1

# 2. application
.\scripts\install\install-server.ps1 -Yes

# 3. édition de la config
notepad C:\ProgramData\anti-ddos\etc\proxy.env
notepad C:\ProgramData\anti-ddos\etc\control.env

# 4. démarrage
Start-Service anti-ddos-proxy, anti-ddos-control
Get-Service anti-ddos-*
```

Désinstallation :

```powershell
.\scripts\install\uninstall-server.ps1 -Yes
.\scripts\install\uninstall-server.ps1 -Yes -Purge   # supprime aussi ProgramData
```

## Options communes

| Flag (sh)        | Flag (ps1)    | Effet                                          |
|------------------|---------------|------------------------------------------------|
| `--dry-run` (déf)| `-DryRun` (déf)| affiche sans modifier                          |
| `--yes`          | `-Yes`        | applique                                       |
| `--prefix DIR`   | `-Prefix DIR` | change le préfixe d'installation               |
| `--no-control`   | `-NoControl`  | data plane seul (pas de Node.js requis)        |

## Sécurité

- **Aucun secret n'est écrit par l'installer.** Les fichiers `.env`
  installés sont copiés depuis `*.env.example` (commités) et ne
  contiennent que des placeholders. Les tokens (`ANTIDDOS_CTRL_API_TOKEN`,
  `ANTIDDOS_PROXY_ADMIN_TOKEN`) doivent être ajoutés sur la machine.
- Sous Linux les `.env` sont en `0640 root:anti-ddos`.
- Le binaire data plane tourne en utilisateur dédié `anti-ddos` non
  privilégié + sandbox systemd (`ProtectSystem=strict`, `NoNewPrivileges`,
  `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`).
- Sous Windows le service tourne par défaut comme `LocalSystem` —
  envisager de le réduire à `NT SERVICE\anti-ddos-proxy` via
  `sc.exe config anti-ddos-proxy obj=…` selon votre politique.
- Le control plane refuse de démarrer si `ANTIDDOS_CTRL_HOST` n'est pas
  loopback **et** qu'aucun `ANTIDDOS_CTRL_API_TOKEN` (>= 16 chars) n'est
  défini. Voir [control/src/config.ts](../../control/src/config.ts).

## Mise à jour

Relancer l'installer (avec `--yes`/`-Yes`) — il est idempotent :
recompile, copie les binaires par-dessus, recharge l'unit systemd
ou met à jour la config du service Windows. Les `.env` existants
ne sont **pas** écrasés.
