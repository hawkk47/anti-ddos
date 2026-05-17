# ADR 0002 — Portabilité Windows + Linux à parité

- **Date** : 2026-05-15
- **Statut** : Accepté
- **Décideurs** : équipe projet
- **Concerne** : tout le projet

## Contexte

Le projet doit fonctionner **à parité** sur :

- **Windows 10+ (x64)**
- **Linux x86_64** (distributions glibc modernes : Ubuntu 22.04+, Debian 12+,
  RHEL 9+, Alpine acceptable mais pas prioritaire car musl)

macOS, FreeBSD, ARM, Windows Server Core sont **hors scope** du MVP. Tout
ajout de plateforme exige une nouvelle ADR.

« À parité » signifie : toute fonctionnalité testée sur l'un doit
fonctionner sur l'autre, avec les mêmes commandes (modulo `.sh`/`.ps1`).

## Décision

### CI bloquante sur les deux OS

Matrix `[ubuntu-latest, windows-latest]` dans
[.github/workflows/ci.yml](../../.github/workflows/ci.yml). Une PR rouge
sur l'un des deux est bloquante. Pas d'`if: matrix.os == 'ubuntu-latest'`
qui exclurait silencieusement Windows d'un test.

### Interdits techniques (cross-cutting)

| Technique | Pourquoi interdit | Alternative portable |
|---|---|---|
| `cgo` (Go) | Casse le build Windows hors MSVC, alourdit la cross-compile | Pure-Go uniquement |
| Modules Node natifs (`node-gyp`) | Idem côté MSVC | Libs JS pures uniquement |
| `eBPF` / `XDP` | N'existent pas sur Windows | Mitigation L7 applicative |
| `iptables` / `nftables` | N'existent pas sur Windows | Drop applicatif L7 |
| `epoll` / `io_uring` direct | Linux-only | Stdlib (Go runtime, `net.Listener`) |
| `SO_REUSEPORT` | Sémantique différente Win/Linux | Listener unique + worker pool Go |
| Unix Domain Sockets pour IPC | Supportés Win10+ mais peu d'outils | TCP `127.0.0.1:port` + mTLS |
| Named pipes Windows | N'existent pas Linux | Idem |
| Signaux `SIGUSR1/2` | N'existent pas Windows | Endpoint HTTP `POST /v1/reload` |
| Chemins en dur `/etc/...`, `/var/...` | N'existent pas Windows | `os.UserConfigDir()` (Go), `process.env.XDG_CONFIG_HOME` (Node), variables d'env |
| `chmod 600` comme garantie | Sémantique différente | Documenter les attentes ACL ; ne pas s'y fier comme contrôle de sécurité unique |
| `bash` requis sans alternative | Pas dispo par défaut sur Windows hors WSL/Git Bash | Fournir un `.ps1` équivalent (cf. [scripts.instructions.md](../../.github/instructions/scripts.instructions.md)) |

### Conventions de chemin

- Toujours `filepath.Join` (Go) / `path.join` (Node), jamais de séparateur
  hardcodé.
- Les exemples dans la doc utilisent `/` (Unix style) ; les utilisateurs
  Windows comprennent la traduction.

### Tests

- `tests/run-integration.sh` (Bash) **et** `tests/run-integration.ps1`
  (PowerShell) doivent exister et faire la même chose.
- Aucun test ne fait de `t.Skip` sur Windows sans ticket explicite.

## Conséquences

- **Coût** : duplication Bash/PowerShell sur les scripts ops critiques.
  Accepté, mitigé par modèle de référence (hooks `scan-secrets`).
- **Bénéfice** : surface d'attaque et de bug plus prévisible (un seul
  comportement à valider au lieu de deux).
- **Limite assumée** : performance brute potentiellement inférieure à
  un proxy Linux-only utilisant XDP. Compensée par le choix de viser
  des charges L7 (pas L3 multi-Gbps).

### Si une fonctionnalité Linux-only devient indispensable

Procédure :

1. Documenter dans une nouvelle ADR pourquoi la portabilité est
   sacrifiée pour cette fonctionnalité.
2. L'isoler dans un **composant séparé** (binaire ou plugin) Linux-only,
   pas dans le data plane principal.
3. Le rendre **optionnel** : le proxy doit continuer à fonctionner
   sans, juste avec moins de mitigations.

## Réversibilité

Élevée pour ajouter macOS / ARM (étendre la matrix CI). Faible pour
*retirer* Windows : tout le projet est conçu autour de cette contrainte.
