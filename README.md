# anti-ddos

Reverse proxy HTTP avec mitigations anti-DDoS L7, portable
**Windows 10+** et **Linux x86_64**.

- **Data plane** : Go pur (≥ 1.22, `CGO_ENABLED=0`) — termine TLS,
  applique les mitigations sur le chemin chaud.
- **Control plane** : Node.js + TypeScript (Fastify) — API d'admin,
  persistance et distribution des règles à chaud.
- **UI d'admin** : Svelte + Vite — tableau de bord temps réel,
  cartographie géo, état des familles de mitigation.

## Mitigations couvertes

### Couche application (L7)

| Famille | Cible |
|---|---|
| `httpflood` | Flood HTTP L7 (RPS abusif, scrapers agressifs) |
| `slowloris` / `slowpost` | Sockets/headers/body lents |
| `http2reset` | CVE-2023-44487 (HTTP/2 Rapid Reset) |
| `hashflood` | Collisions de hash sur grandes maps |
| `rangeamp` | Range request amplification |
| `cachepoison` | Cache poisoning via headers déviants |
| `concurrency` | Saturation de connexions / requêtes concurrentes |
| `credstuff` | Credential stuffing |
| `largeheader` / `requesthygiene` | Headers oversized, encodage douteux |
| `scraping` | Patterns bot / scraping en masse |
| `tlsfingerprint` / `tlsreneg` | JA3 hostiles, renégociation TLS abusive |

### Couche réseau (L3/L4)

Listener wrappers TCP appliqués avant la terminaison TLS. Tous fail-open
par défaut, contournement automatique du loopback et des préfixes RFC1918/ULA.

| Famille | Cible |
|---|---|
| `ip-reputation` | Allowlist/blocklist CIDR statiques + entrées dynamiques à TTL |
| `conn-flood` | Plafond de connexions simultanées par IP et par sous-réseau |
| `syn-flood` | Cadence d'acceptation par IP/sous-réseau (token bucket) avec report vers `ip-reputation` |
| `handshake-guard` | TCP half-open applicatif (handshake OK mais aucun octet utile) |
| `geoblock-l4` | Filtre par code pays ISO-3166-1 alpha-2 dès l'acceptation TCP |

Chaque famille a une règle YAML déclarative dans [configs/base/](configs/base/),
un module Go dans [proxy/mitigations/](proxy/mitigations/) et un
endpoint REST d'admin côté control plane.

## Layout

| Dossier | Rôle |
|---|---|
| [proxy/](proxy/) | Data plane Go |
| [control/](control/) | Control plane Node/TS |
| [ui/](ui/) | Tableau de bord Svelte |
| [configs/](configs/) | Règles WAF, seuils, upstreams (YAML, schémas JSON) |
| [tests/](tests/) | Intégration cross-langages, reproducers d'attaques (loopback uniquement) |
| [docs/](docs/) | ADR, threat model, runbooks |

## Quickstart

### Prérequis

| Outil | Version | Win | Linux |
|---|---|---|---|
| Go | ≥ 1.22 | [installer MSI](https://go.dev/dl/) | `apt install golang-go` ou tarball officiel |
| Node.js | ≥ 20 | [installer MSI](https://nodejs.org/) | `nvm install 20` |
| pnpm | ≥ 9 | `npm i -g pnpm` | idem |
| Git | ≥ 2.40 | Git for Windows | `apt install git` |

PowerShell 5.1+ est disponible nativement sur Windows.

### Build & run

Data plane :

```bash
cd proxy
CGO_ENABLED=0 go build ./...
go test -race ./...
go run ./cmd/proxy
```

Control plane :

```bash
cd control
pnpm install
pnpm test
pnpm dev
```

UI :

```bash
cd ui
pnpm install
pnpm dev      # serveur de dev sur 127.0.0.1:5173
pnpm build    # bundle statique dans ui/dist
```

### Suite d'intégration

Linux / macOS / Git Bash :

```bash
bash tests/run-integration.sh
```

Windows PowerShell :

```powershell
./tests/run-integration.ps1
```

Les deux scripts démarrent proxy + control plane sur des ports
éphémères loopback, exécutent les tests, puis nettoient.

## Configuration

Le control plane et l'admin API du data plane refusent de démarrer
sur un bind non-loopback sans token Bearer.

| Variable                     | Composant     | Rôle |
|------------------------------|---------------|------|
| `ANTIDDOS_CTRL_HOST`         | control plane | Interface d'écoute (défaut `127.0.0.1`). |
| `ANTIDDOS_CTRL_PORT`         | control plane | Port d'écoute (défaut `9090`). |
| `ANTIDDOS_CTRL_API_TOKEN`    | control plane | Token Bearer 16–512 chars, obligatoire hors loopback. |
| `ANTIDDOS_ADMIN_LISTEN`      | data plane    | Bind admin (défaut `127.0.0.1:8081`), loopback obligatoire. |
| `ANTIDDOS_ADMIN_TOKEN`       | data plane    | Token Bearer (défense en profondeur). |
| `ANTIDDOS_PROXY_ADMIN_TOKEN` | control plane | Token envoyé au data plane pour les pushes. |

Routes publiques jamais protégées :
`GET /v1/health`, `GET /metrics`, `GET /_admin/v1/health`,
`GET /_admin/v1/metrics`. Toutes les autres exigent
`Authorization: Bearer <token>` quand un token est configuré
(comparaison en temps constant, pas d'écho dans les logs).

## Sécurité

Projet purement défensif. Les reproducers d'attaques restent
cantonnés à [tests/](tests/) et ne ciblent jamais autre chose que
`127.0.0.1` / `::1` / `localhost`.

## Licence

Apache License 2.0 — voir [LICENSE](LICENSE).
