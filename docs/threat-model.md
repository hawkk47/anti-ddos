# Threat Model — anti-ddos

Catalogue des attaques couvertes (ou planifiées) par le proxy. Une
section par `<attack-id>`. Source de vérité côté docs ; le code et les
configs référencent cette page via `notes:` ou commentaires.

Format des sections : généré par le prompt
[`/threat-model-entry`](../.github/prompts/threat-model-entry.prompt.md).

## Périmètre

- Couche cible : **L7 HTTP/1.1 et HTTP/2** sur TCP+TLS.
- Plateformes : Windows 10+ et Linux x86_64 (cf.
  [ADR 0002](./adr/0002-portability-windows-linux.md)).
- **Hors scope** L3/L4 (SYN flood massif, amplification UDP) : à
  traiter par l'infra réseau en amont (cloud provider, ISP). Le proxy
  assume que le trafic IP arrive jusqu'à lui.

## Index (MVP)

Les 5 attaques cibles du MVP, par priorité d'implémentation :

| # | `<attack-id>` | Statut | Vecteur résumé |
|---|---|---|---|
| 1 | [slowloris](#slowloris) | **livré v0.1** | Connexions lentes qui épuisent le pool |
| 2 | [http-flood-l7](#http-flood-l7) | **livré v0.2** | Volume de requêtes HTTP légitimes en apparence |
| 3 | [slow-post](#slow-post) | **livré v0.4** | Body POST envoyé octet par octet |
| 4 | [large-header](#large-header) | **livré v0.3** | Headers énormes pour saturer parsing/mem |
| 5 | [tls-renegotiation-flood](#tls-renegotiation-flood) | **livré v0.5** | Renégociation TLS répétée pour brûler du CPU |
| 6 | [http2-rapid-reset](#http2-rapid-reset) | **livré v0.6** | Open + RST_STREAM HTTP/2 massif (CVE-2023-44487) |
| 7 | [hash-flood](#hash-flood) | **livré v0.7** | Trop de paramètres dans la query string (parsing O(n)) |
| 8 | [range-amplification](#range-amplification) | **livré v0.8** | Range header massif déclenchant un multipart amplifié (CVE-2011-3192) |
| 9 | [cache-poisoning](#cache-poisoning) | **livré v0.9** | Headers « unkeyed » empoisonnant un cache aval (Kettle 2018) |
| 10 | [scraping-aggressif](#scraping-aggressif) | **livré v1.0** | Bots/scrapers naïfs identifiés par signature (User-Agent + headers manquants) |
| 11 | [credential-stuffing](#credential-stuffing) | **livré v1.1** | Replay massif de paires login/password volées sur endpoints d'authentification |
| 12 | [concurrency-saturation](#concurrency-saturation) | **livré v1.2** | Saturation in-flight (rafale légitime, multi-IP) — load shedding global |
| 13 | [request-hygiene](#request-hygiene) | **livré v1.3** | Méthodes hors-RFC, URIs énormes, framing ambigu (CL/TE conflict, smuggling) |
| 14 | [ja3-ja4-fingerprint](#ja3-ja4-fingerprint) | **livré v1.4** (dormant) | Bots TLS connus par empreinte JA3 / JA4 du ClientHello |

Post-MVP : aucune attaque restante au backlog initial.

---

## slowloris

**Vecteur.** Le client ouvre N connexions TCP vers le proxy et envoie
les en-têtes HTTP/1.1 1 octet toutes les X secondes, sans envoyer le
`\r\n\r\n` final. Chaque connexion mobilise un slot du pool jusqu'au
timeout (`ReadHeaderTimeout`). Avec quelques milliers de connexions
lentes, le serveur ne peut plus accepter de trafic légitime.

**Ressource épuisée.** File descriptors / slots de connexion (TCP +
goroutines `http.Server`). Chaîne secondaire : mémoire des buffers de
lecture par connexion.

**Signal observable.** Forte concurrence de connexions par IP source
relativement à la médiane historique, en l'absence de body de requête
complet (en-têtes incomplets).

**Mitigation appliquée.** Plafond de connexions concurrentes par IP
au niveau `accept()` ([proxy/mitigations/slowloris/](../proxy/mitigations/slowloris/)).
Les connexions au-delà du quota sont fermées immédiatement (RST/FIN),
le slot OS est libéré tout de suite. Mode : **fail-open** (si la
configuration tombe en erreur, pass-through). Les en-têtes bénéficient
de plus du `ReadHeaderTimeout` stdlib (défaut 5 s).

| Paramètre | Source | Défaut |
|---|---|---|
| `max_conns_per_ip` | [configs/base/connections.yaml](../configs/base/connections.yaml) | 64 |
| `on_error` | idem | `allow` |
| `enabled` | idem | `true` |

Les mises à jour passent par `PUT /v1/mitigations/connections/slowloris`
sur le control plane (validation TypeBox + JSON Schema).

**Faux positifs attendus.** Clients NAT'és (universités, opérateurs
mobiles CGNAT) où plusieurs centaines d'utilisateurs partagent une
IP publique. Tuner `max_conns_per_ip` par environnement via
`configs/prod/connections.yaml`. Suivre le ratio
`blocked_total / evaluated_total` ; un saut sur une IP/24 connue NAT
est le signal pour relâcher.

**Métriques à surveiller.**

| Nom | Type | Usage |
|---|---|---|
| `mitigation_slowloris_evaluated_total` | counter | trafic vu par la règle |
| `mitigation_slowloris_blocked_total` | counter | connexions rejetées |
| `mitigation_slowloris_errors_total` | counter | erreurs internes (config invalide sur reload) |
| `mitigation_slowloris_duration_seconds` | histogram | latence ajoutée par la règle (devrait être < 1 µs p99) |

Alerter si `blocked_total` augmente de >50%/min en l'absence d'incident
déclaré (potentielle vague d'attaque) **ou** si `evaluated_total` plafonne
brutalement (le limiter masque peut-être une saturation amont).

**Reproducer.** [proxy/mitigations/slowloris/slowloris_test.go](../proxy/mitigations/slowloris/slowloris_test.go)
(`TestSlowloris_Reproducer_BlockedWithMitigation`), lancer via
`bash tests/attacks/slowloris/scenario.sh` ou son équivalent
PowerShell. Loopback uniquement (`127.0.0.1`).

**Référence.** [RSnake, 2009](https://en.wikipedia.org/wiki/Slowloris_(cyber_attack)).

---

## http-flood-l7

**Vecteur.** Volume élevé de requêtes HTTP/1.1 ou HTTP/2 qui passent
les checks de format (URL valide, méthode connue, headers réalistes),
souvent depuis un botnet distribué ou quelques IPs avec keep-alive
agressif. Cible préférée : endpoints coûteux (recherche, login, page
dynamique, écriture). Contrairement à Slowloris, chaque requête est
complète et rapide ; c'est le **débit cumulé** qui sature.

**Ressource épuisée.** CPU et threads de l'upstream (chaque requête
servie coûte X ms de calcul), bande passante sortante (pages lourdes),
pool de connexions upstream. Le proxy lui-même n'est généralement pas
le goulot tant que les connexions restent bornées (cf. `slowloris`).

**Signal observable.** Pic de RPS soutenu par IP source bien au-delà
de la médiane historique, alors que les distributions de URL/UA/Referer
restent étroites (signature de bot). Latence amont qui monte avant que
le proxy ne sature.

**Mitigation appliquée.** Token bucket par IP au niveau du handler HTTP
([proxy/mitigations/httpflood/](../proxy/mitigations/httpflood/)). Le
bucket initial est plein (`tokens = burst`), se recharge à
`requests_per_second` tokens/s, et chaque requête consomme 1 token.
Au-delà du quota, la requête est rejetée avec HTTP 429.

Mode : **fail-closed** (`on_error: deny` par défaut). Une requête dont
l'IP est non-parseable retourne HTTP 503. Décision dans
[ADR 0003](./adr/0003-http-flood-l7-fail-closed.md) — on préfère
refuser une requête malformée que laisser passer une attaque qui
contourne le rate-limit en spoofant l'IP source.

Le reload de la config est en revanche **fail-open** : une config
invalide pushée à chaud est rejetée et l'ancienne reste active (cf.
`Limiter.Update`).

| Paramètre | Source | Défaut |
|---|---|---|
| `requests_per_second` | [configs/base/ratelimit.yaml](../configs/base/ratelimit.yaml) | 50 |
| `burst` | idem | 100 |
| `on_error` | idem | `deny` |
| `enabled` | idem | `true` |

Les mises à jour passent par `PUT /v1/mitigations/ratelimit/http-flood-l7`
sur le control plane (validation TypeBox + JSON Schema), puis sont
poussées atomiquement au proxy par `POST /v1/reload`.

**Faux positifs attendus.** Clients NAT/CGNAT agressifs (plusieurs
centaines d'utilisateurs derrière une IP publique), CI/bots légitimes
(crawlers, monitoring synthétique), applications SPA qui rafalent des
requêtes API en parallèle. Tuner `requests_per_second` et `burst` par
environnement via `configs/prod/ratelimit.yaml`. Surveiller
`blocked_total` sur les IPs/24 connues NAT — un saut sans incident
déclaré signale qu'il faut relâcher.

**Métriques à surveiller.**

| Nom | Type | Usage |
|---|---|---|
| `mitigation_http_flood_l7_evaluated_total` | counter | requêtes vues par la règle |
| `mitigation_http_flood_l7_blocked_total` | counter | requêtes rejetées (429) |
| `mitigation_http_flood_l7_errors_total` | counter | erreurs internes (IP non parseable, 503 si fail-closed) |
| `mitigation_http_flood_l7_duration_seconds` | histogram | latence ajoutée par la règle (cible : < 1 µs p99) |

Alerter si `blocked_total` augmente de >50%/min en l'absence d'incident
déclaré (potentielle attaque), si `errors_total` augmente du tout en
prod (config ou IP source malformée — investigation requise vu le mode
fail-closed), ou si le ratio `blocked / evaluated` dépasse 10% sur une
fenêtre 5 min (seuils probablement trop bas).

**Reproducer.** [proxy/mitigations/httpflood/httpflood_test.go](../proxy/mitigations/httpflood/httpflood_test.go)
(`TestReproducer_FloodWithoutMitigation` + `TestReproducer_FloodWithMitigation_Blocks`).
Scénario end-to-end : `bash tests/attacks/http-flood-l7/scenario.sh`
(et `.ps1` Windows). Loopback uniquement (`127.0.0.1`).

**Référence.** [OWASP — HTTP Flood](https://owasp.org/www-community/attacks/HTTP_Flood),
[Cloudflare DDoS glossary — HTTP flood](https://www.cloudflare.com/learning/ddos/http-flood-ddos-attack/).

---

## slow-post

**Vecteur.** Le client ouvre une connexion, envoie des headers
valides annonçant un `Content-Length` non-nul (souvent grand), puis
émet le body au compte-gouttes — un octet toutes les centaines de
ms, voire moins. Variante de Slowloris déplacée sur le corps de la
requête : les headers sont déjà lus, donc `ReadHeaderTimeout` ne
couvre pas. `ReadTimeout` global du stdlib coupe au plus tard mais
doit être long pour ne pas casser les vrais uploads (15–60 s), ce qui
laisse à l'attaquant le temps de mobiliser des centaines de slots.

**Ressource épuisée.** Slots du pool de connexions (`net/http` alloue
une goroutine par requête), buffers de requête côté upstream si on
forwarde au fil de l'eau, file d'attente du load-balancer.

**Signal observable.** Débit moyen `bytes_read / wall_clock` du body
beaucoup plus bas que la médiane historique (kbps vs Mbps),
concurrent avec un nombre anormal de POST/PUT en cours. La métrique
`mitigation_slow_post_blocked_total` craît en l'absence d'incident
upstream.

**Mitigation appliquée.** Middleware
([proxy/mitigations/slowpost/](../proxy/mitigations/slowpost/)) qui
wrappe `r.Body` pour deux contrôles :

- `max_body_bytes` : cap dur via `http.MaxBytesReader` (le stdlib
  renvoie 413 quand atteint).
- `min_bytes_per_second` exigé après `grace_period_ms` (TCP slow-start
  + TLS handshake ne doivent pas être punis). Sous le seuil, le Read
  renvoie `ErrSlowPost`, le serveur stdlib ferme la connexion et
  libère le slot.

Ordre dans la chaîne de middlewares : `large-header → http-flood-l7 →
slow-post → reverse proxy`. slow-post wrap `r.Body` donc doit
rester au plus près du handler upstream.

Mode `on_error` par défaut **`allow`** (fail-open AGENTS.md §3,
aucun ADR contraire : couper sur bug interne risquerait de casser des
uploads légitimes).

**Paramètres exploitables.**

| Param | Source | Défaut MVP |
|---|---|---|
| `max_body_bytes` | [configs/base/bodies.yaml](../configs/base/bodies.yaml) | 8 388 608 (8 MiB) |
| `min_bytes_per_second` | [configs/base/bodies.yaml](../configs/base/bodies.yaml) | 1024 (1 KiB/s) |
| `grace_period_ms` | [configs/base/bodies.yaml](../configs/base/bodies.yaml) | 2000 (2 s) |
| `on_error` | id. | `allow` |

Reload à chaud : `POST /v1/reload` (control plane) → PUT vers
`/_admin/v1/mitigations/bodies` sur le data plane (loopback-only).

**Faux positifs.** Uploads légitimes lents (3G dégradée, Wi-Fi
saturé). Mesures : abaisser `min_bytes_per_second` si la métrique
`blocked_total` craît sans corrélation aux autres signaux d'attaque,
ou allonger `grace_period_ms` pour les routes connues lentes.
`max_body_bytes` à ajuster si l'upstream accepte des fichiers plus
gros (vidéo, archive).

**Métriques.**
- `mitigation_slow_post_evaluated_total`
- `mitigation_slow_post_blocked_total`
- `mitigation_slow_post_errors_total`
- `mitigation_slow_post_duration_seconds`

**Reproducer.** [proxy/mitigations/slowpost/slowpost_test.go](../proxy/mitigations/slowpost/slowpost_test.go),
fonctions `TestReproducer_SlowPost_WithoutMitigation` et
`TestReproducer_SlowPost_WithMitigation_Blocks` (drip reader à 10 o/s
face à un seuil de 50 o/s, horloge injectée).

Scénario end-to-end : `bash tests/attacks/slow-post/scenario.sh`
(et `.ps1` Windows). Loopback uniquement (`127.0.0.1`).

**Référence.** [OWASP — Slow HTTP attack](https://owasp.org/www-community/attacks/Slow_HTTP_Headers_DoS_attack),
[CWE-400](https://cwe.mitre.org/data/definitions/400.html).

---

## large-header

**Vecteur.** Un client envoie des requêtes HTTP avec :

- une **valeur** de header énorme (cookie de plusieurs Mo, `User-Agent`
  artisanal, `Authorization` géant, `X-*` rempli de padding), ou
- un **grand nombre** de headers distincts (`X-N-1, X-N-2, …, X-N-50000`).

Le but est de faire allouer des buffers démesurés côté proxy ou
upstream, ou de faire dégénérer un algorithme de parsing en O(n²)
(canonicalisation, dédoublonnage, héritage h2 HPACK).

**Ressource épuisée.** Mémoire RSS du proxy (allocation des buffers de
lecture + map des headers), CPU de parsing, mémoire upstream si la
requête est forwardée. En HTTP/2 l'amplification HPACK peut faire
exploser l'état par-connexion.

**Signal observable.** Taille moyenne de header par requête qui
dépasse la médiane historique, ou nombre de headers/requête
anormalement élevé. En l'absence d'instrumentation upstream, le
proxy voit un pic de mémoire allouée pour le parsing.

**Mitigation appliquée.** Deux contrôles granulaires en middleware
([proxy/mitigations/largeheader/](../proxy/mitigations/largeheader/))
appliqués **avant** le rate-limit L7 (pour ne pas consommer un token
sur du trafic hostile) :

- `max_header_count` : nombre maximal d'entrées distinctes par requête.
- `max_value_bytes` : taille maximale (octets) d'UNE valeur de header.

Au-delà, le proxy répond **HTTP 431 Request Header Fields Too Large**
sans appeler l'upstream. Complémentaire au cap global stdlib
`Server.MaxHeaderBytes` (16 KiB par défaut chez nous), qui coupe au
niveau parse-time avant que les handlers ne voient la requête — cette
mitigation l'étend par-header.

Mode : **fail-open** (`on_error: allow` par défaut, conforme
[AGENTS.md §3](../AGENTS.md)). Pas d'ADR contraire pour cette famille :
un bug du middleware ne doit pas bloquer du trafic légitime, et la
seconde ligne de défense (`MaxHeaderBytes` stdlib) reste active.

| Paramètre | Source | Défaut |
|---|---|---|
| `max_header_count` | [configs/base/headers.yaml](../configs/base/headers.yaml) | 100 |
| `max_value_bytes` | idem | 8192 |
| `on_error` | idem | `allow` |
| `enabled` | idem | `true` |

Les mises à jour passent par `PUT /v1/mitigations/headers/large-header`
sur le control plane (validation TypeBox + JSON Schema), puis sont
poussées atomiquement au proxy par `POST /v1/reload`.

**Faux positifs attendus.** Authentification SSO avec cookies de
session volumineux (SAML assertion en cookie, plusieurs JWT
empilés), proxies amont qui injectent une chaîne de
`X-Forwarded-*` longue, certains user-agents corporate qui empilent
des headers de telemetry. Tuner `max_value_bytes` (16 à 32 KiB est
raisonnable pour du SSO) via `configs/prod/headers.yaml`. Surveiller
`blocked_total` par /24 — un saut sur un range bureautique connu
signale qu'il faut relâcher.

**Métriques à surveiller.**

| Nom | Type | Usage |
|---|---|---|
| `mitigation_large_header_evaluated_total` | counter | requêtes vues par la règle |
| `mitigation_large_header_blocked_total` | counter | requêtes rejetées (431) |
| `mitigation_large_header_errors_total` | counter | erreurs internes (config invalide sur reload) |
| `mitigation_large_header_duration_seconds` | histogram | latence ajoutée par la règle (cible : < 1 µs p99) |

Alerter si `blocked_total` augmente de >50%/min en l'absence
d'incident déclaré (potentielle attaque), ou si le ratio
`blocked / evaluated` dépasse 5% sur 5 min en prod (seuils
probablement trop bas pour un sous-réseau corporate).

**Reproducer.** [proxy/mitigations/largeheader/largeheader_test.go](../proxy/mitigations/largeheader/largeheader_test.go)
(`TestReproducer_LargeHeader_WithoutMitigation` +
`TestReproducer_LargeHeader_WithMitigation_Blocks`). Scénario
end-to-end : `bash tests/attacks/large-header/scenario.sh` (et `.ps1`).
Loopback uniquement (`127.0.0.1`).

**Référence.** [OWASP — Buffer overflow attack via headers](https://owasp.org/www-community/attacks/Buffer_overflow_attack),
[CVE-2018-16487 (HPACK bomb)](https://nvd.nist.gov/vuln/detail/CVE-2018-16487).

---

## tls-renegotiation-flood

**Statut.** Livré v0.5 (fail-open).

**Vecteur.** Deux variantes coexistent dans cette famille :

1. **Renégociation cliente** (TLS 1.0/1.1/1.2) — Le client initie un
   handshake puis demande N renégociations sur la même connexion. Chaque
   renégociation force le serveur à recalculer une clé éphémère (coûteux :
   plusieurs millisecondes CPU pour chaque ECDHE/RSA). Un client peut donc
   amplifier sa charge serveur d'un facteur >100 avec un trafic réseau
   minimal (CVE-2009-3555 historique, encore exploitable contre des
   serveurs mal configurés).
2. **Handshake flood** — Ouverture massive de nouvelles connexions TCP
   avec demande de handshake TLS. Identique à un SYN flood mais le coût
   serveur est porté par la cryptographie, pas par le noyau.

**Ressource épuisée.** CPU du proxy (cryptographie asymétrique pendant
le ClientHello/ServerHello + key exchange).

**Détection.**

1. Le data plane refuse explicitement la renégociation cliente via
   `tls.Config.Renegotiation = RenegotiateNever` (la stdlib Go applique
   déjà ce défaut en pure-Go ; on le rend explicite et auditable).
2. Sur l'`Accept()` du listener TCP, un token bucket par IP source
   limite le taux de nouveaux handshakes (`handshakes_per_second_per_ip`,
   `burst`). Les conns rejetées sont closes avant tout coût TLS.
3. `MinVersion = TLS 1.2` est imposé (TLS 1.0/1.1 expose BEAST/POODLE
   et a une renégociation moins protégée).

**Réaction par défaut.** `Close` direct de la connexion TCP refusée par
le bucket (avant tout handshake). Aucun coût CPU côté serveur. La
renégociation cliente, si tentée, est refusée par crypto/tls et la
connexion est terminée.

**Métriques exposées.**

- `mitigation_tls_renegotiation_flood_evaluated_total` — Nombre
  d'évaluations du token bucket (1 par Accept).
- `mitigation_tls_renegotiation_flood_blocked_total` — Connexions
  closes par dépassement du bucket.
- `mitigation_tls_renegotiation_flood_errors_total` — Erreurs internes
  (config invalide rejetée à l'`Update`, `Accept` qui retourne erreur
  hors `EOF` raisonnable). Fail-open : on laisse passer.
- `mitigation_tls_renegotiation_flood_duration_seconds` — Latence
  d'évaluation du bucket (doit rester en microsecondes).

**Configuration.** [configs/base/tls.yaml](../configs/base/tls.yaml)
contient les seuils par défaut (TLS ≥1.2, 50 handshakes/s/IP, burst 20)
et le schéma [configs/schemas/tls.schema.json](../configs/schemas/tls.schema.json)
contraint les valeurs admissibles. Mode `on_error: allow` (fail-open) par
défaut — la renégociation cliente reste refusée au niveau crypto/tls
quel que soit `on_error`.

**Pourquoi fail-open ?** Sur erreur interne du token bucket
(corruption d'état, race exotique), on préfère laisser passer le
handshake plutôt que d'enfermer le service. La protection cœur
(`RenegotiateNever`, `MinVersion`) n'est pas dépendante du bucket :
elle reste active même si le wrapper de listener est désactivé.

**Limites connues.**

- Le bucket est par IP source (donc bypassable par botnet distribué) ;
  la mitigation est complémentaire de `http-flood-l7` et d'un éventuel
  Anycast/scrubbing amont.
- TLS 1.3 supprime la renégociation classique mais introduit
  l'authentification post-handshake. Le moteur stdlib Go ne l'expose pas
  côté serveur en mode par défaut — pas d'exposition supplémentaire.
- Le `burst` doit rester suffisant pour absorber le chargement d'une
  page riche en sous-domaines (plusieurs connexions parallèles).

**Reproducteur.** [tests/attacks/tls-renegotiation-flood/scenario.sh](../tests/attacks/tls-renegotiation-flood/scenario.sh)
et son équivalent `.ps1` exécutent les tests Go
`TestReproducer_HandshakeFlood_*` du package
`proxy/mitigations/tlsreneg` (loopback only).

**Référence.** [CVE-2009-3555 — TLS renegotiation](https://nvd.nist.gov/vuln/detail/CVE-2009-3555),
[RFC 5746 — Renegotiation Indication](https://www.rfc-editor.org/rfc/rfc5746),
[OWASP — TLS hardening](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).

---

## http2-rapid-reset

**Statut.** Livré v0.6 (fail-open).

**Vecteur.** Le client HTTP/2 ouvre un grand nombre de streams sur une
même connexion TCP puis envoie immédiatement une trame `RST_STREAM` sur
chacun, sans attendre la réponse. Chaque cycle open/reset force le
serveur à allouer une goroutine, parser HPACK et démarrer le handler
avant que l'annulation ne se propage. Avec quelques milliers de cycles
par seconde et par connexion, un seul client (voire un seul navigateur
HTTP/2) peut saturer un cœur CPU. C'est l'attaque [CVE-2023-44487](https://nvd.nist.gov/vuln/detail/CVE-2023-44487)
exploitée à grande échelle en octobre 2023 (≈ 398 M req/s observées
par Google).

**Ressource épuisée.** CPU du proxy (création de streams, parsing
HPACK, scheduling goroutines). Mémoire secondaire pour les buffers de
streams transitoires.

**Détection.**

1. `http2.Server.MaxConcurrentStreams` annonce une limite stricte
   (défaut MVP : 100) au peer HTTP/2 via `SETTINGS_MAX_CONCURRENT_STREAMS`,
   empêchant un client de tenir un nombre déraisonnable de streams en
   parallèle.
2. Le middleware Go observe chaque requête après son passage dans le
   handler : si `r.Context().Err() == context.Canceled` ET qu'aucune
   écriture n'a été faite (`WriteHeader` / `Write`), c'est la signature
   exacte d'un RST_STREAM précoce.
3. Un compteur par connexion TCP (associé via `http.Server.ConnContext`)
   incrémente sur chaque event. Fenêtre glissante de
   `window_ms` ms (10 s par défaut) ; au-delà de `max_resets_per_conn`
   resets (100 par défaut), la connexion est fermée force-close.

**Réaction par défaut.** `conn.Close()` sur la TCP au franchissement
du seuil. Le client doit ouvrir une nouvelle connexion pour reprendre
— le coût d'attaque devient celui d'un handshake TLS par cycle, ce
qui borne mécaniquement le débit.

**Métriques exposées.**

- `mitigation_http2_rapid_reset_evaluated_total` — Annulations
  précoces observées (1 par stream RST tôt).
- `mitigation_http2_rapid_reset_blocked_total` — Connexions TCP closes
  pour dépassement du seuil.
- `mitigation_http2_rapid_reset_errors_total` — Erreurs internes
  (config invalide rejetée à l'`Update`). Fail-open : on laisse passer.
- `mitigation_http2_rapid_reset_duration_seconds` — Latence de
  l'évaluation par requête (doit rester en microsecondes).

**Configuration.** [configs/base/http2.yaml](../configs/base/http2.yaml)
contient les seuils par défaut (100 resets/conn sur 10 s, 100 streams
concurrents max) et le schéma [configs/schemas/http2.schema.json](../configs/schemas/http2.schema.json)
contraint les valeurs admissibles. Mode `on_error: allow` (fail-open)
par défaut.

**Pourquoi fail-open ?** Sur erreur interne du compteur (corruption
d'état, race), on préfère laisser passer plutôt qu'enfermer tout le
trafic HTTP/2 légitime. La protection cœur reste active de toute
façon via `MaxConcurrentStreams` (annoncé par le moteur HTTP/2 lui-même
indépendamment du compteur).

**Limites connues.**

- Le compteur est par connexion TCP. Un attaquant distribué qui ouvre
  beaucoup de TCP différentes (1 reset par TCP) ne déclenchera pas la
  mitigation. Complémentaire de `http-flood-l7` (rate-limit par IP) et
  de `slowloris` (limite de conns simultanées par IP).
- Le signal `Context().Err() == Canceled + !written` peut aussi être
  observé sur une coupure réseau côté client (mobile qui change de
  cellule). En pratique le seuil par défaut (100 sur 10 s) est très
  au-dessus de ces faux positifs.
- Le MVP sert HTTP/2 en cleartext (h2c). Quand TLS sera ajouté, h2 sur
  TLS suivra la même chaîne (`ConnContext`/`ConnState` reste valide).

**Reproducteur.** [tests/attacks/http2-rapid-reset/scenario.sh](../tests/attacks/http2-rapid-reset/scenario.sh)
et son équivalent `.ps1` exécutent les tests Go
`TestReproducer_RapidReset_*` du package
`proxy/mitigations/http2reset` (loopback only).

**Référence.** [CVE-2023-44487 — HTTP/2 Rapid Reset](https://nvd.nist.gov/vuln/detail/CVE-2023-44487),
[Google Cloud — HTTP/2 Rapid Reset disclosure](https://cloud.google.com/blog/products/identity-security/google-cloud-mitigated-largest-ddos-attack-peaking-above-398-million-rps),
[RFC 9113 — HTTP/2 §5.1.1](https://www.rfc-editor.org/rfc/rfc9113#section-5.1.1).

---

## hash-flood

**Statut.** Livré v0.7 (fail-open).

**Vecteur historique.** Un attaquant envoie une requête avec un grand
nombre de paramètres dont les clés ont été choisies pour entrer en
collision dans la hash map du serveur. Le coût de parsing dégénère
alors en O(n²) au lieu d'O(n). C'est la famille [CVE-2011-3414](https://nvd.nist.gov/vuln/detail/CVE-2011-3414)
(PHP), [CVE-2012-5371](https://nvd.nist.gov/vuln/detail/CVE-2012-5371)
(Ruby), CVE-2011-4858 (Java/Tomcat), CVE-2011-4885 (Python). Une
requête de quelques Mo de query string pouvait consommer plusieurs
minutes CPU sur les implantations vulnérables.

**Vecteur résiduel en Go.** La map native Go est immunisée contre les
collisions *algorithmiques* depuis ses premières versions :

- la seed du hasher est randomisée par processus (cf. runtime/hash*.go),
- le hasher (AES-NI ou wyhash selon plateforme) n'est pas inversible
  publiquement.

Le pire cas reste donc O(n) amorti et un attaquant ne peut **pas**
forcer des collisions ciblées. Le résidu d'attaque exploitable est
purement *quantitatif* : forcer le serveur à parser, URL-décoder et
allouer N entrées dans `url.Values` (un `map[string][]string`) pour
chaque requête, ce qui coûte du CPU et de la mémoire même sans
collision.

**Ressource épuisée.** CPU (URL-décodage, hashing, allocation strings)
et mémoire (entrées du map + slices de valeurs). Une URL de quelques
dizaines de Ko peut transporter des milliers de clés.

**Détection.** Comptage des paramètres dans `r.URL.RawQuery` par
`strings.Count(rawQuery, "&") + 1`. Pas de parsing, pas d'allocation,
pas d'accès map : coût O(longueur) de la query string et borne dure.
Le stdlib `net/url.ParseQuery` n'honore plus `;` comme séparateur
depuis Go 1.17, on a donc une borne exacte.

**Réaction par défaut.** HTTP 400 Bad Request si le nombre dépasse
`max_query_params` (64 par défaut). Le handler upstream n'est pas
appelé, `url.ParseQuery` n'est même pas invoqué par le proxy.

**Métriques exposées.**

- `mitigation_hash_flood_evaluated_total` — Requêtes inspectées
  (1 par requête quand activé).
- `mitigation_hash_flood_blocked_total` — Requêtes rejetées (HTTP 400).
- `mitigation_hash_flood_errors_total` — Erreurs internes (config
  invalide rejetée à l'`Update`). Fail-open : on laisse passer.
- `mitigation_hash_flood_duration_seconds` — Latence de l'évaluation
  (doit rester en sub-microseconde : un seul `strings.Count`).

**Configuration.** [configs/base/hashflood.yaml](../configs/base/hashflood.yaml)
(défaut 64 params), schéma [configs/schemas/hashflood.schema.json](../configs/schemas/hashflood.schema.json)
(`minimum: 1`, `maximum: 10000`). Mode `on_error: allow` (fail-open) par
défaut.

**Pourquoi fail-open ?** Le pire cas d'erreur du compteur est qu'on
laisse passer une requête à N paramètres traitée en O(n) par la map
Go — c'est-à-dire le comportement déjà normal sans cette mitigation.
Il n'y a pas de régression de sécurité à ne pas couper.

**Limites connues.**

- Ne couvre pas les paramètres POST form-urlencoded (qui parsent eux
aussi un map). Le body est aujourd'hui borné indirectement par
[bodies.yaml](../configs/base/bodies.yaml) (taille) et par la
mitigation `slow-post` (débit). Une future règle pourra ajouter un
comptage form explicite quand le coût de parse sera maîtrisé.
- Ne couvre pas les Cookies (un seul header, multi-valeurs séparées
par `; `). La famille `large-header` borne déjà leur taille totale et
leur nombre de clés distinctes.
- Un attaquant peut splitter en N requêtes de M params chacune sous
le seuil. Le rate-limit `http-flood-l7` et `slowloris` (conn-per-IP)
restent les barrières en cas de volume.

**Reproducteur.** [tests/attacks/hash-flood/scenario.sh](../tests/attacks/hash-flood/scenario.sh)
et son équivalent `.ps1` exécutent les tests Go
`TestReproducer_HashFlood_*` du package
`proxy/mitigations/hashflood` (loopback only).

**Référence.** [CVE-2011-3414 — PHP hash collisions](https://nvd.nist.gov/vuln/detail/CVE-2011-3414),
[CVE-2012-5371 — Ruby hash flooding](https://nvd.nist.gov/vuln/detail/CVE-2012-5371),
[Klink & Wälde 2011 — Efficient Denial of Service Attacks on Web Application Platforms](https://fahrplan.events.ccc.de/congress/2011/Fahrplan/attachments/2007_28C3_Effective_DoS_on_web_application_platforms.pdf),
[Go runtime/hash randomization](https://github.com/golang/go/blob/master/src/runtime/alg.go).

---

## range-amplification

**Statut.** Livré v0.8 (fail-open).

**Vecteur.** [CVE-2011-3192](https://nvd.nist.gov/vuln/detail/CVE-2011-3192)
("Apache Killer", S. Kingsley 2011). Le client envoie un header
`Range: bytes=0-,0-1,0-2,...,0-N` où N peut atteindre plusieurs
milliers. Le serveur respecte la RFC et répond
`206 Partial Content` avec un body `multipart/byteranges` où chaque
range occasionne une copie du contenu ciblé. Avec N=1300 sur un
fichier de quelques Mo, Apache 1.3/2.x avant 2.2.20 générait des
réponses de plusieurs Go, saturant la mémoire et le réseau de la
cible. C'est de l'**amplification 1:N** au niveau applicatif :
l'attaquant paie 1 KiB de header, le serveur produit N×taille MiB.

**Ressource épuisée.** Bande passante upstream et mémoire applicative
(buffer de chaque part du multipart). Le coût CPU est réel mais
secondaire face à l'amplification réseau.

**Détection.** Comptage des ranges dans le header `Range` par
`strings.Count(header, ",") + 1`. Pas de parsing du range-spec, pas
d'allocation, pas d'accès structuré : coût O(longueur du header) qui
est borné par `MaxHeaderBytes` (~16 KiB). La RFC 9110 §14.1.1
autorise explicitement le serveur à refuser une requête Range jugée
abusive.

**Réaction par défaut.** HTTP 416 Range Not Satisfiable si le nombre
dépasse `max_ranges` (8 par défaut). Le handler upstream n'est pas
appelé, donc même si l'origin reste vulnérable (Apache non patché,
backend NAS, etc.) il ne paye jamais le coût du multipart.

**Métriques exposées.**

- `mitigation_range_amp_evaluated_total` — Requêtes inspectées
  (1 par requête quand activé).
- `mitigation_range_amp_blocked_total` — Requêtes rejetées (HTTP 416).
- `mitigation_range_amp_errors_total` — Erreurs internes (config
  invalide rejetée à l'`Update`). Fail-open : on laisse passer.
- `mitigation_range_amp_duration_seconds` — Latence de l'évaluation
  (sub-microseconde : un seul `strings.Count`).

**Configuration.** [configs/base/rangeamp.yaml](../configs/base/rangeamp.yaml)
(défaut 8 ranges, valeur historiquement recommandée par Apache après
patch), schéma [configs/schemas/rangeamp.schema.json](../configs/schemas/rangeamp.schema.json)
(`minimum: 1`, `maximum: 1000`). Mode `on_error: allow` (fail-open) par
défaut.

**Pourquoi fail-open ?** Le compteur est un simple `strings.Count`
sur un header court (borné à `MaxHeaderBytes`). Tout échec interne
impliquerait un bug stdlib. Laisser passer n'expose pas directement
le proxy (il ne génère pas de multipart) — seule la réponse upstream
peut être amplifiée, et l'upstream est généralement patché (Apache
≥ 2.2.20 défaut 5 ranges, nginx défaut 16 ranges).

**Limites connues.**

- Ne couvre pas le header `If-Range` (utilisé pour invalider un cache
partiel). Pas de vecteur d'amplification connu à son sujet.
- Un attaquant peut éclater son attaque en N requêtes de M ranges
chacune. Le rate-limit `http-flood-l7` reste la barrière volumétrique.
- Le compteur traite `;` comme un caractère neutre (pas de virgule).
Une valeur exotique `bytes=0-1; charset=utf-8` est comptée comme
un seul range, ce qui est conservatif (sous-estime). Pas d'évasion
possible : un attaquant ne peut qu'**augmenter** le compte réel via
des virgules supplémentaires.

**Reproducteur.** [tests/attacks/range-amplification/scenario.sh](../tests/attacks/range-amplification/scenario.sh)
et son équivalent `.ps1` exécutent les tests Go
`TestReproducer_RangeAmp_*` du package
`proxy/mitigations/rangeamp` (loopback only).

**Référence.** [CVE-2011-3192 — Apache HTTPD Range header DoS](https://nvd.nist.gov/vuln/detail/CVE-2011-3192),
[Apache advisory CVE-2011-3192](https://httpd.apache.org/security/CVE-2011-3192.txt),
[RFC 9110 §14.1 — Range Requests](https://www.rfc-editor.org/rfc/rfc9110#section-14.1).

---

## cache-poisoning

**Vecteur.** L'attaquant injecte un request-header *unkeyed* (non pris
en compte dans la clé de cache aval) que l'application réfléchit dans
la réponse — typiquement `X-Forwarded-Host`, `X-Original-URL`,
`X-HTTP-Method-Override`, `X-Rewrite-URL`. Si la réponse est
cacheable, le CDN/reverse-cache en aval la sert ensuite à tous les
clients pour la même URL. Référence canonique : James Kettle,
*Practical Web Cache Poisoning*, Black Hat USA 2018.

Exemple : `GET / HTTP/1.1` avec `X-Forwarded-Host: evil.example`,
l'app construit `<link rel="canonical" href="https://evil.example/">`
dans la page d'accueil et le CDN cache cette page pour `/`.

**Ressource exploitée.** Intégrité du cache aval (pas une saturation
de capacité — un seul requête suffit à empoisonner N clients).
C'est donc un risque d'intégrité plus que de disponibilité, mais le
seuil de déclenchement est trivial et l'impact massif.

**Détection.** Inspection de la requête entrante : présence d'un
header figurant dans la liste configurable (`headers`). Vérification
case-insensitive via `textproto.CanonicalMIMEHeaderKey` précalculé
au chargement de config. Coût : O(N_headers_attaque × log N_liste)
en pratique négligeable.

**Réaction.** Deux modes configurables :

- `action: strip` (défaut, silencieux) : suppression du header avant
  forward upstream. L'application ne le voit pas, ne peut donc pas
  le réfléchir. Pas de log par requête, juste le compteur Prometheus
  `antiddos_cachepoison_stripped_total` (compté **par header**, pas
  par requête).
- `action: deny` (opt-in, bruyant) : réponse `400 Bad Request`
  immédiate. Utile en pré-prod pour identifier des clients légitimes
  qui enverraient ces headers (proxies internes mal configurés)
  avant d'activer en prod.

**Critique : préservation des headers proxy.** Le mitigateur NE DOIT
PAS strip `X-Forwarded-For`, `X-Forwarded-Proto` ni `X-Real-IP` —
ce sont les headers que le proxy lui-même positionne et que
l'upstream attend. La validation de config refuse ces noms
implicitement parce que la liste est *positive* (allowlist des
noms à strip), pas *négative*.

**Métriques.**

- `antiddos_cachepoison_evaluated_total` — requêtes inspectées.
- `antiddos_cachepoison_stripped_total` — headers retirés (somme).
- `antiddos_cachepoison_blocked_total` — requêtes refusées (deny).
- `antiddos_cachepoison_errors_total` — erreurs internes.
- `antiddos_cachepoison_duration_seconds` — histogramme.

**Fail-open.** Conforme à la politique projet : sur erreur interne du
mitigateur (panique récupérée, etc.), la requête passe avec ses
headers intacts. Le risque d'empoisonnement est jugé inférieur au
risque d'indisponibilité d'un site légitime.

**Limites connues.**

- Ne couvre pas la *Web Cache Deception* (Omer Gil, 2017) qui repose
  sur des chemins type `/account.php/nonexistent.css` — il faut une
  normalisation de chemin séparée (non livrée).
- Ne couvre pas le *HTTP request smuggling* (Kettle 2019) qui
  exploite des désaccords `Content-Length`/`Transfer-Encoding` —
  c'est un sujet de parsing HTTP, hors scope de cette mitigation.
- La liste par défaut (11 headers Kettle + IIS/Symfony) n'est pas
  exhaustive ; les apps custom peuvent réfléchir n'importe quel
  header. La liste doit être ajustée par déploiement.

**Reproducer.** [`proxy/mitigations/cachepoison/cachepoison_test.go`](../proxy/mitigations/cachepoison/cachepoison_test.go)
— `TestReproducer_CachePoison_*` démontre l'empoisonnement sans
mitigation, puis confirme le strip silencieux et le deny 400.
Le scénario d'attaque scriptable
[`tests/attacks/cache-poisoning/scenario.sh`](../tests/attacks/cache-poisoning/scenario.sh)
et son équivalent `.ps1` exécutent ces tests Go (loopback only).

**Référence.** [J. Kettle — *Practical Web Cache Poisoning*, Black Hat USA 2018](https://portswigger.net/research/practical-web-cache-poisoning),
[O. Gil — *Web Cache Deception Attack*, Black Hat USA 2017](https://www.blackhat.com/docs/us-17/wednesday/us-17-Gil-Web-Cache-Deception-Attack.pdf),
[RFC 9110 §5.5 — Field Values](https://www.rfc-editor.org/rfc/rfc9110#section-5.5).

---


## scraping-aggressif

**Vecteur.** Des bots aspirent en boucle les pages publiques (catalogue
produit, contenu éditorial, données ouvertes) pour les ré-indexer ou
les revendre. Ils utilisent souvent des libs HTTP brutes (`python-requests`,
`curl`, `wget`, `Go-http-client`, `okhttp`) ou des frameworks de scraping
explicites (`Scrapy`, `Selenium`, `Puppeteer`, `Playwright`,
`HeadlessChrome`), et n'envoient pas tous les en-têtes qu'un navigateur
grand public envoie systématiquement (`Accept-Language`,
`Accept-Encoding`).

**AVERTISSEMENT — signature only.** Cette mitigation est délibérément
naïve : un attaquant déterminé spoofe ces signaux en quelques lignes.
Elle filtre le **bruit de fond** (indexeurs mal configurés, scripts
d'apprentissage, libs HTTP par défaut), pas un adversaire motivé. Pour
du scraping persistant il faut une couche **comportementale** distincte
(rate-limit par session authentifiée, JS challenge, fingerprint TLS),
non livrée ici.

**Ressource épuisée.** Bande passante upstream, CPU du backend, et —
plus grave selon le modèle d'affaires — **les données elles-mêmes**
(exfiltration silencieuse). Aussi : pollution des métriques produit
(taux de conversion, A/B tests).

**Signal observable.** User-Agent contenant un marqueur connu (recherche
substring case-insensitive), ou absence simultanée de
`Accept-Language` / `Accept-Encoding` que tout navigateur grand public
envoie. Les seuils sont configurables par déploiement
(`configs/base/scraping.yaml`).

**Détection.** À chaque requête, on compare le `User-Agent` (lowercase
précalculé une fois pour la liste, lowercase à la volée pour la requête)
avec une liste de substrings interdites, puis on vérifie la présence
des headers requis. La détection est **allocation-free** quand la
règle est désactivée ou qu'aucun signal ne matche (chemin chaud).
Un `User-Agent` vide n'est jamais considéré comme match (anti-régression
`strings.Contains("", "")`).

**Réaction.** Deux modes :
- `log` (défaut) : laisse passer, incrémente
  `mitigation_scraping_logged_total` et journalise la décision. Permet
  d'observer le bruit avant d'activer un blocage.
- `deny` (opt-in) : refuse en `403 Forbidden` dès qu'un signal matche
  et incrémente `mitigation_scraping_blocked_total`. Le body upstream
  n'est jamais consulté.

**Métriques.** `mitigation_scraping_evaluated_total`,
`mitigation_scraping_matched_total`, `mitigation_scraping_logged_total`,
`mitigation_scraping_blocked_total`, `mitigation_scraping_errors_total`,
plus l'histogramme `mitigation_scraping_duration_seconds`.

**Fail-open.** Une mise à jour invalide via `PUT /v1/mitigations/scraping/:id`
est rejetée (4xx) et la règle précédemment chargée reste active ; le
compteur `mitigation_scraping_errors_total` est incrémenté. Le data
plane ne plante pas et continue de servir le trafic.

**Limites.**
- **Spoofing trivial** : changer le User-Agent et ajouter deux headers
  contourne la règle. Ne pas s'en servir comme défense unique.
- Ne couvre pas le scraping **comportemental** (vrai navigateur piloté,
  patterns de fetch humanoïdes). Les couches `http-flood-l7` (rate-limit
  par IP) et `slow-post` (anti-tarpit) restent les barrières de volume.
- Pas de regex (anti-ReDoS volontaire) : si une signature requiert plus
  qu'un substring, ouvrir une discussion ADR avant de relâcher cette
  contrainte.
- La liste par défaut peut générer des faux positifs sur des intégrations
  partenaires légitimes (`okhttp`, `Java/`). Ajuster par déploiement.

**Reproducer.** [`proxy/mitigations/scraping/scraping_test.go`](../proxy/mitigations/scraping/scraping_test.go)
— `TestReproducer_Scraping_*` montre un scraper qui atteint l'upstream
sans mitigation, puis se voit refuser en 403 (action=deny) ou passer
silencieusement journalisé (action=log).
Le scénario d'attaque scriptable
[`tests/attacks/scraping-aggressif/scenario.sh`](../tests/attacks/scraping-aggressif/scenario.sh)
et son équivalent `.ps1` exécutent ces tests Go (loopback only).

**Référence.** [OWASP Automated Threats — OAT-011 Scraping](https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-011_Scraping),
[RFC 9110 §10.1.5 — User-Agent](https://www.rfc-editor.org/rfc/rfc9110#section-10.1.5).

---

## credential-stuffing

**Vecteur.** OWASP Automated Threats **OAT-008** — l'attaquant rejoue
massivement des paires `login:password` issues de fuites publiques
contre les endpoints d'authentification d'une application. Le but n'est
pas la disponibilité du service mais la **prise de contrôle de comptes
utilisateurs** dont les credentials sont réutilisés. Pour le proxy
anti-DDoS, c'est un cas de **L7 abus** : burst de POST légitimes en
apparence (forme valide, headers normaux) vers `/login`, `/api/auth/...`.

> **AVERTISSEMENT — défense en surface.** Ce module rate-limit par IP
> sur les paths de login. Il bloque les attaquants centralisés (un
> serveur, quelques IPs). Contre un attaquant **distribué** (botnet,
> proxies résidentiels rotatifs, services type Bright Data), un seuil
> per-IP est trivialement contourné. La défense complète exige une
> couche **comportementale** dans l'application : CAPTCHA, MFA,
> détection d'anomalies sur le compte cible (essais multiples sur un
> même login depuis des IPs différentes), fingerprinting client. Le
> proxy ne peut pas voir « 10 000 IPs essaient 10 000 logins distincts
> à 1 essai chacun ».

**Ressource ciblée.** CPU (vérification de mot de passe, généralement
bcrypt/argon2 — coûteux par design), base utilisateurs (lookups,
verrouillages de compte), et au final **les comptes valides exfiltrés**
qui sont la vraie valeur pour l'attaquant.

**Signal de détection.** Taux de tentatives d'authentification par IP,
scopé aux chemins de login configurés (préfixes + méthodes). Token
bucket : capacité = `max_attempts_per_minute`, recharge linéaire
`max/60` par seconde. Premier hit = bucket plein (burst initial = N).

**Réaction.** Sur épuisement du bucket :
- `action: deny` (défaut) — HTTP `429 Too Many Requests` +
  `Retry-After: 60`, requête non transmise à l'upstream.
- `action: log` — la requête passe (mode observation), seul le compteur
  `mitigation_credential_stuffing_logged_total` s'incrémente.

Requêtes **hors scope** (path ne match aucun `login_paths`, ou méthode
non listée) traversent sans coût : le code n'incrémente même pas
`evaluated_total` (hot path allocation-free).

**Fail-open.** IP cliente absente ou non parsable → `Allow` +
`mitigation_credential_stuffing_errors_total++`. Aligné sur le défaut
projet (préférer laisser passer en cas de bug du mitigateur).
Cf. [`docs/adr/0003-fail-open-vs-fail-closed.md`](adr/0003-fail-open-vs-fail-closed.md).

**Métriques exposées.**
- `mitigation_credential_stuffing_evaluated_total` — requêtes dans le
  scope (path + méthode matchés), bucket consulté.
- `mitigation_credential_stuffing_matched_total` — sous-ensemble dans
  le scope (redondant avec `evaluated`, prévu pour évoluer si on ajoute
  des sous-règles).
- `mitigation_credential_stuffing_logged_total` — bucket épuisé,
  `action: log`.
- `mitigation_credential_stuffing_blocked_total` — bucket épuisé,
  `action: deny` (HTTP 429).
- `mitigation_credential_stuffing_errors_total` — fail-open (IP vide,
  config invalide à l'`Update`).
- `mitigation_credential_stuffing_duration_seconds` (histogramme) —
  latence de l'évaluation.

**Limites assumées.**
- **Botnet rotatif** : chaque IP n'envoie que peu de tentatives, sous
  le seuil. Aucune mitigation per-IP ne peut détecter ça — c'est le
  rôle de la couche applicative (anomalies par compte).
- **Proxies résidentiels** : IPs partagées avec du trafic légitime ;
  baisser le seuil produit des faux positifs sur du NAT carrier-grade
  (CGNAT) ou de gros NAT d'entreprise. À ajuster selon la base
  utilisateurs.
- **Compromission par phishing** : hors scope (l'attaquant a déjà le
  bon mot de passe, son essai unique passe).

**Reproducer.** [`proxy/mitigations/credstuff/credstuff_test.go`](../proxy/mitigations/credstuff/credstuff_test.go)
— `TestReproducer_CredStuff_*` montre 50 POST sur `/login` qui frappent
tous l'upstream sans mitigation, puis seulement 5 (le burst) avec
`action=deny` (45 réponses 429), puis 50 passent avec `action=log` (45
comptés sans bloquer).
Le scénario d'attaque scriptable
[`tests/attacks/credential-stuffing/scenario.sh`](../tests/attacks/credential-stuffing/scenario.sh)
et son équivalent `.ps1` exécutent ces tests Go (loopback only).

**Références.**
- [OWASP Automated Threats — OAT-008 Credential Stuffing](https://owasp.org/www-project-automated-threats-to-web-applications/assets/oats/EN/OAT-008_Credential_Stuffing).
- [NIST SP 800-63B §5.2.2 — Rate limiting](https://pages.nist.gov/800-63-3/sp800-63b.html#sec5).

---

## concurrency-saturation

**Statut.** Livré v1.2 (fail-open, désactivé par défaut — calibrer
`max_in_flight` pour l'upstream cible avant activation).

**Vecteur.** Toutes les mitigations en amont raisonnent par source
(per-IP) ou par signature : `slowloris` cape les connexions par IP,
`http-flood-l7` cape le RPS par IP, `credstuff` cape les tentatives
login par IP. Aucune ne fixe un plafond *global* sur le nombre de
requêtes simultanément en cours de traitement à travers le proxy.

Deux scénarios saturent malgré tout l'upstream :

- **Flash-crowd légitime** : un événement (mise en ligne d'un produit,
  trafic référencé) fait converger des milliers de clients distincts
  qui passent chacun sous les seuils per-IP. L'upstream s'écroule
  parce que sa capacité (workers, connexions DB, pool TCP) est finie.
- **Attaque distribuée multi-IP** (botnet résidentiel, proxies
  rotatifs) : chaque IP envoie peu de requêtes, sous tous les seuils.
  Le volume agrégé dépasse la capacité upstream.

Dans les deux cas, l'in-flight global croît jusqu'à ce que l'upstream
time-out, drop des connexions ou tombe ; le proxy continue d'envoyer
de nouvelles requêtes qui ne reviennent jamais, propageant la latence
dans tout l'écosystème (cascade failure).

**Ressource épuisée.** Capacité upstream : pool de connexions, workers,
file descriptors, mémoire des sessions in-flight. Côté proxy : nombre
de goroutines actives et de buffers `httputil.ReverseProxy`.

**Détection / mesure.** Sémaphore non bloquant implémenté par un
`chan struct{}` buffered de taille `max_in_flight`. Acquisition O(1)
via `select { case sem <- struct{}{}: ; default: }`. Aucun parsing,
aucune allocation par requête.

**Réaction.** Quand le sémaphore est saturé : HTTP
`503 Service Unavailable` + header `Retry-After: 1`. Le handler
upstream n'est pas appelé, la requête est rejetée immédiatement. Le
client reçoit un signal RFC 7231 §6.6.4 propre lui indiquant qu'il
peut réessayer.

L'attaquant n'a aucun moyen de distinguer ce 503 d'une indisponibilité
réelle, et un client légitime correctement implémenté backoffe. Le
load shedding s'auto-régule : dès qu'un handler termine, un nouveau
slot se libère et la requête suivante passe.

**Métriques exposées.**

- `mitigation_concurrency_cap_evaluated_total` — requêtes inspectées.
- `mitigation_concurrency_cap_blocked_total` — requêtes shed (503).
- `mitigation_concurrency_cap_errors_total` — erreurs internes.
- `mitigation_concurrency_cap_duration_seconds` — latence d'évaluation
  (sub-microseconde : un `select` non bloquant).

Alerter si `blocked_total / evaluated_total` dépasse durablement
10 % : signe que `max_in_flight` est sous-dimensionné ou que
l'upstream a un problème de débit. Alerter aussi si la dérivée monte
brutalement (vague d'attaque ou flash-crowd).

**Configuration.** [configs/base/concurrency.yaml](../configs/base/concurrency.yaml)
(défaut désactivé), schéma [configs/schemas/concurrency.schema.json](../configs/schemas/concurrency.schema.json)
(`minimum: 1`, `maximum: 1_000_000`). Hot-reload :
`PUT /v1/mitigations/concurrency-cap/concurrency-cap` côté control plane,
puis `POST /v1/reload` pour pousser. Le hot-swap remplace le canal
sous-jacent par `atomic.Pointer` ; les requêtes in-flight libèrent
leur slot sur l'ancien canal (pointeur capturé), sans interférer avec
le nouveau quota.

**Pourquoi fail-open par défaut.** Un cap cassé qui rejette tout est
strictement pire que pas de cap (DoS auto-infligé). Conforme à
AGENTS.md §3 : sur erreur interne de l'évaluation, la requête passe.

**Pourquoi désactivé par défaut.** `max_in_flight` doit être calibré
pour la capacité upstream du déploiement. Une valeur trop basse shed
du trafic légitime ; une valeur trop haute n'apporte aucune
protection. La règle livre `enabled: false` avec une `reason` :
l'opérateur doit choisir un seuil avant activation (cf.
`docs/runbooks/concurrency-cap.md` quand il sera livré).

**Limites assumées.**

- **Cap global, pas per-tenant** : un tenant glouton peut squatter le
  quota au détriment des autres. Un cap par hôte virtuel ou par route
  est une extension future ; le filet actuel reste un cap global.
- **Pas de priorisation** : 503 frappe le prochain entrant, qu'il
  soit un crawler trivial ou un utilisateur premium. Une queue à
  priorités est une amélioration future.
- **Pas de queueing** : on shed immédiatement, on ne fait pas
  attendre. C'est volontaire (un buffer in-memory aggraverait la
  latence en cas d'attaque) mais ça impose au client de retry.
- **Métriques en complément, pas en remplacement** : ce filet ne
  remplace pas le rate-limit per-IP, il l'augmente. Sans `http-flood-l7`
  en amont, une IP peut squatter le cap.

**Reproducer.** [`proxy/mitigations/concurrency/concurrency_test.go`](../proxy/mitigations/concurrency/concurrency_test.go)
— `TestReproducer_ConcurrencyCap_WithoutMitigation` montre 50 requêtes
concurrentes qui atteignent toutes le handler (peak in-flight ≥ N),
puis `TestReproducer_ConcurrencyCap_WithMitigation_Sheds` montre que
avec `max_in_flight=5`, le peak observé reste ≤ 5 et le surplus reçoit
un 503 + `Retry-After`. Scénario scriptable :
[`tests/attacks/concurrency-saturation/scenario.sh`](../tests/attacks/concurrency-saturation/scenario.sh)
et son équivalent `.ps1` (loopback only).

**Références.**
- [Netflix Tech Blog — Performance Under Load (concurrency limiting)](https://netflixtechblog.medium.com/performance-under-load-3e6fa9a60581).
- [RFC 7231 §6.6.4 — 503 Service Unavailable](https://www.rfc-editor.org/rfc/rfc7231#section-6.6.4).
- [RFC 7231 §7.1.3 — Retry-After](https://www.rfc-editor.org/rfc/rfc7231#section-7.1.3).
- [Marc Brooker — Load shedding for fun and profit](https://brooker.co.za/blog/2021/04/27/shuffle-sharding.html).

---

## request-hygiene

**Statut.** Livré v1.3 (mitigation #13).

**Vecteur.** Une requête HTTP non conforme RFC peut servir plusieurs
buts offensifs :

- **HTTP request smuggling (CL.TE / TE.CL)** : co-existence de
  `Content-Length` et `Transfer-Encoding`, ou duplication de
  `Content-Length`, ou `Transfer-Encoding` non `chunked`. Le front et
  le back désynchronisent leur parsing du corps, permettant à
  l'attaquant d'injecter une seconde requête « cachée » dans la
  socket persistante (cf. James Kettle, *HTTP Desync Attacks*,
  BlackHat USA 2019 ; PortSwigger Web Security Academy).
- **WAF / proxy bypass via méthodes exotiques** (TRACE, CONNECT,
  méthodes inventées) : certains middlewares ne couvrent que
  GET/POST. Un endpoint dérrière qui accepte `TRACE` ouvre la voie
  au Cross-Site Tracing (CVE-2003-1567 et famille).
- **URIs énormes** : amplification mémoire au parsing, log spam,
  vecteur ReDoS sur path matchers naïfs.
- **Host vide** : requête HTTP/1.1 invalide (RFC 7230 §5.4) parfois
  utilisée pour confondre routing / vhost selection.

**Détection.** En-tête de chaîne (avant tout autre filtre) on
inspecte uniquement les champs de la requête (pas le corps) :

- méthode dans la whitelist (`GET HEAD POST PUT PATCH DELETE OPTIONS`
  par défaut, configurable, case-sensitive upper-case) ;
- `len(RequestURI) <= max_uri_length` ;
- pas de coexistence `Content-Length` + `Transfer-Encoding` ;
- au plus un `Content-Length` ;
- `Transfer-Encoding` = `chunked` seul (rien d'autre, et pas de liste) ;
- `Host` non vide après trim.

**Réaction.** Sur violation : `400 Bad Request` body court, **sans
header explicatif** côté client (defense in depth — ne pas indiquer
le critère exact qui a déclenché). Le motif (`Reason`) est journalisé
et compté en interne.

**Métriques.** Quatre compteurs Prometheus standard :
`request_hygiene_evaluated_total`, `_blocked_total`, `_errors_total`,
`_duration_seconds` (histogramme).

**Configuration.** [`configs/base/request-hygiene.yaml`](../configs/base/request-hygiene.yaml),
schéma [`configs/schemas/request-hygiene.schema.json`](../configs/schemas/request-hygiene.schema.json).
Activable à chaud via
`PUT /v1/mitigations/request-hygiene/request-hygiene` côté control plane,
poussé au data plane par `POST /v1/reload`. Variables d'environnement :
`ANTIDDOS_REQUEST_HYGIENE_{ENABLED,ALLOWED_METHODS,MAX_URI_LENGTH,REJECT_TE_CL,REJECT_DUP_CL,REJECT_BAD_TE,REJECT_EMPTY_HOST,ON_ERROR}`.

**Limites.**

- **Mitigation ne fait PAS de normalisation** (pas de réécriture de
  framing). C'est un *gate* binaire. La normalisation complète anti-
  smuggling reste un travail ultérieur si un upstream légacy s'avère
  vulnérable malgré le front Go (qui lui-même applique un parsing
  strict via `net/http`).
- **WebDAV / méthodes custom** : si l'application a besoin de
  `PROPFIND`, `MKCOL`, etc., il faut élargir `allowed_methods` —
  CONNECT/TRACE restent à éviter sauf cas explicite.
- **Faux positifs** sur clients buggés qui dupliquent `Content-Length`
  à 0 : observable côté métriques avant activation prod.

**Reproducer.** [`proxy/mitigations/requesthygiene/requesthygiene_test.go`](../proxy/mitigations/requesthygiene/requesthygiene_test.go)
— `TestReproducer_RequestHygiene_WithoutMitigation` montre qu'une
méthode `FOOBAR` et une combinaison `Content-Length` + `Transfer-Encoding`
atteignent le handler upstream brut ; `TestReproducer_RequestHygiene_WithMitigation_Blocks`
montre que les cinq cas (FOOBAR, TRACE, URI 5 KiB, TE+CL, dup CL) sont
tous rejetés en 400 sans atteindre l'upstream. Scénario scriptable :
[`tests/attacks/request-hygiene/scenario.sh`](../tests/attacks/request-hygiene/scenario.sh)
et son équivalent `.ps1` (loopback only).

**Références.**
- [James Kettle — *HTTP Desync Attacks: Request Smuggling Reborn*, BlackHat USA 2019](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn).
- [PortSwigger Web Security Academy — HTTP request smuggling](https://portswigger.net/web-security/request-smuggling).
- [RFC 7230 §3.3.3 — Message Body Length](https://www.rfc-editor.org/rfc/rfc7230#section-3.3.3).
- [RFC 7230 §5.4 — Host header field](https://www.rfc-editor.org/rfc/rfc7230#section-5.4).
- [RFC 9110 §9 — Methods](https://www.rfc-editor.org/rfc/rfc9110#section-9).
- [CVE-2003-1567 — Cross-Site Tracing (XST)](https://nvd.nist.gov/vuln/detail/CVE-2003-1567).

---

## ja3-ja4-fingerprint

**Statut.** **Livré v1.4** (dormant tant que TLS n'est pas terminé côté
proxy). Bloque au handshake les ClientHello listés par hash JA3
(Salesforce 2017) ou par chaîne JA4 (FoxIO 2023).

**Vecteur.** Bots et outils d'attaque embarquent souvent une pile TLS
distincte d'un navigateur — `curl`, `python-requests`, `go-http-client`,
`Masscan`, scanners customs, frameworks d'amplification HTTP. Leur
ClientHello a une signature stable (ordre des cipher suites, extensions,
courbes, points) qui se condense en une empreinte courte. Une blocklist
de quelques dizaines d'empreintes bien curées coupe une part
significative du trafic automatisé hostile **avant** même qu'une requête
HTTP soit émise — économie d'une chaîne de mitigations L7.

**Détection.** `tls.Config.GetConfigForClient(*tls.ClientHelloInfo)` est
le hook standard de la stdlib Go : invoqué une fois par handshake, il
peut retourner une erreur pour abandonner la session avant `ServerHello`.
Le mitigateur calcule JA3 (filtrage GREASE par RFC 8701, MD5 hex
lowercase de `version,ciphers-,exts-,curves-,points-`) et JA4 (format
`tXXYnnmmALPN_<sha12>_<sha12>` — TCP/QUIC, version TLS la plus haute
proposée, SNI présent (`d`) ou absent (`i`), compteurs ciphers/exts
clampés, ALPN premier+dernier byte ou `00`, hash sha256[:12] des ciphers
hex triés, hash sha256[:12] des extensions triées hors SNI+ALPN puis
`_` puis sigalgs en ordre original). Les deux empreintes sont
**toujours** calculées (observabilité) ; le blocage n'intervient que si
`enabled=true` et que l'une est dans la blocklist.

**Réaction.** Handshake abandonné par retour d'`ErrBlocked` depuis
`GetConfigForClient` (la stdlib ferme alors la connexion proprement,
sans envoyer d'`Alert` exploitable comme oracle). Aucun middleware HTTP
n'est wrappé : la décision est strictement au niveau TLS — pas de
coût L7, pas de corrélation à faire entre connexion et requête.

**Métriques (Prometheus).**
- `mitigation_tls_fingerprint_evaluated_total` — nombre de
  ClientHello évalués (incrémenté uniquement si la mitigation est
  active).
- `mitigation_tls_fingerprint_blocked_total` — nombre de handshakes
  rejetés.
- `mitigation_tls_fingerprint_errors_total` — réservé pour erreurs
  internes (parsing impossible, etc.).
- `mitigation_tls_fingerprint_duration_seconds` — histogramme de la
  durée d'évaluation (calcul des deux hashes + lookup).

**Configuration.** [`configs/base/tls-fingerprint.yaml`](../configs/base/tls-fingerprint.yaml),
schéma [`configs/schemas/tls-fingerprint.schema.json`](../configs/schemas/tls-fingerprint.schema.json).
Reload à chaud : `PUT /_admin/v1/mitigations/tls-fingerprint` côté proxy,
`PUT /v1/mitigations/tls-fingerprint/tls-fingerprint` côté control plane,
`Limiter.Update(cfg)` côté Go — atomic.Pointer swap des blocklists, pas
de drop des sessions en cours.

**Mode par défaut.** `enabled=false`, `reason="Dormant tant que le proxy
ne termine pas TLS et qu'aucune blocklist curée n'est fournie."`.
`on_error=allow` (fail-open) : une erreur de calcul ne doit jamais
empêcher un client légitime de négocier.

**Limites.**
- **Dormant en mode h2c actuel** : `GetConfigForClient` n'est appelé
  que si le proxy termine TLS. Tant que le data plane est en clair,
  cette mitigation est configurable (via l'admin API) mais inactive
  côté décision.
- **JA3 obsolète depuis TLS 1.3 + ECH** : extensions chiffrées (ECH /
  encrypted ClientHello) cassent les hashes à terme. JA4 est plus
  robuste mais subit le même angle d'attaque.
- **Faux positifs** : utls (Go), curl-impersonate (curl rebuild avec
  fingerprint navigateur), Chrome custom builds, anciens iOS — peuvent
  émettre des empreintes identiques à du trafic légitime. Toute
  blocklist doit être **curée à la main**, jamais auto-générée sur
  trafic observé.
- **Contournable** par un attaquant qui rote son fingerprint (utls +
  randomisation, ja3-fly, etc.). Couche complémentaire — pas de défense
  unique.
- **Pas de regex / pas de wildcards** : un hash = un ClientHello
  canonique. La blocklist reste petite (limite 1024 entrées) et
  auditable.

**Reproducer.** [`proxy/mitigations/tlsfingerprint/tlsfingerprint_test.go`](../proxy/mitigations/tlsfingerprint/tlsfingerprint_test.go)
— `TestReproducer_TLSFingerprint_WithoutMitigation` montre qu'avec la
mitigation désactivée, un `helloChrome()` est évalué (hash calculé)
mais non bloqué ; `TestReproducer_TLSFingerprint_WithMitigation_Blocks`
montre qu'avec son JA3 dans la blocklist, `GetConfigForClient` retourne
`ErrBlocked` (handshake aborté). Scénario scriptable :
[`tests/attacks/ja3-ja4-fingerprint/scenario.sh`](../tests/attacks/ja3-ja4-fingerprint/scenario.sh)
et son équivalent `.ps1` (loopback only).

**Références.**
- [Salesforce — *Open Sourcing JA3 SSL/TLS Client Fingerprinting for Malware Detection* (2017)](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/).
- [FoxIO — *JA4+ TLS Client Fingerprinting* (2023)](https://github.com/FoxIO-LLC/ja4).
- [RFC 8701 — Applying Generate Random Extensions And Sustain Extensibility (GREASE)](https://www.rfc-editor.org/rfc/rfc8701).
- [RFC 8446 §4.1.2 — TLS 1.3 ClientHello](https://www.rfc-editor.org/rfc/rfc8446#section-4.1.2).

---

