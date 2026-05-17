# ADR 0004 — Couche comportementale credential-stuffing (per-account + push blocklist)

- **Date** : 2026-05-16 (révisé : 2026-05-17, statut → Implémenté)
- **Statut** : Implémenté (phases 1–5 livrées, mode `shadow` par défaut côté pusher)
- **Décideurs** : équipe projet
- **Concerne** : `proxy/mitigations/credstuff/`,
  `control/src/mitigations/credstuff.ts`, futur
  `control/src/behavioral/`, futur `proxy/internal/blocklist/`
- **Supersede** : —
- **Lié à** : [docs/threat-model.md#credential-stuffing](../threat-model.md#credential-stuffing),
  [docs/runbooks/credential-stuffing.md](../runbooks/credential-stuffing.md),
  [proxy/mitigations/credstuff/credstuff.go](../../proxy/mitigations/credstuff/credstuff.go)

## Contexte

La v1.1 de `credential-stuffing` applique un **token bucket per-IP** sur les
routes de login. Cf. limite documentée dans le runbook :

> Botnet distribué : per-IP buckets ne détectent rien si l'attaquant
> reste sous le seuil par IP. […]

Les campagnes credential-stuffing modernes utilisent typiquement
10 k–100 k IPs résidentielles (residential proxies, botnets IoT). Chaque
IP fait 1–3 requêtes login : sous tous les seuils per-IP raisonnables.
La signature qui reste détectable est **per-account** :

- Un même `username` est ciblé depuis N IPs en quelques minutes.
- Le taux d'échec d'auth pour un même `username` explose.

Cette signature n'est pas observable depuis le data plane stateless
(qui ne sait pas ce qu'est un « username » sans parser un body POST
arbitraire, et ne sait pas si l'auth a réussi sans signal de l'upstream).

## Forces en présence

1. **Hot path data plane** : doit rester O(1) et sans état partagé
   coûteux. Pas de DB, pas d'appel réseau synchrone, pas de parse de
   body JSON.
2. **Confidentialité** : les `username` (souvent = email) sont des PII.
   Ne pas les stocker en clair côté proxy. Hash + sel obligatoire si
   stockés > 24 h.
3. **Cross-platform** : pas de dépendance Linux-only, pas de cgo.
   Stockage par défaut en mémoire ; backend externe optionnel.
4. **Fail-open** : un bug dans la couche comportementale ne doit pas
   couper les logins legit. La couche v1.1 per-IP reste le filet de
   sécurité minimal et **ne dépend pas** de la couche comportementale.
5. **Hot-reload** : la blocklist comportementale doit pouvoir s'activer
   et se détendre sans drop de connexion.

## Décision

On introduit une **architecture en deux couches** :

```
┌──────────────────────────┐
│  Data plane (Go)         │       per-IP bucket (v1.1, existant)
│  proxy/mitigations/      │       + lookup blocklist (nouveau)
│    credstuff/            │
│    blocklist/            │ ←── push HTTP+gRPC depuis control plane
└──────────────────────────┘
            ▲
            │ push diff (add/remove entries)
            │
┌──────────────────────────┐
│  Control plane (TS)      │       agrège signaux per-account
│  control/src/behavioral/ │       (login attempts, failure rate, IP fan-out)
│    credstuff/            │       décide qui blocklister, pousse la liste
└──────────────────────────┘
            ▲
            │ async ingest (callback POST /auth/result depuis upstream)
            │
┌──────────────────────────┐
│  Upstream applicatif     │       envoie {username_hash, success, source_ip}
└──────────────────────────┘       après chaque tentative auth
```

### Principe

- L'**upstream applicatif** (au-delà du reverse proxy) est seul à savoir
  parser un POST `/login` et à connaître le résultat. Il pousse les
  résultats au control plane via un endpoint dédié.
- Le **control plane** garde l'état per-account (compteurs, fenêtres
  glissantes), applique une heuristique, et pousse une **blocklist
  IP** au data plane.
- Le **data plane** consulte cette blocklist en O(1) au début de la
  chaîne `credstuff.Middleware`, avant le bucket per-IP. Si l'IP est
  blocklistée, deny direct.

### Pourquoi pas tout faire dans le data plane

- Parser un POST `/login` en JSON/form arbitraire = surface de bug
  (regex, JSON parsing, content-type weirdness) sur le chemin chaud.
- État per-account = état de cardinalité utilisateur (millions
  potentiellement) — pas la place propre pour ça dans un proxy.
- L'upstream a déjà la logique d'auth ; lui demander 1 callback
  asynchrone est trivial et localise le parsing.

### Pourquoi pas tout faire dans le control plane

- Le control plane n'est pas dans le chemin chaud. Il ne peut bloquer
  qu'en publiant une décision au data plane.

## Conception détaillée

### Ingestion (upstream → control plane)

Nouvel endpoint Fastify :

```
POST /v1/behavioral/credstuff/auth-event
Authorization: Bearer <token upstream>
Content-Type: application/json

{
  "username_hash": "<sha256(lowercase(username) + salt)>",
  "success": false,
  "source_ip": "203.0.113.45",
  "ts": "2026-05-16T12:34:56Z",
  "user_agent": "Mozilla/5.0 …"   // optionnel, indicatif
}
```

- **`username_hash`** : SHA-256 avec sel rotatif. **Pas** le username en
  clair. Sel partagé via secret manager (hors VCS).
- **Auth** : Bearer token long-vivant configuré côté upstream (1 token
  par environnement). Validation par comparaison constante.
- **Rate limit** : l'endpoint d'ingestion lui-même est rate-limité
  (Fastify plugin `@fastify/rate-limit`) pour éviter qu'un upstream
  compromis ne DDoS le control plane.

### Heuristique per-account

Sur fenêtre glissante de 10 minutes :

| Signal                                | Seuil défaut | Action proposée                     |
|---------------------------------------|--------------|-------------------------------------|
| `failed_logins(username_hash)`        | > 20         | Blocklist toutes les IPs sources    |
| `distinct_ips(username_hash, failed)` | > 5          | Blocklist toutes les IPs sources    |
| `failed_logins(source_ip)`            | > 50         | Blocklist cette IP (cross-account)  |
| Succès soudain après N échecs         | N ≥ 5        | Logger + paginer (compromission ?)  |

Tous les seuils sont dans `configs/base/credstuff-behavioral.yaml`,
hot-reloadable, schéma JSON dans `configs/schemas/`.

### Stockage état per-account

Phase 1 — in-memory uniquement, single-node :

- `Map<username_hash, RingBuffer<event>>` avec TTL 10 min.
- Cardinalité bornée par éviction LRU à 1 M entrées (~80 MiB).
- Crash = perte d'état = retour à la couche per-IP seule. **Acceptable.**

Phase 2 (hors scope ADR) — Redis externe pour multi-node. Schéma compatible.

### Push blocklist (control → data plane)

Endpoint sur le data plane :

```
PUT /admin/blocklist/credstuff
Authorization: Bearer <token admin>
Content-Type: application/json

{
  "version": 42,
  "entries": [
    { "ip": "203.0.113.45", "expires_at": "2026-05-16T13:00:00Z", "reason": "per-account-fan-out" },
    { "ip": "198.51.100.7",  "expires_at": "2026-05-16T13:00:00Z", "reason": "per-ip-failed-rate" }
  ]
}
```

- **Idempotent** : `version` strictement croissant. Un PUT avec
  `version` ≤ courant est ignoré (cohérence avec lectures
  concurrentes).
- **Diff-friendly** : à terme on pourra basculer sur un PATCH
  `add/remove` ; PUT full snapshot suffit pour la phase 1
  (entrées < 100 k → quelques MB JSON, push toutes les 30 s).
- **Bounded** : refuser un PUT avec `entries.length > 100_000`
  (sanity cap). Documenté dans le schéma.
- **TTL côté data plane** : chaque entrée a `expires_at`. Le data
  plane purge à la lecture (lazy) + sweep périodique (toutes les
  60 s) pour borner la mémoire si pas de PUT.

### Stockage data plane

```go
package blocklist

type Entry struct {
    IP        netip.Addr
    ExpiresAt time.Time
    Reason    string
}

type Set struct {
    cur atomic.Pointer[snapshot]
}

type snapshot struct {
    version int64
    byIP    map[netip.Addr]Entry
}

// Lookup : O(1), allocation-free, lock-free.
func (s *Set) Lookup(now time.Time, ip netip.Addr) (Entry, bool) { … }

// Replace : remplace atomiquement le snapshot complet.
func (s *Set) Replace(version int64, entries []Entry) error { … }
```

- `netip.Addr` (pas `string`) : zéro alloc, comparable.
- `atomic.Pointer[snapshot]` : même pattern hot-reload que les autres
  mitigations.
- Métriques : `blocklist_credstuff_size`, `blocklist_credstuff_lookups_total`,
  `blocklist_credstuff_hits_total`, `blocklist_credstuff_version`.

### Intégration dans `credstuff.Middleware`

```
Middleware(next) ServeHTTP(w, r):
  if !cfg.Enabled || !matchPath(r) || !matchMethod(r):
      next.ServeHTTP(w, r); return

  ip := parseIP(r.RemoteAddr)
  // NOUVEAU : check blocklist d'abord (O(1), pas d'alloc)
  if entry, ok := blocklist.Lookup(now(), ip); ok:
      metrics.blocklist_hit.Inc()
      deny(w, "blocklisted: " + entry.Reason)
      return

  // EXISTANT : per-IP bucket
  if !bucket.Allow(ip): deny(...); return
  next.ServeHTTP(w, r)
```

La blocklist agit **avant** le bucket : elle court-circuite et n'utilise
pas de capacité du bucket per-IP.

### Fail-open

- **Ingestion KO** : upstream ne pousse plus → control plane n'a plus de
  signal → blocklist se vide par TTL → on retombe sur per-IP. Pas de
  faux positif.
- **Push KO** : data plane garde l'ancien snapshot. Métrique
  `blocklist_credstuff_version` stagne → alerte
  `BlocklistStaleness > 5 min`.
- **Heuristique trop large** : impact = trop d'IPs blocklistées →
  observable via `blocklist_credstuff_size` + ratio
  `blocklist_hits / requests` → action runbook : pousser un PUT vide
  pour reset complet.

### Rollout

État réel après livraison (2026-05-17) :

| Phase | Livrable                                                                                  | Statut |
|-------|-------------------------------------------------------------------------------------------|--------|
| 0     | Cette ADR (décision écrite).                                                              | ✅      |
| 1     | `proxy/internal/blocklist/` (Set + admin PUT/GET + tests + bench).                        | ✅      |
| 2     | Câblage dans `credstuff.Middleware` derrière feature flag `blocklist_enabled`.            | ✅      |
| 3     | `control/src/behavioral/credstuff.ts` (store in-memory + heuristiques + ingestion auth).  | ✅      |
| 4     | Pusher control → proxy + endpoint `/v1/behavioral/credstuff/push` + mode `shadow`/`enforce`. | ✅      |
| 5     | Métriques bout en bout (`/metrics` control plane) + alertes Prometheus + runbook + ADR statut. | ✅      |

Reste à arbitrer hors ADR : bascule par défaut en `enforce` après
2 semaines d'observation `shadow` en staging (mesure faux positifs via
`behavioral_credstuff_push_total{status="shadow"}` × `candidates`).

## Conséquences

### Positives

- Détecte les campagnes botnet distribuées invisibles per-IP.
- Découplage clair : le data plane ne parse jamais de body sensible.
- Hot path inchangé sauf 1 lookup `map[netip.Addr]Entry` O(1).
- Couche v1.1 reste fonctionnelle et fail-safe en cas de panne control plane.

### Négatives / risques

- **Dépendance opérationnelle** sur l'upstream pour les callbacks
  d'auth. Si l'upstream ne les envoie pas, on est aveugle.
- **Confidentialité** : push de blocklist contient des IPs. À traiter
  comme tel (TLS mutual auth recommandé entre control et data plane).
- **Cardinalité** : la `Map<username_hash, …>` du control plane peut
  exploser sous attaque ciblant des username inexistants. Mitigations :
  cap LRU + alerte sur taille.
- **Surface d'attaque ingestion** : nouvel endpoint POST authentifié.
  Risque d'injection si l'auth fuit. Mitigations : token long, rate-limit,
  audit log.

### Neutres

- Aucun nouveau langage. Aucune nouvelle dépendance réseau dans le
  data plane (le control plane initie le PUT vers le data plane sur
  socket admin déjà existante).

## Alternatives écartées

1. **Tout faire dans le data plane** : parser POST login + tracker
   per-account. Refusé : surface d'attaque + état lourd sur hot path
   + couplage fort aux contrats applicatifs.
2. **Externaliser à un service tiers (Cloudflare/Akamai)** : sort du
   scope du projet (self-hosted, parité Linux/Windows).
3. **Inspection passive de la réponse upstream (parse 200 vs 401)** :
   coûteux (le proxy doit buffer la réponse), faux positifs fréquents
   (apps qui retournent 200 même sur échec), couple le data plane au
   contrat de l'upstream.
4. **Challenge JS / captcha** : complémentaire mais hors scope d'un
   proxy ; nécessite intégration applicative.
