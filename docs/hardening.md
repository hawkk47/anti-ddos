# Hardening — chaîne de mitigations

Ce document capture trois invariants transverses du data plane :

1. **L'ordre de la chaîne handler** et son rationale.
2. **Le coût mesuré** de la chaîne (benchmarks).
3. **Le contrat hot-reload « no-drop »** vérifié sous charge.

Tout changement structurel sur ces trois axes doit être reflété ici.

## 1. Ordre de la chaîne handler

Ordre exact (outer → inner) appliqué par
[proxy/internal/server/server.go](../proxy/internal/server/server.go) et
reproduit par le banc
[proxy/internal/server/chain_bench_test.go](../proxy/internal/server/chain_bench_test.go) :

```
scraping → cache-poison → hash-flood → range-amp → large-header
        → http-flood-l7 → cred-stuff → slow-post → reverse-proxy
```

Trois mitigations ne participent **pas** à la chaîne handler :

| Mitigation     | Niveau               | Raison                                                                 |
|----------------|----------------------|------------------------------------------------------------------------|
| `tlsreneg`     | listener TLS         | Décision prise sur `tls.Conn` avant tout handler HTTP.                 |
| `slowloris`    | connexion TCP/HTTP   | Lectures de header partielles : intercepté côté `net.Conn`.            |
| `http2-reset`  | serveur HTTP/2       | Hook sur les `RST_STREAM` ; pas observable depuis un handler.          |

### Rationale de l'ordre

Le principe directeur : **rejeter le plus tôt possible les requêtes les
moins coûteuses à filtrer**, et faire payer les filtres coûteux le plus
tard possible sur des requêtes déjà pré-validées.

| Position | Mitigation       | Coût / signal                                             |
|----------|------------------|-----------------------------------------------------------|
| 1        | `scraping`       | Inspection UA + 1-2 headers. O(1), pas d'état.            |
| 2        | `cache-poison`   | Comparaison set de headers connus. O(1).                  |
| 3        | `hash-flood`     | `len(r.URL.Query())` borné. O(1).                         |
| 4        | `range-amp`      | Parse `Range:` header. O(1).                              |
| 5        | `large-header`   | `len(r.Header)` + max value bytes. O(headers).            |
| 6        | `http-flood-l7`  | Token bucket per-IP (`sync.Map` lookup + atomic).         |
| 7        | `cred-stuff`     | Match path + method + bucket per-IP. **Stateful, scoped.**|
| 8        | `slow-post`      | Wrappe `r.Body` ; coût étalé sur la lecture.              |

Mettre `slow-post` en dernier est essentiel : il **remplace
`r.Body`**, donc si une mitigation amont rejette, on n'a pas payé le
wrapping. Mettre `http-flood-l7` avant `cred-stuff` garantit que les
attaques en volume brut sont coupées avant la logique « login » plus
chère.

## 2. Coût mesuré

Benchmark : `go test -bench=^Benchmark -benchmem -run=^$
./internal/server/...`

Référence (AMD Ryzen 7 5800X, Windows, `go1.25`, `CGO_ENABLED=0`) :

| Banc                                     | ns/op | B/op | allocs/op |
|------------------------------------------|------:|-----:|----------:|
| `Chain_AllDisabled`                      |  361  |  208 |   4       |
| `Chain_AllEnabledPermissive`             |  592  |  232 |   5       |
| `Chain_ParallelEnabledPermissive` (16c)  |  317  |  714 |   9       |

**Lecture** :

- Coût d'activer **les 8 mitigations** sur un GET / qui ne match rien :
  **+231 ns/op, +1 alloc/op**. Le budget de filtrage tient en un seul
  cache miss L2.
- Le banc parallèle (16 cœurs) descend à 317 ns/op en agrégé : aucune
  contention globale détectée (pas de lock partagé, `sync.Map` et
  `atomic.Pointer` font leur travail).
- Allocs constants entre disabled et enabled : aucune mitigation ne
  fait d'alloc gratuite par requête.

**Régression budget** : si une PR fait dépasser
`Chain_AllEnabledPermissive` au-delà de **+25 %** vs cette baseline,
elle est à justifier dans le commit + ADR si elle introduit un nouvel
état partagé.

## 3. Contrat hot-reload no-drop

Couvert par
[`TestHotReload_UnderLoad`](../proxy/internal/server/chain_bench_test.go) :

- 32 workers HTTP en boucle pendant ~800 ms.
- En parallèle, un reloader bascule les 9 limiters entre deux configs
  valides toutes les 5 ms (≈160 reloads).
- Invariants vérifiés :
  - `ok > 0` (le serveur sert effectivement du trafic).
  - `bad == 0` (aucune 4xx/5xx déclenchée par le swap de config).
  - `failures == 0` (aucun reset TCP, aucun timeout).
  - Métriques `errors` à 0 sur `credstuff` et `scraping` (les deux
    seuls limiters qui exposent un compteur d'erreurs interne).

Ce que ça prouve : `atomic.Pointer[Config]` + path fail-open documenté
suffisent pour swapper la config **sans drop de requête en cours**, y
compris sur la transition (la requête courante voit toujours soit
l'ancienne soit la nouvelle config, jamais un état intermédiaire).

Toute nouvelle mitigation doit :

1. Stocker sa config dans un `atomic.Pointer`.
2. Exposer `Update(cfg) error` qui valide puis swap.
3. Avoir au moins un test sous le pattern de
   `TestHotReload_UnderLoad` (suffit de l'ajouter au bundle ; le test
   le reloadera automatiquement).
