# ADR 0003 — http-flood-l7 par défaut fail-closed

- **Date** : 2026-05-22
- **Statut** : Accepté
- **Décideurs** : équipe projet
- **Concerne** : `proxy/mitigations/httpflood/`, `configs/base/ratelimit.yaml`,
  `control/src/mitigations/ratelimit.ts`
- **Supersede** : —
- **Lié à** : [AGENTS.md §3](../../AGENTS.md), [docs/threat-model.md#http-flood-l7](../threat-model.md#http-flood-l7)

## Contexte

`AGENTS.md` fixe comme défaut **fail-open** pour le data plane :

> Le défaut pour le data plane est *fail-open* sur erreur interne
> (ne pas bloquer le trafic légitime sur bug du mitigateur), sauf
> décision contraire écrite dans une ADR.

La mitigation `slowloris` ([ADR implicite via §3](../../AGENTS.md)) suit ce
défaut : `on_error: allow`. Pour `http-flood-l7`, le contexte est
différent et justifie une exception, qui doit être écrite.

`http-flood-l7` applique un **token bucket par IP source**. La clé de
décision est l'IP du client extraite de `r.RemoteAddr`. Deux modes
d'erreur internes existent :

1. **`r.RemoteAddr` non parseable** (ex. format inattendu, IPv6 mal formé).
   Aucune décision possible : impossible d'attribuer la requête à un bucket.
2. **Hot-reload reçoit une config invalide.** Géré séparément : on
   conserve l'ancienne config (`Limiter.Update` est, lui, fail-open). Ce
   point n'est PAS l'objet de cette ADR.

Le mode `on_error` n'arbitre que le cas (1).

## Décision

Le défaut de la mitigation `http-flood-l7` est **fail-closed**
(`on_error: deny`).

Implications concrètes :

- En cas d'erreur de parsing IP, la requête est rejetée avec **HTTP 503**.
- L'opérateur peut explicitement basculer en `on_error: allow` via
  `configs/{env}/ratelimit.yaml`, mais doit le justifier dans `notes:`.
- Le control plane refuse `enabled: false` sans champ `reason`
  (cohérent : désactiver un rate-limit en production est une décision
  qui doit laisser une trace).

## Justification

1. **L'attaque cible précisément le mécanisme d'identification.** Un
   attaquant qui découvre que des `RemoteAddr` malformés bypassent le
   rate-limit obtient un contournement trivial. Fail-open ici crée
   exactement le trou que la mitigation est censée fermer.
2. **Le coût d'un faux-positif est borné et signalé.** Un client
   légitime dont l'IP est non parseable est extrêmement rare en
   pratique (le runtime Go normalise via `net.SplitHostPort` ; les
   échecs viennent quasi exclusivement de stacks réseau exotiques ou
   d'un L4 LB mal configuré). HTTP 503 est explicite côté client et
   incrémente `mitigation_http_flood_l7_errors_total`, déclenchant une
   alerte ops avant qu'un volume significatif soit touché.
3. **Slowloris ≠ http-flood-l7.** Slowloris décide au niveau `accept()`
   (compter des connexions ouvertes) — l'erreur interne probable est
   un bug du compteur, indépendant de l'identité de l'attaquant.
   `http-flood-l7` décide au niveau requête sur la base de l'IP source
   — l'erreur est directement liée à un input attaquant-contrôlé.
4. **Symétrie avec le control plane.** Les routes Fastify refusent déjà
   les inputs malformés (validation TypeBox + `additionalProperties:false`).
   Étendre la même posture « refus sur input invalide » au data plane
   pour cette famille est cohérent.

## Conséquences

- **Tests** : `proxy/mitigations/httpflood/httpflood_test.go` couvre
  explicitement `TestEvaluate_FailClosed_ReturnsDeny` et le pendant
  `FailOpen` (mode opt-in).
- **Configs prod** : `configs/prod/ratelimit.yaml` (à créer) **DOIT**
  garder `on_error: deny`. Tout override `allow` nécessite review et
  doit pointer une justification écrite (incident, mitigation
  temporaire, etc.).
- **Runbook** : un pic de `errors_total` indique soit un attaquant qui
  sonde la robustesse du parseur, soit un changement amont (nouveau
  L4 LB, IPv6 mal géré). Investigation prioritaire.
- **AGENTS.md** : pas de changement. Le défaut global reste fail-open,
  cette ADR est l'exception documentée prévue par le texte.

## Alternatives écartées

- **Fail-open avec compteur séparé.** Possible mais bypass-friendly
  comme expliqué §1.
- **Drop silencieux (`net/http.Hijacker` → close).** Casse les SLO
  HTTP observables côté client, complique le debugging.
- **Rate-limit global (sans clé IP) en fallback.** Ajoute une seconde
  couche de logique difficile à raisonner ; à reconsidérer si on
  ajoute un jour un mode « best-effort ».
