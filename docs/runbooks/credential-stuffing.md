# Runbook — credential-stuffing

**Famille** : `credential-stuffing` &nbsp;·&nbsp; **Couche** : HTTP middleware
&nbsp;·&nbsp; **Default action** : `deny` (fail-closed sur les routes login)
&nbsp;·&nbsp; **Config** : [`configs/base/credstuff.yaml`](../../configs/base/credstuff.yaml)
&nbsp;·&nbsp; **Refs** : OWASP OAT-008, NIST SP 800-63B §5.2.2.

## Symptôme

- Alerte `CredStuffBlockedSurge`.
- Pic de POST sur `/login`, `/api/auth/...` depuis une même IP.
- Hausse soudaine de comptes pivot vers password reset.

## Métriques clés

```promql
rate(mitigation_credential_stuffing_evaluated_total[1m])  # POST sur paths login
rate(mitigation_credential_stuffing_matched_total[1m])    # IP au-dessus du seuil
rate(mitigation_credential_stuffing_logged_total[1m])     # action=log
rate(mitigation_credential_stuffing_blocked_total[1m])    # action=deny
mitigation_credential_stuffing_errors_total               # doit rester à 0
```

`blocked / evaluated` durablement > 5 % = attaque active.

## Diagnostic

1. **Périmètre paths/methods** : la mitigation **n'évalue rien hors**
   `login_paths` × `methods`. Vérifier que la config couvre toutes les
   routes d'authentification (`/login`, `/api/auth/login`, `/signin`,
   `/api/v1/login`, OAuth callbacks, etc.).
2. **Distribution IP** : credential stuffing depuis botnet =
   distribution plate (chaque IP juste sous le seuil). Voir étape 4
   (couche comportementale) — pas encore en place.
3. **NAT / CGNAT** : un seuil trop bas frappe les utilisateurs
   derrière une même IP carrier-grade.

## Actions immédiates

```bash
# Durcir
curl -X PUT $CTRL/mitigations/credential-stuffing -d '{
  "enabled": true,
  "login_paths": ["/login","/api/auth/","/api/v1/login","/signin"],
  "methods": ["POST"],
  "max_attempts_per_minute": 5,
  "action": "deny"
}'

# Passer en observe pour confirmer la signature
curl -X PUT $CTRL/mitigations/credential-stuffing -d '{
  "enabled": true,
  "login_paths": ["/login","/api/auth/","/api/v1/login","/signin"],
  "methods": ["POST"],
  "max_attempts_per_minute": 20,
  "action": "log"
}'
```

Hot-reload : OK sans drop (cf. [docs/hardening.md](../hardening.md#3-contrat-hot-reload-no-drop)).

## Rollback

Snapshot précédent.

## Limites connues

- **Botnet distribué** : per-IP buckets ne détectent rien si l'attaquant
  reste sous le seuil par IP. Couche `behavioral` (cf. ci-dessous,
  [ADR 0004](../adr/0004-credstuff-behavioral.md)) couvre ce cas.
- **CGNAT** : risque de FP sur opérateurs mobiles. Préférer
  `max_attempts_per_minute >= 10` en mode `deny` quand on a peu de
  signal.

## behavioral

Couche **per-account** (ADR 0004) servie par le control plane Node ;
ingère des `auth-event` `{username_hash, success, source_ip, ts}` envoyés
par l'upstream, calcule des candidats IPs à blocklister sur fenêtre
10 min, et pousse un snapshot complet au data plane via
`PUT /_admin/v1/blocklist/credstuff`.

### Endpoints

| Méthode | Route                                              | Effet |
|---------|----------------------------------------------------|-------|
| POST    | `/v1/behavioral/credstuff/auth-event`              | Ingestion unitaire (`username_hash` SHA-256 sel + `success` + `source_ip`). |
| POST    | `/v1/behavioral/credstuff/auth-events`             | Idem, batch ≤ 100. |
| GET     | `/v1/behavioral/credstuff/state`                   | Inspection (totals, candidates, version). |
| DELETE  | `/v1/behavioral/credstuff/state`                   | Reset fenêtre (incrémente version). |
| POST    | `/v1/behavioral/credstuff/push`                    | Déclenche le push vers le proxy. |
| GET     | `/v1/behavioral/credstuff/push`                    | Dernier `PushResult`. |
| GET\|POST | `/v1/behavioral/credstuff/push/mode`             | Lit ou bascule `shadow`/`enforce`. |
| GET     | `/metrics`                                         | Compteurs Prometheus (control plane). |

### Métriques clés

- `behavioral_credstuff_candidates` — nb d'IPs flaggées (gauge).
- `behavioral_credstuff_push_total{status="ok|shadow|stale_version|error"}`.
- `behavioral_credstuff_push_last_pushed` — `1` si dernier push 2xx.
- `behavioral_credstuff_push_mode{mode="shadow|enforce"}` — 1 sur le
  mode actif.
- `mitigation_credential_stuffing_blocklist_hits_total` (côté proxy) —
  effet réel sur le trafic.

### Procédures

1. **Push manuel** :
   ```bash
   curl -fsS -X POST http://127.0.0.1:9090/v1/behavioral/credstuff/push
   ```
   Vérifier `pushed:true` et `status:"ok"` (ou `"shadow"`).
2. **Bascule shadow → enforce** (après ≥ 2 semaines d'observation,
   cf. [ADR 0004 rollout](../adr/0004-credstuff-behavioral.md#rollout)) :
   ```bash
   curl -fsS -X POST -H 'content-type: application/json' \
     http://127.0.0.1:9090/v1/behavioral/credstuff/push/mode \
     -d '{"mode":"enforce"}'
   ```
3. **Rollback enforce → shadow** (faux positifs détectés) :
   ```bash
   curl -fsS -X POST -H 'content-type: application/json' \
     http://127.0.0.1:9090/v1/behavioral/credstuff/push/mode \
     -d '{"mode":"shadow"}'
   ```
4. **Vider la blocklist data plane** (panic button) :
   ```bash
   curl -fsS -X PUT -H 'content-type: application/json' \
     http://127.0.0.1:8081/_admin/v1/blocklist/credstuff \
     -d '{"version": <prev+1>, "entries": []}'
   ```

### Alertes Prometheus

Cf. [docs/observability/prometheus-rules.yaml](../observability/prometheus-rules.yaml) :

- `BehavioralCredStuffPushErrors` — push KO sur 10 min → page.
- `BehavioralCredStuffPushStale` — aucun push depuis > 10 min → warn.
- `BehavioralCredStuffCandidatesSurge` — > 1000 candidats → warn.
- `BehavioralCredStuffShadowOnly` — shadow + candidats > 1 h → info.

## Escalade

- `errors_total > 0` : bug → escalade data plane immédiate (cette
  mitigation est fail-closed sur ses routes).
- Hausse de password resets corrélée : ouvrir incident sécurité +
  notifier utilisateurs compromis.
