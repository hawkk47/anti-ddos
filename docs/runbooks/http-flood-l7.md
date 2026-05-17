# Runbook — http-flood-l7

**Famille** : `http-flood-l7` &nbsp;·&nbsp; **Couche** : HTTP middleware
&nbsp;·&nbsp; **Default action** : `deny` (fail-closed)
&nbsp;·&nbsp; **Config** : [`configs/base/httpflood.yaml`](../../configs/base/httpflood.yaml)

## Symptôme

- Alerte `HTTPFloodBlockedSurge` : `rate(blocked_total[5m])` dépasse un seuil.
- Pics de 429 côté upstream.
- Latence p99 contrôlée mais erreurs côté client legit (faux positifs).

## Métriques clés

```promql
rate(mitigation_http_flood_l7_evaluated_total[1m])
rate(mitigation_http_flood_l7_blocked_total[1m])
mitigation_http_flood_l7_errors_total                 # doit rester à 0
histogram_quantile(0.99, mitigation_http_flood_l7_duration_seconds_bucket)
```

Ratio `blocked / evaluated` > 5 % en continu = soit attaque réelle,
soit seuils trop bas.

## Diagnostic

1. **Attaque distribuée ou concentrée ?** Regarder la distribution des
   IPs sources dans les logs upstream (l'accès au `X-Forwarded-For`
   est préservé).
2. **Pic vs. plateau ?** Pic = burst client legit / crawler. Plateau =
   abus.
3. **Faux positifs ?** Vérifier les Ranges les plus impactées et les
   User-Agents associés. Si CDN/crawler connu, whitelisting amont
   plutôt que durcir le bucket.

## Actions immédiates

Via control plane :

```bash
# Durcir
curl -X PUT $CTRL/mitigations/http-flood-l7 -d '{
  "enabled": true,
  "requests_per_second": 5,
  "burst": 10,
  "on_error": "deny"
}'

# Détendre (faux positifs avérés)
curl -X PUT $CTRL/mitigations/http-flood-l7 -d '{
  "enabled": true,
  "requests_per_second": 50,
  "burst": 200,
  "on_error": "allow"
}'
```

Hot-reload : pas de drop de connexions en cours (cf.
[docs/hardening.md](../hardening.md#3-contrat-hot-reload-no-drop)).

## Rollback

Restorer la version précédente depuis `configs/base/httpflood.yaml`
(garder un snapshot avant chaque PUT en prod).

## Escalade

- `errors_total > 0` : bug dans la mitigation → escalade data plane
  immédiate (fail-closed actif, du trafic legit est coupé).
- Attaque > 10 k req/s par IP unique : envisager blocklist amont (réseau).
