# Runbook — slow-post

**Famille** : `slow-post` &nbsp;·&nbsp; **Couche** : HTTP body
&nbsp;·&nbsp; **Default action** : `allow` (fail-open)
&nbsp;·&nbsp; **Config** : [`configs/base/slowpost.yaml`](../../configs/base/slowpost.yaml)

## Symptôme

- Alerte `SlowPostBlockedSurge` : pic de connexions terminées prématurément.
- Goodput POST upstream qui s'effondre (clients bloquent les workers).

## Métriques clés

```promql
rate(mitigation_slow_post_evaluated_total[1m])
rate(mitigation_slow_post_blocked_total[1m])
mitigation_slow_post_errors_total                       # doit rester à 0
```

## Diagnostic

1. **Distribution des Content-Length** : si beaucoup de très gros corps
   à très bas débit, attaque probable.
2. **Endpoints touchés** : un upload légitime lent (mobile sur edge
   3G) peut tomber dans le piège.
3. **Cause technique** : `min_bytes_per_second` trop élevé pour le profil
   client réel.

## Actions immédiates

```bash
# Durcir
curl -X PUT $CTRL/mitigations/slow-post -d '{
  "enabled": true,
  "max_body_bytes": 8388608,
  "min_bytes_per_second": 1024,
  "grace_period": "5s",
  "on_error": "allow"
}'

# Détendre (mobile fragile)
curl -X PUT $CTRL/mitigations/slow-post -d '{
  "enabled": true,
  "max_body_bytes": 33554432,
  "min_bytes_per_second": 64,
  "grace_period": "30s",
  "on_error": "allow"
}'
```

## Rollback

Snapshot de `configs/base/slowpost.yaml`.

## Escalade

- Faux positifs récurrents sur mobile : envisager un endpoint-specific
  override (à implémenter — n'existe pas encore).
- `errors_total > 0` : fail-open silencieux ; data plane à inspecter.
