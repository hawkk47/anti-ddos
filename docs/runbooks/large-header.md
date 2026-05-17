# Runbook — large-header

**Famille** : `large-header` &nbsp;·&nbsp; **Couche** : HTTP middleware
&nbsp;·&nbsp; **Default action** : `allow` (fail-open) → 431
&nbsp;·&nbsp; **Config** : [`configs/base/largeheader.yaml`](../../configs/base/largeheader.yaml)

## Symptôme

- Alerte `LargeHeaderBlockedSurge`.
- Pic de 431 dans les logs proxy.
- Latence p99 stable (le rejet est en amont).

## Métriques clés

```promql
rate(mitigation_large_header_evaluated_total[1m])
rate(mitigation_large_header_blocked_total[1m])
mitigation_large_header_errors_total                    # doit rester à 0
```

## Diagnostic

1. **Endpoints touchés** : si majoritairement des APIs avec Bearer
   tokens longs, augmenter `max_value_bytes`.
2. **User-Agent suspects** : tools qui injectent des centaines de
   headers (recon, fingerprinting).

## Actions immédiates

```bash
# Durcir
curl -X PUT $CTRL/mitigations/large-header -d '{
  "enabled": true,
  "max_header_count": 50,
  "max_value_bytes": 4096,
  "on_error": "allow"
}'

# Détendre (APIs avec gros JWT)
curl -X PUT $CTRL/mitigations/large-header -d '{
  "enabled": true,
  "max_header_count": 200,
  "max_value_bytes": 32768,
  "on_error": "allow"
}'
```

## Rollback

Snapshot précédent.

## Escalade

- Faux positifs systématiques sur un client connu → demander réduction
  des headers côté applicatif avant d'augmenter le quota.
