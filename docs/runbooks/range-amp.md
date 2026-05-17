# Runbook — range-amp

**Famille** : `range-amp` &nbsp;·&nbsp; **Couche** : HTTP middleware
&nbsp;·&nbsp; **Default action** : `allow` (fail-open) → 416
&nbsp;·&nbsp; **Config** : [`configs/base/rangeamp.yaml`](../../configs/base/rangeamp.yaml)

## Symptôme

- Alerte `RangeAmpBlockedSurge`.
- Bande passante upstream qui décolle sans hausse de QPS.
- Pic de 416 dans les logs.

## Métriques clés

```promql
rate(mitigation_range_amp_evaluated_total[1m])
rate(mitigation_range_amp_blocked_total[1m])
mitigation_range_amp_errors_total                       # doit rester à 0
```

## Diagnostic

1. **Endpoints touchés** : range-amp cible typiquement les gros fichiers
   (vidéo, archives, PDF). Vérifier que la mitigation ne casse pas la
   lecture vidéo (clients HTTP/2 streaming font 10-30 ranges).
2. **Distribution IP** : peu d'IPs avec très haut taux de range
   demandées = signature attaque.

## Actions immédiates

```bash
# Durcir
curl -X PUT $CTRL/mitigations/range-amp -d '{
  "enabled": true,
  "max_ranges": 4,
  "on_error": "allow"
}'

# Détendre (streaming vidéo legit)
curl -X PUT $CTRL/mitigations/range-amp -d '{
  "enabled": true,
  "max_ranges": 32,
  "on_error": "allow"
}'
```

## Rollback

Snapshot précédent.

## Escalade

- Faux positifs vidéo : envisager des seuils par endpoint (non
  implémenté à date).
