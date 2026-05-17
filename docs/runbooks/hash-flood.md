# Runbook — hash-flood

**Famille** : `hash-flood` &nbsp;·&nbsp; **Couche** : HTTP middleware
&nbsp;·&nbsp; **Default action** : `allow` (fail-open) → 400
&nbsp;·&nbsp; **Config** : [`configs/base/hashflood.yaml`](../../configs/base/hashflood.yaml)

## Symptôme

- Alerte `HashFloodBlockedSurge`.
- CPU upstream qui monte sur le parsing query string (avant la mitigation).
- Pic de 400 dans les logs.

## Métriques clés

```promql
rate(mitigation_hash_flood_evaluated_total[1m])
rate(mitigation_hash_flood_blocked_total[1m])
mitigation_hash_flood_errors_total                      # doit rester à 0
```

## Diagnostic

1. **`evaluated` constant + `blocked` non nul** : attaque ciblée
   (URLs avec milliers de paramètres).
2. **Distribution IP** : si concentrée, fingerprinting client ; si
   distribuée, botnet.

## Actions immédiates

```bash
# Durcir
curl -X PUT $CTRL/mitigations/hash-flood -d '{
  "enabled": true,
  "max_query_params": 32,
  "on_error": "allow"
}'

# Détendre (API legit avec beaucoup de filtres)
curl -X PUT $CTRL/mitigations/hash-flood -d '{
  "enabled": true,
  "max_query_params": 256,
  "on_error": "allow"
}'
```

## Rollback

Snapshot précédent.

## Escalade

- Si l'attaque persiste malgré durcissement : envisager bloquer les
  IPs offensives via le control plane scraping/blocklist (à raccorder).
