# Runbook — slowloris

**Famille** : `slowloris` &nbsp;·&nbsp; **Couche** : TCP/HTTP (lecture headers)
&nbsp;·&nbsp; **Default action** : `allow` (fail-open)
&nbsp;·&nbsp; **Config** : [`configs/base/slowloris.yaml`](../../configs/base/slowloris.yaml)

## Symptôme

- Alerte `SlowlorisBlockedSurge`.
- Connexions ESTABLISHED qui s'empilent côté proxy sans jamais devenir
  des requêtes complètes.

## Métriques clés

```promql
rate(mitigation_slowloris_evaluated_total[1m])
rate(mitigation_slowloris_blocked_total[1m])
mitigation_slowloris_errors_total                       # doit rester à 0
```

`blocked / evaluated` proche de 1 = attaque ciblée. Faible mais non
nul = robots web mal codés ou réseau saturé.

## Diagnostic

1. **Profil réseau** : si la cible a beaucoup de clients sur réseaux
   à RTT élevé (satellite, mobile lointain), `header_timeout` peut
   être trop strict.
2. **Distribution IP** : Slowloris est typiquement distribué (botnet) ;
   peu d'IPs avec >100 connexions ouvertes = attaque.

## Actions immédiates

```bash
# Durcir
curl -X PUT $CTRL/mitigations/slowloris -d '{
  "enabled": true,
  "header_timeout": "3s",
  "max_inflight_per_ip": 10
}'

# Détendre
curl -X PUT $CTRL/mitigations/slowloris -d '{
  "enabled": true,
  "header_timeout": "15s",
  "max_inflight_per_ip": 100
}'
```

## Rollback

Snapshot précédent depuis `configs/base/slowloris.yaml`.

## Escalade

- Attaque > 50 k connexions concurrentes : envisager rate-limit
  connexions au niveau réseau (firewall amont).
- Surveillance OS : `netstat -an | findstr ESTABLISHED` (Windows) /
  `ss -s` (Linux).
