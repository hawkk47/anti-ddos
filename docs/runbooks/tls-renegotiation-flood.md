# Runbook — tls-renegotiation-flood

**Famille** : `tls-renegotiation-flood` &nbsp;·&nbsp; **Couche** : listener TLS
&nbsp;·&nbsp; **Default action** : `allow` (fail-open) — fermeture connexion
&nbsp;·&nbsp; **Config** : [`configs/base/tlsreneg.yaml`](../../configs/base/tlsreneg.yaml)

## Symptôme

- Alerte `TLSRenegFloodBlockedSurge`.
- CPU TLS (handshake) qui monte sans hausse de QPS HTTP.
- Connexions TLS fermées tôt après quelques renegs.

## Métriques clés

```promql
rate(mitigation_tls_renegotiation_flood_evaluated_total[1m])
rate(mitigation_tls_renegotiation_flood_blocked_total[1m])
mitigation_tls_renegotiation_flood_errors_total         # doit rester à 0
```

## Diagnostic

1. **Note** : Go 1.22+ refuse la renegociation TLS 1.2 par défaut côté
   serveur. Cette mitigation couvre TLS 1.3 KeyUpdate abusif et les
   patterns équivalents.
2. **Distribution IP** : attaque typiquement concentrée.

## Actions immédiates

```bash
# Durcir
curl -X PUT $CTRL/mitigations/tls-reneg -d '{
  "enabled": true,
  "max_renegs_per_conn": 1,
  "window": "60s"
}'

# Détendre
curl -X PUT $CTRL/mitigations/tls-reneg -d '{
  "enabled": true,
  "max_renegs_per_conn": 5,
  "window": "300s"
}'
```

## Rollback

Snapshot précédent.

## Escalade

- Si pic massif : envisager blocklist IP au niveau firewall (la cible
  est l'épuisement CPU).
