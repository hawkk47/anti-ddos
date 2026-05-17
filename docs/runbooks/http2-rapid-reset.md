# Runbook — http2-rapid-reset

**Famille** : `http2-rapid-reset` &nbsp;·&nbsp; **Couche** : serveur HTTP/2
&nbsp;·&nbsp; **Default action** : `allow` (fail-open) — fermeture connexion
&nbsp;·&nbsp; **Config** : [`configs/base/http2reset.yaml`](../../configs/base/http2reset.yaml)
&nbsp;·&nbsp; **CVE** : CVE-2023-44487.

## Symptôme

- Alerte `HTTP2RapidResetBlockedSurge`.
- CPU/mémoire upstream qui décollent sans hausse de QPS effectif.
- Connexions HTTP/2 fermées brutalement par le proxy (côté client :
  GOAWAY).

## Métriques clés

```promql
rate(mitigation_http2_rapid_reset_evaluated_total[1m])  # 1 par RST_STREAM précoce observé
rate(mitigation_http2_rapid_reset_blocked_total[1m])    # 1 par connexion fermée
mitigation_http2_rapid_reset_errors_total               # doit rester à 0
```

`evaluated / blocked` élevé = beaucoup de resets mais peu de connexions
fermées (config tolérante). Ratio faible = chaque connexion défaille
vite (config stricte ou attaque massive).

## Diagnostic

1. **Clients legit qui annulent** : navigateurs annulent volontiers
   (changement de page rapide). Une valeur `max_resets_per_conn` trop
   basse génère des fermetures intempestives.
2. **Distribution IP** : attaque rapid-reset typiquement concentrée
   (un attaquant peut saturer avec quelques connexions).

## Actions immédiates

```bash
# Durcir
curl -X PUT $CTRL/mitigations/http2-rapid-reset -d '{
  "enabled": true,
  "max_resets_per_conn": 50,
  "window": "10s",
  "max_concurrent_streams": 100,
  "on_error": "allow"
}'

# Détendre (faux positifs navigateur)
curl -X PUT $CTRL/mitigations/http2-rapid-reset -d '{
  "enabled": true,
  "max_resets_per_conn": 500,
  "window": "60s",
  "max_concurrent_streams": 250,
  "on_error": "allow"
}'
```

## Rollback

Snapshot précédent.

## Escalade

- Hausse de fermetures sans hausse de `evaluated` : bug interne, ouvrir
  ticket data plane.
- Si CVE actif sur libs amont : vérifier que `golang.org/x/net/http2`
  est à jour (`go list -m -u all`).
