# Runbook — scraping

**Famille** : `scraping` &nbsp;·&nbsp; **Couche** : HTTP middleware
&nbsp;·&nbsp; **Default action** : `log` (observe-only)
&nbsp;·&nbsp; **Config** : [`configs/base/scraping.yaml`](../../configs/base/scraping.yaml)

## Symptôme

- Hausse soutenue de `matched_total`.
- Trafic anormal sur des endpoints catalogue / API publique.
- Pic de coût upstream (DB, CDN) sans hausse de revenus / conversions.

## Métriques clés

```promql
rate(mitigation_scraping_evaluated_total[1m])
rate(mitigation_scraping_matched_total[1m])     # signaux scraping détectés
rate(mitigation_scraping_logged_total[1m])      # action=log
rate(mitigation_scraping_blocked_total[1m])     # action=deny
mitigation_scraping_errors_total                # doit rester à 0
```

`matched / evaluated` est l'indicateur principal. > 10 % en continu
suggère scraping organisé.

## Diagnostic

1. **Action courante** : `log` (mode observe). Passer en `deny`
   uniquement après confirmation que les signaux capturent bien des
   bots et pas des clients legit.
2. **Signaux actifs** : `user_agent_deny`, `require_accept_language`,
   `require_accept_encoding`. Un seul signal suffit pour matcher.
3. **Faux positifs probables** : cURL / clients officiels mobiles
   parfois sans Accept-Language. Vérifier avant durcir.

## Actions immédiates

```bash
# Passer en mode bloquant après observation
curl -X PUT $CTRL/mitigations/scraping -d '{
  "enabled": true,
  "user_agent_deny": ["python-requests","curl/","wget","scrapy","Go-http-client"],
  "require_accept_language": true,
  "require_accept_encoding": false,
  "action": "deny"
}'

# Revenir en observe
curl -X PUT $CTRL/mitigations/scraping -d '{
  "enabled": true,
  "user_agent_deny": ["python-requests","curl/","wget","scrapy"],
  "require_accept_language": false,
  "require_accept_encoding": false,
  "action": "log"
}'
```

## Rollback

Snapshot précédent. **Important** : si on a basculé en `deny` et qu'on
voit `matched_total` exploser au-delà du raisonnable, repasser en `log`
sans attendre — on coupe potentiellement du trafic legit.

## Escalade

- Scraping persistant malgré blocage UA : envisager challenge JS /
  rate-limit IP via `http-flood-l7` ciblé sur endpoints catalogue.
