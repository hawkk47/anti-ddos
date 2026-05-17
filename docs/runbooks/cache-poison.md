# Runbook — cache-poison

**Famille** : `cache-poison` &nbsp;·&nbsp; **Couche** : HTTP middleware
&nbsp;·&nbsp; **Default action** : `strip` (fail-open)
&nbsp;·&nbsp; **Config** : [`configs/base/cachepoison.yaml`](../../configs/base/cachepoison.yaml)

## Symptôme

- Alerte `CachePoisonStrippedSurge` ou `CachePoisonBlockedSurge`.
- Hausse d'erreurs côté upstream sur des routes habituellement saines.
- Cache CDN qui sert du contenu d'une session à une autre (à
  remonter en priorité — peut indiquer poisoning en cours).

## Métriques clés

```promql
rate(mitigation_cache_poison_evaluated_total[1m])
rate(mitigation_cache_poison_stripped_total[1m])
rate(mitigation_cache_poison_blocked_total[1m])
mitigation_cache_poison_errors_total                    # doit rester à 0
```

## Diagnostic

1. **`stripped` non nul** : des clients envoient des headers dangereux
   listés dans la config. C'est exactement ce qu'on veut **strip**
   silencieusement. Mode normal.
2. **`blocked` non nul** (action = `deny`) : escalade — quelqu'un tente
   activement du cache poisoning.
3. **Vérifier la liste de headers** : couvre-t-elle `X-Forwarded-Host`,
   `X-Original-URL`, `X-Rewrite-URL`, `X-HTTP-Method-Override` ?

## Actions immédiates

```bash
# Passer en mode bloquant après une attaque confirmée
curl -X PUT $CTRL/mitigations/cache-poison -d '{
  "enabled": true,
  "headers": ["X-Forwarded-Host","X-Original-URL","X-Rewrite-URL","X-HTTP-Method-Override"],
  "action": "deny"
}'

# Revenir à strip (mode opéra normal)
curl -X PUT $CTRL/mitigations/cache-poison -d '{
  "enabled": true,
  "headers": ["X-Forwarded-Host","X-Original-URL","X-Rewrite-URL","X-HTTP-Method-Override"],
  "action": "strip"
}'
```

## Rollback

Snapshot précédent.

## Escalade

- Si poisoning soupçonné (contenu utilisateur leaké via cache CDN) :
  purge cache CDN + équipe sécurité immédiate.
