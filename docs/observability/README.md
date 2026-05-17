# Observabilité

Artéfacts pour scraper, alerter et visualiser le data plane anti-DDoS.

## Métriques exposées

Le data plane n'a pas encore d'exporter Prometheus HTTP intégré
(prévu via un adapter sur `metrics.Registry` — voir
[proxy/internal/metrics/metrics.go](../../proxy/internal/metrics/metrics.go)).
En attendant, l'in-memory `Registry` est consultable via :

- l'admin API (`GET /admin/metrics`) — JSON brut.
- les tests / scripts.

Toutes les métriques suivent le préfixe `mitigation_<famille>_*`. Liste
complète documentée par runbook ([docs/runbooks/README.md](../runbooks/README.md)).

## Fichiers

| Fichier                                           | Usage                                                |
|---------------------------------------------------|------------------------------------------------------|
| [prometheus-rules.yaml](prometheus-rules.yaml)    | Règles d'alerte : errors_total, blocked surges, p99. |
| [grafana-dashboard.json](grafana-dashboard.json)  | Dashboard d'overview : import direct dans Grafana.   |

## Conventions

- **errors_total = 0 toujours**. Alerte `MitigationErrorsNonZero`
  paginale. Sur les familles fail-closed (`http-flood-l7`,
  `credential-stuffing`) c'est du trafic legit coupé. Sur les
  fail-open c'est un signal silencieux non traité.
- **Latence p99 < 1 ms par famille**. La chaîne complète mesurée à
  ~600 ns/op (cf. [docs/hardening.md](../hardening.md#2-coût-mesuré)).
  Tout dépassement durable indique contention ou régression.
- **Pas de label `client_ip`** dans les métriques Prometheus (cardinalité
  explosive). Les détails par IP restent dans les logs structurés
  (avec hash IP si stockés > 24 h).

## Import dashboard

```bash
# Grafana 10+ via API
curl -X POST -H "Content-Type: application/json" \
     -H "Authorization: Bearer $GRAFANA_TOKEN" \
     -d @docs/observability/grafana-dashboard.json \
     "$GRAFANA_URL/api/dashboards/db"
```

## Charger les rules Prometheus

```yaml
# prometheus.yml
rule_files:
  - /etc/prometheus/anti-ddos/prometheus-rules.yaml
```
