# Runbooks — anti-DDoS

Procédures opérationnelles par mitigation. Chaque runbook suit le même
plan :

1. **Symptôme** — ce qui déclenche l'alerte / le ticket.
2. **Métriques clés** — quoi regarder en priorité.
3. **Diagnostic** — questions à se poser dans l'ordre.
4. **Actions immédiates** — quoi changer dans la config (control plane).
5. **Rollback** — comment revenir à l'état antérieur.
6. **Escalade** — quand impliquer plus de monde.

## Index

| Famille                                                | Couche       | Default action |
|--------------------------------------------------------|--------------|----------------|
| [http-flood-l7](http-flood-l7.md)                      | HTTP         | deny (fail-closed) |
| [slow-post](slow-post.md)                              | HTTP body    | allow (fail-open)  |
| [slowloris](slowloris.md)                              | TCP/HTTP     | allow (fail-open)  |
| [large-header](large-header.md)                        | HTTP         | allow (fail-open)  |
| [hash-flood](hash-flood.md)                            | HTTP         | allow (fail-open)  |
| [range-amp](range-amp.md)                              | HTTP         | allow (fail-open)  |
| [cache-poison](cache-poison.md)                        | HTTP         | strip (fail-open)  |
| [http2-rapid-reset](http2-rapid-reset.md)              | HTTP/2       | allow (fail-open)  |
| [tls-renegotiation-flood](tls-renegotiation-flood.md)  | TLS listener | allow (fail-open)  |
| [scraping](scraping.md)                                | HTTP         | log (observe-only) |
| [credential-stuffing](credential-stuffing.md)          | HTTP         | deny (fail-closed) |

## Convention de métriques

Toutes les mitigations exposent ce préfixe :

```
mitigation_<famille>_evaluated_total
mitigation_<famille>_blocked_total
mitigation_<famille>_errors_total
mitigation_<famille>_duration_seconds  (histogramme)
```

Certaines familles ajoutent :

- `_matched_total` / `_logged_total` (`scraping`, `credential-stuffing`).
- `_stripped_total` (`cache-poison`).

## Règle générale fail-open / fail-closed

- **Défaut data plane = fail-open** : un bug interne ne doit pas couper
  du trafic légitime. Le compteur `errors_total` est l'indicateur
  d'un fail-open silencieux — il **doit** rester à 0 en régime normal.
- **Exception fail-closed** : `http-flood-l7` et `credential-stuffing`
  acceptent `on_error: deny` quand la mitigation est explicitement
  sécurité-first.

Voir [docs/adr/0003-http-flood-l7-fail-closed.md](../adr/0003-http-flood-l7-fail-closed.md)
pour le rationale de l'exception http-flood-l7.

## Contacts d'escalade

- **On-call data plane** : voir `configs/oncall.yaml` (pas commité).
- **Sécurité produit** : si exploitation active suspectée.
- **Réseau / infra** : si l'attaque dépasse 1 Gbps cumulé.
