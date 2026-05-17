# ADR 0005 — Architecture des mitigations L3/L4 (listener wrappers)

- **Date** : 2026-05-23
- **Statut** : Accepté
- **Décideurs** : équipe projet
- **Concerne** : `proxy/mitigations/{ipreputation,connflood,synflood,handshakeguard,geoblockl4}/`,
  `proxy/internal/server/server.go`,
  `configs/base/{ipreputation,connflood,synflood,handshakeguard,geoblock-l4}.yaml`,
  `control/src/mitigations/l3l4.ts`
- **Lié à** : [AGENTS.md §3](../../AGENTS.md), [ADR 0002 portabilité](0002-portability-windows-linux.md),
  [docs/threat-model.md](../threat-model.md)

## Contexte

Les 13 mitigations existantes opèrent en aval de la pile HTTP
(middlewares `http.Handler` ou hooks TLS). Cela laisse passer plusieurs
classes d'attaque qui consomment des ressources **avant** que la
requête HTTP atteigne le routeur :

- floods de SYN (TCP backlog saturé),
- ouvertures massives de connexions TCP par une seule IP/sous-réseau,
  consommant des FD et de la mémoire kernel,
- connexions à moitié ouvertes côté applicatif (handshake TCP réussi
  mais aucun octet utile envoyé, pas même un préface HTTP),
- trafic provenant de pays jamais légitimes pour le service,
- IP déjà connues comme hostiles via threat-intel locale.

Aucune dépendance à `eBPF`, `iptables`, `nftables` ou aux raw sockets
n'est admise (cf. [ADR 0002](0002-portability-windows-linux.md)).
La défense doit rester **pure-Go, portable Windows + Linux**.

## Décision

Adopter un patron **listener wrapper TCP** : chaque mitigation L3/L4
implémente

```go
WrapListener(net.Listener) net.Listener
```

et la chaîne est appliquée dans `server.Run`, du plus externe au plus
interne :

```
raw net.Listen
  ↓ ip-reputation        (drop immédiat des IP/CIDR connus)
  ↓ conn-flood           (cap des connexions simultanées par IP / subnet)
  ↓ syn-flood            (token bucket sur le taux d'`Accept` par IP)
  ↓ handshake-guard      (timeout sur la 1ʳᵉ lecture utile)
  ↓ geoblock-l4          (lookup ISO sans terminer TLS)
  ↓ tls-renegotiation    (existant, hook TLS)
  ↓ slowloris            (existant, wrapper net.Listener)
```

Chaque wrapper :

1. **Ignore systématiquement** loopback + RFC1918 + ULA via
   `netshield.IsPrivateOrLoopback`. Aucune protection L3/L4 ne doit
   bloquer un health-check local ni un sidecar.
2. Maintient ses propres compteurs `mitigation_<id>_{evaluated,blocked,errors}_total`
   + histogramme `_duration_seconds` (cf. `metrics.Registry`).
3. Expose son `Config` via `atomic.Pointer[Config]` pour hot-reload
   atomique sans drop de connexion.
4. Est **désactivé** dans `configs/base/` (raison documentée). Les
   thresholds sains varient trop par déploiement pour figurer
   en dur.

### Reporter pattern (cross-mitigation)

`syn-flood` et `handshake-guard` détectent un comportement abusif mais
n'ont qu'un signal local et fugace. Plutôt que de bloquer une IP eux-mêmes
(et perdre la trace au prochain redémarrage), ils s'abonnent à un
`Reporter` (interface à un seul `BlockIP(ip, ttl)`).
`ip-reputation` l'implémente : le report inscrit l'IP dans la table
dynamique à TTL, déjà partagée entre tous les listeners en amont.
Wiring : `server.New()` appelle `synfloodLim.SetReporter(ipreputLim)`
et `handshakeLim.SetReporter(ipreputLim)`.

### Défaut fail-open

Toutes les mitigations L3/L4 sont **fail-open par défaut**
(`on_error: allow`). Justification :

- contrairement à [ADR 0003](0003-http-flood-l7-fail-closed.md), l'erreur
  interne typique (parsing IP, lookup géo absent) survient **avant**
  toute terminaison TLS. Refuser la connexion masque la cause réelle
  derrière un `connection refused` opaque et casse les sondes
  loopback.
- Les attaques L3/L4 majeures (SYN flood, conn flood) atteignent leur
  but quand la queue d'accept est saturée. Une mitigation buggée qui
  bloque le data plane entier amplifie l'attaque.
- Le mode `deny` reste configurable par règle.

## Alternatives rejetées

| Option | Raison du rejet |
|---|---|
| Filtre kernel (`iptables` / `nftables` / `Windows Filtering Platform`) | viole [ADR 0002](0002-portability-windows-linux.md), demande root/admin. |
| `eBPF` / `XDP` | Linux-only, kernel ≥ 5.x, viole [ADR 0002](0002-portability-windows-linux.md). |
| Middleware HTTP (post-TLS) | trop tardif : `Accept()` a déjà coûté, TLS handshake déjà payé. |
| `SO_REUSEPORT` + worker pinning | Linux-only, ne résout pas le filtrage applicatif. |

## Conséquences

- **Positives** : surface couverte étendue de L7 vers L3/L4 sans cgo,
  sans privilège root, sans nouvelle dépendance externe (sauf
  `github.com/phuslu/iploc`, déjà présent pour `geoip`).
- **Négatives** : 5 nouveaux paquets à maintenir, 5 nouveaux endpoints
  admin/control, surface de configuration accrue. Mitigation : tous
  désactivés par défaut, schémas JSON stricts, factory générique côté
  control plane (`control/src/mitigations/l3l4.ts`).
- **Tests** : reproducers loopback-only requis avant chaque PR de
  changement (cf. [.github/instructions/tests.instructions.md](../../.github/instructions/tests.instructions.md)).
