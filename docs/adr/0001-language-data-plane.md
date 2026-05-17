# ADR 0001 — Langage du data plane : Go

- **Date** : 2026-05-15
- **Statut** : Accepté
- **Décideurs** : équipe projet
- **Concerne** : `proxy/**`

## Contexte

Le projet anti-ddos vise un reverse proxy de mitigation HTTP qui doit
fonctionner **à parité sur Windows 10+ et Linux x86_64**
(cf. [ADR 0002](./0002-portability-windows-linux.md)). Le data plane est
le chemin chaud : il termine TLS, parse HTTP/1.1 et HTTP/2, applique
rate-limiting et règles WAF. Le langage doit offrir :

1. Compilation et exécution **natives** sur Windows et Linux sans
   chaîne de build complexe.
2. Une stdlib HTTP/TLS production-ready (pas besoin de réimplémenter).
3. Concurrence I/O efficace sans recours à `epoll`/`io_uring` direct.
4. Outillage (test, lint, profilage) identique sur les deux OS.

## Options envisagées

| Critère | Go ≥ 1.22 | Rust 2021 |
|---|---|---|
| Cross-compile Win/Linux | `GOOS=… GOARCH=… go build`, intégré | `cargo` + `cross` ou MSVC sur Windows |
| Build Windows | Aucun toolchain externe (binaire statique) | Exige MSVC Build Tools (~3 Go) |
| HTTP/TLS stdlib | `net/http`, `crypto/tls` mature | `hyper` + `rustls` excellent mais externe |
| Async runtime | Goroutines (M:N), portable | `tokio` (chemins de code différents Win/Linux pour I/O) |
| Écosystème proxy de référence | Caddy, Traefik (tous portables) | `pingora` (Cloudflare) **Linux-only** |
| Perf brute | Bonne, GC court (sub-ms typique) | Meilleure, prévisible (no GC) |
| Effort pour atteindre la parité Win/Linux | Faible | Élevé (plusieurs features Linux-only à éviter) |
| Sûreté mémoire | GC + types | Borrow checker (plus fort) |
| Courbe d'apprentissage | Faible | Élevée |

## Décision

**Go ≥ 1.22, en pure-Go (`CGO_ENABLED=0`).**

Justifications principales :

1. **Cross-platform sans friction.** L'objectif numéro 1 du projet est
   « ça marche sur Windows comme sur Linux ». Go le donne gratuitement.
   Rust impose MSVC sur Windows et plusieurs crates de l'écosystème
   réseau ciblent Linux en priorité.
2. **Stdlib HTTP de qualité production.** `net/http` couvre HTTP/1.1
   et HTTP/2 ; `crypto/tls` couvre TLS 1.2/1.3. Permet d'écrire un
   proxy fonctionnel sans dépendance externe.
3. **Modèle de concurrence portable.** Goroutines + scheduler s'adaptent
   à IOCP (Windows) et epoll (Linux) sans que le code applicatif voie
   la différence.
4. **Outillage identique** (`go test`, `go vet`, `golangci-lint`,
   `pprof`) sur les deux OS — pas de divergence à gérer.

La perte de la sûreté mémoire de Rust est compensée par :
- les règles strictes de [proxy-data-plane.instructions.md](../../.github/instructions/proxy-data-plane.instructions.md)
  (no panic, no allocation par requête évitable, fuzzing sur les parsers) ;
- l'isolation processus du data plane (un crash redémarre le proxy,
  ne compromet pas le control plane).

## Conséquences

- `proxy/` est en Go, build avec `CGO_ENABLED=0 go build ./...`.
- Aucune dépendance qui requiert cgo (vérifié par CI).
- Aucun appel à `golang.org/x/sys/unix` non couvert sur Windows sans
  build tags + fallback portable.
- Si un jour une mitigation L3/L4 nécessite eBPF/XDP, ce sera un
  **composant séparé Linux-only**, pas une réécriture du data plane.

## Réversibilité

Faible. Réécrire le data plane dans un autre langage représente
plusieurs semaines. Un changement nécessiterait une nouvelle ADR
documentant un blocage majeur (perf insuffisante mesurée, faille de
sûreté répétée).
