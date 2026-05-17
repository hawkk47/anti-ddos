/**
 * Auth Bearer minimal pour le control plane.
 *
 * Politique (cf. control-plane.instructions.md §Sécurité) :
 *   - /v1/health et /metrics : toujours publics.
 *   - Tout le reste : Header `Authorization: Bearer <token>` requis si
 *     un token est configuré.
 *   - Token absent (`null`) : autorisé UNIQUEMENT pour bind loopback
 *     (vérifié au boot par `loadConfigFromEnv`). Si on arrive ici avec
 *     un token null on logue un warning au boot et on laisse passer
 *     pour préserver l'ergonomie dev.
 *   - Comparaison en temps constant pour éviter une oracle de timing.
 *
 * Aucune valeur secrète n'est logée. Le statut 401 ne dit pas si le
 * token est manquant ou erroné (pas de différence observable).
 */
import { Buffer } from 'node:buffer';
import { timingSafeEqual } from 'node:crypto';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Routes (méthode + URL) publiques par construction. /metrics est
 * ouvert pour le scrape Prometheus — SUPPOSE que le control plane
 * bind loopback ou est placé derrière un réseau de confiance. Si on
 * doit un jour exposer le control plane sur Internet, retirer
 * /metrics d'ici et exiger Bearer dessus aussi.
 */
const PUBLIC_ROUTES: ReadonlyArray<{ method: string; url: string }> = [
  { method: 'GET', url: '/v1/health' },
  { method: 'GET', url: '/metrics' },
];

/**
 * Préfixes publics — couvrent les assets statiques de l'UI admin
 * (`/ui/...`). Le bundle ne contient aucun secret ; les appels
 * réels passent ensuite par `/v1/...` avec Bearer.
 */
const PUBLIC_PREFIXES: ReadonlyArray<{ method: string; prefix: string }> = [
  { method: 'GET', prefix: '/ui/' },
  { method: 'GET', prefix: '/ui' }, // /ui (sans trailing slash) → redirect interne
];

function isPublic(req: FastifyRequest): boolean {
  // routerPath dispo après matching ; en pré-validation on retombe
  // sur req.url. Comme aucun de nos endpoints publics n'a de query
  // string variable, un split sur '?' suffit.
  const url = req.url.split('?')[0] ?? '';
  for (const r of PUBLIC_ROUTES) {
    if (req.method === r.method && url === r.url) return true;
  }
  for (const p of PUBLIC_PREFIXES) {
    if (req.method === p.method && (url === p.prefix || url.startsWith(p.prefix))) {
      return true;
    }
  }
  return false;
}

function tokensEqual(a: string, b: string): boolean {
  // timingSafeEqual exige des buffers de même longueur. Si elles
  // diffèrent, le temps de cette branche dépend uniquement de la
  // longueur du token PRÉSENTÉ (connue de l'attaquant), jamais de
  // celle du secret — donc pas d'oracle. On fait quand même un
  // timingSafeEqual(ab, ab) pour normaliser grossièrement le coût
  // CPU et éviter un short-circuit observable.
  const ab = Buffer.from(a, 'utf8');
  const bb = Buffer.from(b, 'utf8');
  if (ab.length !== bb.length) {
    timingSafeEqual(ab, ab);
    return false;
  }
  return timingSafeEqual(ab, bb);
}

export interface AuthOptions {
  apiToken: string | null | undefined;
}

export function registerAuthHook(app: FastifyInstance, opts: AuthOptions): void {
  const { apiToken } = opts;

  if (apiToken === null || apiToken === undefined || apiToken === '') {
    // Bind loopback uniquement (garanti par loadConfigFromEnv ; en
    // contexte de test on tolère aussi `undefined` pour ne pas forcer
    // tous les __tests__ à déclarer apiToken: null explicitement).
    app.log.warn(
      { msg: 'control plane API token is unset; auth disabled (loopback only)' },
    );
    return;
  }

  app.addHook('onRequest', async (req: FastifyRequest, reply: FastifyReply) => {
    if (isPublic(req)) return;

    const header = req.headers.authorization;
    if (typeof header !== 'string' || header.length === 0) {
      reply.code(401).send({ error: 'unauthorized' });
      return;
    }
    const prefix = 'Bearer ';
    if (!header.startsWith(prefix)) {
      reply.code(401).send({ error: 'unauthorized' });
      return;
    }
    const presented = header.slice(prefix.length).trim();
    if (presented.length === 0 || !tokensEqual(presented, apiToken)) {
      reply.code(401).send({ error: 'unauthorized' });
      return;
    }
    // OK : laisser passer.
  });
}
