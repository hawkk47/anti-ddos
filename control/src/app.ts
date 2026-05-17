import Fastify, { type FastifyInstance } from 'fastify';
import { Type } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import fastifyStatic from '@fastify/static';
import { existsSync, statSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Config } from './config.js';
import {
  createInMemoryStore,
  registerConnectionsRoutes,
  type ConnectionsStore,
} from './mitigations/connections.js';
import {
  createInMemoryRatelimitStore,
  registerRatelimitRoutes,
  type RatelimitStore,
} from './mitigations/ratelimit.js';
import {
  createInMemoryHeadersStore,
  registerHeadersRoutes,
  type HeadersStore,
} from './mitigations/headers.js';
import {
  createInMemoryBodiesStore,
  registerBodiesRoutes,
  type BodiesStore,
} from './mitigations/bodies.js';
import {
  createInMemoryTLSStore,
  registerTLSRoutes,
  type TLSStore,
} from './mitigations/tls.js';
import {
  createInMemoryHttp2Store,
  registerHttp2Routes,
  type Http2Store,
} from './mitigations/http2.js';
import {
  createInMemoryHashFloodStore,
  registerHashFloodRoutes,
  type HashFloodStore,
} from './mitigations/hashflood.js';
import {
  createInMemoryRangeAmpStore,
  registerRangeAmpRoutes,
  type RangeAmpStore,
} from './mitigations/rangeamp.js';
import {
  createInMemoryCachePoisonStore,
  registerCachePoisonRoutes,
  type CachePoisonStore,
} from './mitigations/cachepoison.js';
import {
  createInMemoryScrapingStore,
  registerScrapingRoutes,
  type ScrapingStore,
} from './mitigations/scraping.js';
import {
  createInMemoryCredStuffStore,
  registerCredStuffRoutes,
  type CredStuffStore,
} from './mitigations/credstuff.js';
import {
  createInMemoryConcurrencyStore,
  registerConcurrencyRoutes,
  type ConcurrencyStore,
} from './mitigations/concurrency.js';
import {
  createInMemoryRequestHygieneStore,
  registerRequestHygieneRoutes,
  type RequestHygieneStore,
} from './mitigations/requesthygiene.js';
import {
  createInMemoryTLSFingerprintStore,
  registerTLSFingerprintRoutes,
  type TLSFingerprintStore,
} from './mitigations/tlsfingerprint.js';
import {
  createInMemoryBehavioralCredStuffStore,
  registerBehavioralCredStuffRoutes,
  type BehavioralCredStuffStore,
  type BehavioralThresholds,
} from './behavioral/credstuff.js';
import {
  createBehavioralCredStuffPusher,
  registerBehavioralCredStuffPushRoutes,
  type BehavioralCredStuffPusher,
  type PushMode,
} from './behavioral/credstuff-push.js';
import { registerMetricsRoute } from './metrics.js';
import { registerAuthHook } from './auth.js';
import { registerPersistence, type FamilyBinding } from './persistence.js';

export interface BuildOptions {
  config: Config;
  /** Surcharge utile pour les tests (par défaut : Date.now). */
  now?: () => number;
  /** Store injectable (par défaut : in-memory). */
  connectionsStore?: ConnectionsStore;
  /** Store ratelimit (http-flood-l7) injectable. */
  ratelimitStore?: RatelimitStore;
  /** Store headers (large-header) injectable. */
  headersStore?: HeadersStore;
  /** Store bodies (slow-post) injectable. */
  bodiesStore?: BodiesStore;
  /** Store tls (tls-renegotiation-flood) injectable. */
  tlsStore?: TLSStore;
  /** Store http2 (http2-rapid-reset) injectable. */
  http2Store?: Http2Store;
  /** Store hash-flood injectable. */
  hashFloodStore?: HashFloodStore;
  /** Store range-amp injectable. */
  rangeAmpStore?: RangeAmpStore;
  /** Store cache-poison injectable. */
  cachePoisonStore?: CachePoisonStore;
  /** Store scraping injectable. */
  scrapingStore?: ScrapingStore;
  /** Store credential-stuffing injectable. */
  credStuffStore?: CredStuffStore;
  /** Store concurrency-cap injectable. */
  concurrencyStore?: ConcurrencyStore;
  /** Store request-hygiene injectable. */
  requestHygieneStore?: RequestHygieneStore;
  /** Store tls-fingerprint injectable. */
  tlsFingerprintStore?: TLSFingerprintStore;
  /** Store behavioral credential-stuffing (ADR 0004 phase 3) injectable. */
  behavioralCredStuffStore?: BehavioralCredStuffStore;
  /** Override partiel des seuils behavioral (10 min, 20/5/50 par défaut). */
  behavioralCredStuffThresholds?: Partial<BehavioralThresholds>;
  /** Pusher behavioral (ADR 0004 phase 4) injectable pour les tests. */
  behavioralCredStuffPusher?: BehavioralCredStuffPusher;
  /** Mode initial du pusher behavioral. Défaut : 'shadow' (cf. ADR 0004). */
  behavioralCredStuffPushMode?: PushMode;
  /**
   * Fetch utilisé pour pousser la config au data plane. Injectable
   * pour les tests (par défaut : global `fetch`). Doit suivre la
   * signature standard.
   */
  fetcher?: typeof fetch;
}

/**
 * Construit l'instance Fastify du control plane.
 *
 * Endpoints :
 *   GET  /v1/health  → liveness/readiness simple
 *   POST /v1/reload  → déclenche un rechargement à chaud (no-op MVP)
 *
 * La vraie logique mTLS / JWT / persistence sera ajoutée incrémentalement
 * via /add-mitigation. MVP : route surface + schémas stricts.
 */
export function buildApp(opts: BuildOptions): FastifyInstance {
  const {
    config,
    now = () => Date.now(),
    connectionsStore = createInMemoryStore(),
    ratelimitStore = createInMemoryRatelimitStore(),
    headersStore = createInMemoryHeadersStore(),
    bodiesStore = createInMemoryBodiesStore(),
    tlsStore = createInMemoryTLSStore(),
    http2Store = createInMemoryHttp2Store(),
    hashFloodStore = createInMemoryHashFloodStore(),
    rangeAmpStore = createInMemoryRangeAmpStore(),
    cachePoisonStore = createInMemoryCachePoisonStore(),
    scrapingStore = createInMemoryScrapingStore(),
    credStuffStore = createInMemoryCredStuffStore(),
    concurrencyStore = createInMemoryConcurrencyStore(),
    requestHygieneStore = createInMemoryRequestHygieneStore(),
    tlsFingerprintStore = createInMemoryTLSFingerprintStore(),
    behavioralCredStuffStore,
    behavioralCredStuffThresholds,
    behavioralCredStuffPusher,
    behavioralCredStuffPushMode,
    fetcher = fetch,
  } = opts;
  const startedAt = now();

  const app = Fastify({
    logger: {
      level: config.logLevel,
      // JSON par défaut (pas de pretty en prod). Cf. logs JSON sans PII.
    },
    disableRequestLogging: false,
    // Anti-large-header côté control plane.
    bodyLimit: 1 * 1024 * 1024, // 1 MiB
    trustProxy: false,
  });

  // ----------------------------------------------------------------
  // Auth Bearer (cf. control-plane.instructions.md §Sécurité).
  // Doit être enregistré AVANT toute autre route pour que onRequest
  // s'applique à 100% du surface area.
  // ----------------------------------------------------------------
  registerAuthHook(app, { apiToken: config.apiToken });

  // ----------------------------------------------------------------
  // GET /v1/health
  // ----------------------------------------------------------------
  app.route({
    method: 'GET',
    url: '/v1/health',
    schema: {
      response: {
        200: Type.Object(
          {
            status: Type.Literal('ok'),
            uptimeMs: Type.Integer({ minimum: 0 }),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async (_req, _reply) => {
      return { status: 'ok' as const, uptimeMs: now() - startedAt };
    },
  });

  // ----------------------------------------------------------------
  // POST /v1/reload
  //
  // MVP : accepte une requête, valide le body si présent (vide accepté),
  // retourne accepted. L'implémentation réelle (recharger configs/,
  // notifier le proxy sans drop de connexion) viendra avec le module
  // configs/.
  // Fail-closed pour cet endpoint : sur erreur, on renvoie 5xx et on
  // ne change RIEN à l'état. Documenté dans configs.instructions.md.
  // ----------------------------------------------------------------
  const ReloadBodySchema = Type.Object(
    {
      reason: Type.Optional(Type.String({ maxLength: 256 })),
    },
    { additionalProperties: false },
  );

  app.route({
    method: 'POST',
    url: '/v1/reload',
    schema: {
      response: {
        202: Type.Object(
          {
            status: Type.Literal('accepted'),
            at: Type.Integer({ minimum: 0 }),
            pushed: Type.Integer({ minimum: 0 }),
          },
          { additionalProperties: false },
        ),
        400: Type.Object(
          {
            error: Type.Literal('invalid_body'),
            details: Type.Array(Type.String()),
          },
          { additionalProperties: false },
        ),
        502: Type.Object(
          {
            error: Type.Literal('proxy_unreachable'),
            details: Type.Array(Type.String()),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async (req, reply) => {
      // Body absent ou vide → accepté.
      const raw = req.body;
      if (raw !== undefined && raw !== null && !(typeof raw === 'object' && Object.keys(raw as object).length === 0)) {
        if (!Value.Check(ReloadBodySchema, raw)) {
          const details = [...Value.Errors(ReloadBodySchema, raw)].map(
            (e) => `${e.path} ${e.message}`,
          );
          reply.code(400);
          return { error: 'invalid_body' as const, details };
        }
      }

      // Snapshot atomique des règles connections + ratelimit. Format
      // aligné avec proxy/internal/adminapi/admin.go.
      const connSnapshot = connectionsStore.list();
      const rateSnapshot = ratelimitStore.list();
      const hdrSnapshot = headersStore.list();
      const bodySnapshot = bodiesStore.list();
      const tlsSnapshot = tlsStore.list();
      const http2Snapshot = http2Store.list();
      const hashFloodSnapshot = hashFloodStore.list();
      const rangeAmpSnapshot = rangeAmpStore.list();
      const cachePoisonSnapshot = cachePoisonStore.list();
      const scrapingSnapshot = scrapingStore.list();
      const credStuffSnapshot = credStuffStore.list();
      const concurrencySnapshot = concurrencyStore.list();
      const requestHygieneSnapshot = requestHygieneStore.list();
      const tlsFingerprintSnapshot = tlsFingerprintStore.list();
      const targets: Array<{ url: string; payload: unknown; family: string }> = [
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/connections`,
          payload: connSnapshot,
          family: 'connections',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/ratelimit`,
          payload: rateSnapshot,
          family: 'ratelimit',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/headers`,
          payload: hdrSnapshot,
          family: 'headers',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/bodies`,
          payload: bodySnapshot,
          family: 'bodies',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/tls`,
          payload: tlsSnapshot,
          family: 'tls',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/http2`,
          payload: http2Snapshot,
          family: 'http2',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/hash-flood`,
          payload: hashFloodSnapshot,
          family: 'hash-flood',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/range-amp`,
          payload: rangeAmpSnapshot,
          family: 'range-amp',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/cache-poison`,
          payload: cachePoisonSnapshot,
          family: 'cache-poison',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/scraping`,
          payload: scrapingSnapshot,
          family: 'scraping',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/credential-stuffing`,
          payload: credStuffSnapshot,
          family: 'credential-stuffing',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/concurrency`,
          payload: concurrencySnapshot,
          family: 'concurrency-cap',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/request-hygiene`,
          payload: requestHygieneSnapshot,
          family: 'request-hygiene',
        },
        {
          url: `${config.proxyAdminUrl}/_admin/v1/mitigations/tls-fingerprint`,
          payload: tlsFingerprintSnapshot,
          family: 'tls-fingerprint',
        },
      ];
      const totalRules =
        connSnapshot.rules.length +
        rateSnapshot.rules.length +
        hdrSnapshot.rules.length +
        bodySnapshot.rules.length +
        tlsSnapshot.rules.length +
        http2Snapshot.rules.length +
        hashFloodSnapshot.rules.length +
        rangeAmpSnapshot.rules.length +
        cachePoisonSnapshot.rules.length +
        scrapingSnapshot.rules.length +
        credStuffSnapshot.rules.length +
        concurrencySnapshot.rules.length +
        requestHygieneSnapshot.rules.length +
        tlsFingerprintSnapshot.rules.length;
      req.log.info({
        msg: 'reload pushing',
        rev: {
          connections: connSnapshot.rev,
          ratelimit: rateSnapshot.rev,
          headers: hdrSnapshot.rev,
          bodies: bodySnapshot.rev,
          tls: tlsSnapshot.rev,
          http2: http2Snapshot.rev,
          'hash-flood': hashFloodSnapshot.rev,
          'range-amp': rangeAmpSnapshot.rev,
          'cache-poison': cachePoisonSnapshot.rev,
          scraping: scrapingSnapshot.rev,
          'credential-stuffing': credStuffSnapshot.rev,
          'concurrency-cap': concurrencySnapshot.rev,
          'request-hygiene': requestHygieneSnapshot.rev,
          'tls-fingerprint': tlsFingerprintSnapshot.rev,
        },
        rules: totalRules,
      });

      for (const t of targets) {
        let response: Response;
        try {
          response = await fetcher(t.url, {
            method: 'PUT',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(t.payload),
          });
        } catch (err) {
          const detail = err instanceof Error ? err.message : String(err);
          req.log.error({ msg: 'reload push failed', family: t.family, err: detail });
          reply.code(502);
          return { error: 'proxy_unreachable' as const, details: [`${t.family}: ${detail}`] };
        }

        if (!response.ok) {
          const body = await safeText(response);
          req.log.error({ msg: 'reload push rejected', family: t.family, status: response.status, body });
          reply.code(502);
          return {
            error: 'proxy_unreachable' as const,
            details: [`${t.family}: proxy returned ${response.status}: ${body}`],
          };
        }
      }

      reply.code(202);
      return {
        status: 'accepted' as const,
        at: now(),
        pushed: totalRules,
      };
    },
  });

  // 404 explicite, JSON.
  app.setNotFoundHandler((req, reply) => {
    reply.code(404).send({ error: 'not_found', path: req.url });
  });

  // ----------------------------------------------------------------
  // Persistence : load snapshots & wire onResponse dump hook BEFORE
  // registering mitigation routes so the hook captures their PUTs.
  // ----------------------------------------------------------------
  const bindings: FamilyBinding[] = [
    { family: 'connections', store: connectionsStore },
    { family: 'ratelimit', store: ratelimitStore },
    { family: 'headers', store: headersStore },
    { family: 'bodies', store: bodiesStore },
    { family: 'tls', store: tlsStore },
    { family: 'http2', store: http2Store },
    { family: 'hash-flood', store: hashFloodStore },
    { family: 'range-amp', store: rangeAmpStore },
    { family: 'cache-poison', store: cachePoisonStore },
    { family: 'scraping', store: scrapingStore },
    { family: 'credential-stuffing', store: credStuffStore },
    { family: 'concurrency', store: concurrencyStore },
    { family: 'request-hygiene', store: requestHygieneStore },
    { family: 'tls-fingerprint', store: tlsFingerprintStore },
  ];
  registerPersistence(app, config.stateDir ?? '', bindings);

  // ----------------------------------------------------------------
  // Mitigations / connections (Slowloris).
  // ----------------------------------------------------------------
  registerConnectionsRoutes(app, connectionsStore);
  // ----------------------------------------------------------------
  // Mitigations / ratelimit (http-flood-l7).
  // ----------------------------------------------------------------
  registerRatelimitRoutes(app, ratelimitStore);
  // ----------------------------------------------------------------
  // Mitigations / headers (large-header).
  // ----------------------------------------------------------------
  registerHeadersRoutes(app, headersStore);
  // ----------------------------------------------------------------
  // Mitigations / bodies (slow-post).
  // ----------------------------------------------------------------
  registerBodiesRoutes(app, bodiesStore);
  // ----------------------------------------------------------------
  // Mitigations / tls (tls-renegotiation-flood).
  // ----------------------------------------------------------------
  registerTLSRoutes(app, tlsStore);
  // ----------------------------------------------------------------
  // Mitigations / http2 (http2-rapid-reset, CVE-2023-44487).
  // ----------------------------------------------------------------
  registerHttp2Routes(app, http2Store);
  // ----------------------------------------------------------------
  // Mitigations / hash-flood (cap nombre de params query string).
  // ----------------------------------------------------------------
  registerHashFloodRoutes(app, hashFloodStore);
  // ----------------------------------------------------------------
  // Mitigations / range-amp (CVE-2011-3192 Apache Killer).
  // ----------------------------------------------------------------
  registerRangeAmpRoutes(app, rangeAmpStore);
  // ----------------------------------------------------------------
  // Mitigations / cache-poison (Kettle 2018 Practical Web Cache Poisoning).
  // ----------------------------------------------------------------
  registerCachePoisonRoutes(app, cachePoisonStore);
  // ----------------------------------------------------------------
  // Mitigations / scraping-aggressif (signature-based bot detection).
  // ----------------------------------------------------------------
  registerScrapingRoutes(app, scrapingStore);
  // ----------------------------------------------------------------
  // Mitigations / credential-stuffing (rate-limit per-IP scopé login).
  // ----------------------------------------------------------------
  registerCredStuffRoutes(app, credStuffStore);
  // ----------------------------------------------------------------
  // Mitigations / concurrency-cap (load shedding / backpressure global).
  // ----------------------------------------------------------------
  registerConcurrencyRoutes(app, concurrencyStore);
  // ----------------------------------------------------------------
  // Mitigations / request-hygiene (méthode whitelist + anti-smuggling).
  // ----------------------------------------------------------------
  registerRequestHygieneRoutes(app, requestHygieneStore);
  // ----------------------------------------------------------------
  // Mitigations / tls-fingerprint (JA3 + JA4 blocklist au handshake).
  // ----------------------------------------------------------------
  registerTLSFingerprintRoutes(app, tlsFingerprintStore);
  // ----------------------------------------------------------------
  // Behavioral / credential-stuffing (ADR 0004 phase 3).
  // Fenêtre glissante 10 min, heuristiques per-user + per-IP.
  // Phase 3 : ingestion + état candidat. Le push proxy arrive en phase 4.
  // ----------------------------------------------------------------
  const behavioralStore =
    behavioralCredStuffStore ??
    createInMemoryBehavioralCredStuffStore(
      behavioralCredStuffThresholds === undefined
        ? { now }
        : { now, thresholds: behavioralCredStuffThresholds },
    );
  registerBehavioralCredStuffRoutes(app, behavioralStore);
  // ----------------------------------------------------------------
  // Behavioral / credential-stuffing push (ADR 0004 phase 4).
  // Shadow mode par défaut : on calcule et logue les candidats sans
  // appel réseau au data plane. Bascule en 'enforce' via
  // POST /v1/behavioral/credstuff/push/mode.
  // ----------------------------------------------------------------
  const behavioralPusher =
    behavioralCredStuffPusher ??
    createBehavioralCredStuffPusher({
      store: behavioralStore,
      proxyAdminUrl: config.proxyAdminUrl,
      ...(config.proxyAdminToken !== null && config.proxyAdminToken !== undefined
        ? { proxyAdminToken: config.proxyAdminToken }
        : {}),
      fetcher,
      now,
      initialMode: behavioralCredStuffPushMode ?? 'shadow',
      logger: app.log,
    });
  registerBehavioralCredStuffPushRoutes(app, behavioralPusher);
  // ----------------------------------------------------------------
  // /metrics (Prometheus text exposition).
  // Phase 5 ADR 0004 : expose store + pusher counters.
  // ----------------------------------------------------------------
  registerMetricsRoute(app, {
    behavioralStore,
    behavioralPusher,
  });

  // ----------------------------------------------------------------
  // GET /v1/proxy/metrics — relais vers data plane /_admin/v1/metrics.
  // Permet à l'UI admin de scrape les counters mitigation sans
  // CORS / second port. Auth Bearer (control plane) requise comme
  // toute route /v1/. Le token proxy est ajouté s'il est configuré.
  // ----------------------------------------------------------------
  app.route({
    method: 'GET',
    url: '/v1/proxy/metrics',
    handler: async (req, reply) => {
      const url = `${config.proxyAdminUrl.replace(/\/$/, '')}/_admin/v1/metrics`;
      let res: Response;
      try {
        res = await fetcher(url, {
          method: 'GET',
          headers:
            config.proxyAdminToken !== null && config.proxyAdminToken !== undefined
              ? { authorization: `Bearer ${config.proxyAdminToken}` }
              : {},
        });
      } catch (err) {
        req.log.warn({ msg: 'proxy metrics unreachable', err: (err as Error).message });
        reply.code(502).type('text/plain').send('# proxy unreachable\n');
        return;
      }
      const body = await res.text();
      reply
        .code(res.ok ? 200 : 502)
        .type('text/plain; version=0.0.4')
        .send(res.ok ? body : `# proxy returned ${res.status}\n`);
    },
  });

  // ----------------------------------------------------------------
  // UI statique servie sous /ui/* (cf. ui/).
  // Whitelistée dans auth.ts (préfixe public). Si le bundle n'a pas
  // été buildé, on logue un warning et on skip — pas d'erreur fatale.
  // ----------------------------------------------------------------
  registerStaticUI(app);

  return app;
}

function registerStaticUI(app: FastifyInstance): void {
  const override = process.env['ANTIDDOS_UI_DIST'];
  const here = dirname(fileURLToPath(import.meta.url));
  // Chemins candidats : env > ../../ui/dist (depuis src/ ou dist/).
  const candidates = [
    override,
    resolve(here, '..', '..', 'ui', 'dist'),
    resolve(here, '..', '..', '..', 'ui', 'dist'),
  ].filter((p): p is string => typeof p === 'string' && p.length > 0);
  const root = candidates.find((p) => existsSync(p) && statSync(p).isDirectory());
  if (!root) {
    app.log.warn({ msg: 'UI bundle not found; skipping /ui/* mount', tried: candidates });
    return;
  }
  app.register(fastifyStatic, {
    root,
    prefix: '/ui/',
    decorateReply: false,
    index: 'index.html',
    list: false,
  });
  // Redirige /ui (sans slash) → /ui/.
  app.get('/ui', async (_req, reply) => {
    reply.redirect('/ui/');
  });
  app.log.info({ msg: 'UI mounted at /ui/', root });
}

async function safeText(r: Response): Promise<string> {
  try {
    return (await r.text()).slice(0, 512);
  } catch {
    return '';
  }
}
