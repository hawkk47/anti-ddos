/**
 * Phase 4 ADR 0004 — Push control → data plane de la blocklist
 * credential-stuffing comportementale.
 *
 * Responsabilités :
 *   1. Lire l'état candidat du store behavioral (phase 3).
 *   2. Transformer les candidats en entrées blocklist (RFC 3339 expiry).
 *   3. Pousser le snapshot complet via PUT /_admin/v1/blocklist/credstuff
 *      (idempotent, version monotone côté pusher pour éviter les
 *      collisions avec un opérateur qui curl-erait à la main).
 *   4. Supporter deux modes :
 *        - 'shadow'  : compute + log, AUCUN appel réseau au proxy.
 *                      Mode par défaut pour la phase 4 → on observe
 *                      les candidats sans risquer de bloquer du trafic
 *                      légitime tant que les heuristiques ne sont pas
 *                      tunées en prod.
 *        - 'enforce' : push effectif. Sur erreur, on garde le mode mais
 *                      lastResult expose l'échec pour /push GET.
 *
 * Pas de scheduler interne : c'est l'orchestrateur (ou un job cron
 * externe) qui appelle POST /v1/behavioral/credstuff/push. Conserver
 * la simplicité de l'API surface side. Une seconde itération pourra
 * ajouter un interval timer si besoin.
 *
 * Aucun secret, aucune PII : les IPs sont transmises telles quelles
 * (déjà tronquées en candidats par la phase 3), pas de username_hash
 * dans le payload sortant.
 */
import { Type } from '@sinclair/typebox';
import type { FastifyInstance } from 'fastify';
import type { BehavioralCredStuffStore, BlocklistCandidate } from './credstuff.js';

export type PushMode = 'shadow' | 'enforce';

export interface PushResult {
  /** ms UNIX du tick de push. */
  at: number;
  /** Mode au moment du push. */
  mode: PushMode;
  /** Nombre de candidats poussés (ou simulés). */
  candidates: number;
  /** Version monotone interne au pusher (croît à chaque push). */
  version: number;
  /** true si le PUT data plane a renvoyé 2xx. false en shadow ou sur erreur. */
  pushed: boolean;
  /** Statut court : 'shadow' | 'ok' | 'stale_version' | 'error' | 'noop'. */
  status: 'shadow' | 'ok' | 'stale_version' | 'error' | 'noop';
  /** Détail en cas d'erreur (message court, tronqué). */
  error?: string;
}

export interface PusherMetrics {
  /** Totaux cumulés par status depuis le boot. */
  pushTotals: Record<PushResult['status'], number>;
  /** Mode courant (étiquette utile dans /metrics). */
  mode: PushMode;
  /** Dernière version poussée (0 si jamais). */
  lastVersion: number;
  /** ms UNIX du dernier push (0 si jamais). */
  lastAtMs: number;
  /** 1 si dernier push a effectivement atteint le data plane, 0 sinon. */
  lastPushed: 0 | 1;
  /** Nombre de candidats au dernier push (0 si jamais). */
  lastCandidates: number;
}

export interface BehavioralCredStuffPusher {
  push(): Promise<PushResult>;
  lastResult(): PushResult | null;
  mode(): PushMode;
  setMode(mode: PushMode): void;
  metrics(): PusherMetrics;
}

export interface PusherDeps {
  store: BehavioralCredStuffStore;
  proxyAdminUrl: string;
  /**
   * Token Bearer envoyé au data plane via `Authorization`. Optionnel
   * (vide / undefined ⇒ pas de header, le proxy doit alors tourner
   * sans token — dev loopback uniquement).
   */
  proxyAdminToken?: string;
  fetcher?: typeof fetch;
  now?: () => number;
  /** Mode initial. Défaut : 'shadow' (cf. ADR 0004 — observation d'abord). */
  initialMode?: PushMode;
  /** Timeout réseau (ms) pour le PUT. Défaut 5000. */
  timeoutMs?: number;
  /**
   * Logger best-effort. Si fourni, on log les transitions de mode et
   * les erreurs de push (jamais le contenu des candidats — IPs).
   */
  logger?: { info: (o: object) => void; warn: (o: object) => void; error: (o: object) => void };
}

export function createBehavioralCredStuffPusher(deps: PusherDeps): BehavioralCredStuffPusher {
  const fetchImpl = deps.fetcher ?? fetch;
  const now = deps.now ?? (() => Date.now());
  const timeoutMs = deps.timeoutMs ?? 5000;
  const base = deps.proxyAdminUrl.replace(/\/+$/, '');
  const url = `${base}/_admin/v1/blocklist/credstuff`;

  let mode: PushMode = deps.initialMode ?? 'shadow';
  let version = 0;
  let last: PushResult | null = null;
  const pushTotals: Record<PushResult['status'], number> = {
    shadow: 0,
    ok: 0,
    stale_version: 0,
    error: 0,
    noop: 0,
  };

  function record(result: PushResult): PushResult {
    last = result;
    pushTotals[result.status] += 1;
    return result;
  }

  function buildEntries(candidates: readonly BlocklistCandidate[]): Array<{
    ip: string;
    expires_at: string;
    reason: string;
  }> {
    return candidates.map((c) => ({
      ip: c.ip,
      // expires_at est UNIX seconds côté store ; on convertit en RFC 3339
      // UTC tel qu'attendu par adminapi/blocklist.go (time.RFC3339).
      expires_at: new Date(c.expiresAtSec * 1000).toISOString(),
      // reason: jointure stable des heuristiques déclenchantes pour debug.
      reason: c.reasons.join('|'),
    }));
  }

  async function push(): Promise<PushResult> {
    const state = deps.store.state();
    version += 1;
    const at = now();
    const candidates = state.candidates.length;

    if (mode === 'shadow') {
      const result: PushResult = {
        at,
        mode,
        candidates,
        version,
        pushed: false,
        status: 'shadow',
      };
      record(result);
      deps.logger?.info({ msg: 'behavioral.credstuff push shadow', candidates, version });
      return result;
    }

    // enforce : PUT au data plane.
    const payload = {
      version,
      entries: buildEntries(state.candidates),
    };
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (deps.proxyAdminToken !== undefined && deps.proxyAdminToken !== '') {
        headers['authorization'] = `Bearer ${deps.proxyAdminToken}`;
      }
      const res = await fetchImpl(url, {
        method: 'PUT',
        headers,
        body: JSON.stringify(payload),
        signal: ctrl.signal,
      });
      if (res.ok) {
        const result: PushResult = {
          at,
          mode,
          candidates,
          version,
          pushed: true,
          status: 'ok',
        };
        record(result);
        deps.logger?.info({ msg: 'behavioral.credstuff push ok', candidates, version });
        return result;
      }
      const detail = await safeText(res);
      const status: PushResult['status'] = res.status === 409 ? 'stale_version' : 'error';
      const result: PushResult = {
        at,
        mode,
        candidates,
        version,
        pushed: false,
        status,
        error: `proxy ${res.status}: ${detail}`,
      };
      record(result);
      deps.logger?.error({
        msg: 'behavioral.credstuff push rejected',
        proxyStatus: res.status,
        version,
      });
      return result;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      const result: PushResult = {
        at,
        mode,
        candidates,
        version,
        pushed: false,
        status: 'error',
        error: msg.slice(0, 256),
      };
      record(result);
      deps.logger?.error({ msg: 'behavioral.credstuff push failed', err: msg, version });
      return result;
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    push,
    lastResult: () => last,
    mode: () => mode,
    setMode: (m: PushMode) => {
      if (m !== mode) {
        deps.logger?.warn({ msg: 'behavioral.credstuff mode change', from: mode, to: m });
        mode = m;
      }
    },
    metrics: () => ({
      pushTotals: { ...pushTotals },
      mode,
      lastVersion: last?.version ?? 0,
      lastAtMs: last?.at ?? 0,
      lastPushed: last?.pushed ? 1 : 0,
      lastCandidates: last?.candidates ?? 0,
    }),
  };
}

async function safeText(r: Response): Promise<string> {
  try {
    return (await r.text()).slice(0, 256);
  } catch {
    return '';
  }
}

// --------------------------------------------------------------------
// Routes Fastify.
// --------------------------------------------------------------------

const ModeSchema = Type.Union([Type.Literal('shadow'), Type.Literal('enforce')]);

const PushResultSchema = Type.Object(
  {
    at: Type.Integer({ minimum: 0 }),
    mode: ModeSchema,
    candidates: Type.Integer({ minimum: 0 }),
    version: Type.Integer({ minimum: 0 }),
    pushed: Type.Boolean(),
    status: Type.Union([
      Type.Literal('shadow'),
      Type.Literal('ok'),
      Type.Literal('stale_version'),
      Type.Literal('error'),
      Type.Literal('noop'),
    ]),
    error: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);

const SetModeBodySchema = Type.Object(
  {
    mode: ModeSchema,
  },
  { additionalProperties: false },
);

const SetModeResponseSchema = Type.Object(
  {
    mode: ModeSchema,
  },
  { additionalProperties: false },
);

export function registerBehavioralCredStuffPushRoutes(
  app: FastifyInstance,
  pusher: BehavioralCredStuffPusher,
): void {
  // POST /v1/behavioral/credstuff/push — déclenche un push.
  app.route({
    method: 'POST',
    url: '/v1/behavioral/credstuff/push',
    schema: {
      response: {
        200: PushResultSchema,
      },
    },
    handler: async () => {
      return pusher.push();
    },
  });

  // GET /v1/behavioral/credstuff/push — dernier résultat (404 si jamais poussé).
  app.route({
    method: 'GET',
    url: '/v1/behavioral/credstuff/push',
    schema: {
      response: {
        200: PushResultSchema,
        404: Type.Object(
          { error: Type.Literal('no_push_yet'), mode: ModeSchema },
          { additionalProperties: false },
        ),
      },
    },
    handler: async (_req, reply) => {
      const last = pusher.lastResult();
      if (last === null) {
        reply.code(404);
        return { error: 'no_push_yet' as const, mode: pusher.mode() };
      }
      return last;
    },
  });

  // POST /v1/behavioral/credstuff/push/mode — change le mode (shadow|enforce).
  app.route({
    method: 'POST',
    url: '/v1/behavioral/credstuff/push/mode',
    schema: {
      body: SetModeBodySchema,
      response: {
        200: SetModeResponseSchema,
      },
    },
    handler: async (req) => {
      const body = req.body as { mode: PushMode };
      pusher.setMode(body.mode);
      return { mode: pusher.mode() };
    },
  });

  // GET /v1/behavioral/credstuff/push/mode — lecture du mode.
  app.route({
    method: 'GET',
    url: '/v1/behavioral/credstuff/push/mode',
    schema: {
      response: {
        200: SetModeResponseSchema,
      },
    },
    handler: async () => {
      return { mode: pusher.mode() };
    },
  });
}
