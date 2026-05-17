import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Couche behavioral credential-stuffing (ADR 0004) — Phase 3.
 *
 * Reçoit les événements d'authentification depuis l'upstream applicatif
 * via POST /v1/behavioral/credstuff/auth-event(s) et calcule un set
 * d'IPs candidates à blocklist selon trois heuristiques sur fenêtre
 * glissante (10 min par défaut) :
 *
 *   1. failed_logins per username_hash > maxFailedLoginsPerUser
 *   2. distinct source_ips per username_hash > maxDistinctIPsPerUser
 *   3. failed_logins per source_ip > maxFailedLoginsPerIP
 *
 * Cette phase n'effectue **aucun push** vers le data plane : elle
 * expose juste l'état candidat. Le push (Phase 4) lira ce store.
 *
 * Privacy : `username_hash` doit déjà être SHA-256 salé côté upstream
 * (64 caractères hex). On ne reçoit ni ne log jamais le username clair.
 *
 * Pas de PII brute dans les logs : `source_ip` est conservée en clair
 * pour la mitigation mais n'apparaît pas dans les logs Fastify (logger
 * config en JSON, niveau info par défaut).
 *
 * Cf. docs/adr/0004-credstuff-behavioral.md
 */

// ---------------------------------------------------------------------
// Schémas TypeBox.
// ---------------------------------------------------------------------

/** Un événement d'authentification. */
export const AuthEventSchema = Type.Object(
  {
    /** SHA-256 salé hex (64 chars). Aucune vérification de salt côté contrôle. */
    username_hash: Type.String({ minLength: 64, maxLength: 64, pattern: '^[0-9a-f]{64}$' }),
    /** Succès du login. Seuls les échecs comptent dans les heuristiques. */
    success: Type.Boolean(),
    /** IPv4 ou IPv6 littérale. */
    source_ip: Type.String({ minLength: 3, maxLength: 45 }),
    /** Timestamp UNIX en secondes (entier). */
    ts: Type.Integer({ minimum: 0 }),
    /** Optionnel, tronqué à 256 chars. Non utilisé dans les heuristiques mais journalisé. */
    user_agent: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type AuthEvent = Static<typeof AuthEventSchema>;

const BatchSchema = Type.Object(
  {
    events: Type.Array(AuthEventSchema, { minItems: 1, maxItems: 100 }),
  },
  { additionalProperties: false },
);

// ---------------------------------------------------------------------
// Configuration des heuristiques.
// ---------------------------------------------------------------------

export interface BehavioralThresholds {
  /** Largeur de fenêtre glissante en ms. Défaut 10 min. */
  windowMs: number;
  /** Heuristique 1 : nb d'échecs par username_hash. Défaut 20. */
  maxFailedLoginsPerUser: number;
  /** Heuristique 2 : nb d'IPs distinctes par username_hash. Défaut 5. */
  maxDistinctIPsPerUser: number;
  /** Heuristique 3 : nb d'échecs par source_ip. Défaut 50. */
  maxFailedLoginsPerIP: number;
  /** Cap dur sur le nombre de clés trackées (anti-DoS sur l'ingestion). Défaut 100_000. */
  maxTrackedKeys: number;
  /** Cap d'événements par clé (FIFO). Défaut 200. */
  maxEventsPerKey: number;
  /** Durée par défaut d'une entrée de blocklist quand un candidat est produit. Défaut 1h en secondes. */
  candidateTTLSeconds: number;
}

export const DEFAULT_THRESHOLDS: BehavioralThresholds = {
  windowMs: 10 * 60 * 1000,
  maxFailedLoginsPerUser: 20,
  maxDistinctIPsPerUser: 5,
  maxFailedLoginsPerIP: 50,
  maxTrackedKeys: 100_000,
  maxEventsPerKey: 200,
  candidateTTLSeconds: 3600,
};

// ---------------------------------------------------------------------
// État interne + store.
// ---------------------------------------------------------------------

interface StoredEvent {
  ts: number; // ms (now()-based)
  ip: string;
  user: string;
}

/** IP candidate à blocklist, dérivée des heuristiques. */
export interface BlocklistCandidate {
  ip: string;
  /** Raison de l'inscription (au moins une heuristique a déclenché). */
  reasons: Array<'failed_per_user' | 'distinct_ips_per_user' | 'failed_per_ip'>;
  /** Dernier événement vu pour cette IP (ms epoch). */
  lastSeenMs: number;
  /** Expiration suggérée pour la blocklist (s epoch). */
  expiresAtSec: number;
}

export interface BehavioralCredStuffState {
  /** Version monotone : incrémentée à chaque mutation. */
  version: number;
  /** Snapshot du moment du calcul (ms epoch). */
  computedAtMs: number;
  /** Liste candidate, ordonnée par lastSeenMs DESC. */
  candidates: BlocklistCandidate[];
  /** Nb de username_hash actuellement trackés. */
  trackedUsers: number;
  /** Nb d'IPs actuellement trackées. */
  trackedIPs: number;
  /** Compteurs cumulés depuis le boot. */
  totals: {
    ingested: number;
    accepted: number;
    rejected: number;
  };
}

export interface BehavioralCredStuffStore {
  ingest(event: AuthEvent): void;
  state(): BehavioralCredStuffState;
  /** Réinitialise toutes les fenêtres. Conserve version (incrément). */
  reset(): void;
}

interface StoreDeps {
  now: () => number; // ms
  thresholds?: Partial<BehavioralThresholds>;
}

export function createInMemoryBehavioralCredStuffStore(
  deps: StoreDeps,
): BehavioralCredStuffStore {
  const t: BehavioralThresholds = { ...DEFAULT_THRESHOLDS, ...deps.thresholds };
  const byUser = new Map<string, StoredEvent[]>();
  const byIP = new Map<string, StoredEvent[]>();
  let version = 0;
  let ingested = 0;
  let accepted = 0;
  let rejected = 0;

  function trim(list: StoredEvent[], cutoff: number): StoredEvent[] {
    // Les événements arrivent globalement dans l'ordre temporel ;
    // un linear-scan from-start est O(N) au pire mais le tableau est
    // cap-borné à maxEventsPerKey. Aucune allocation si rien à drop.
    let i = 0;
    while (i < list.length) {
      const ev = list[i];
      if (ev === undefined || ev.ts >= cutoff) break;
      i++;
    }
    return i === 0 ? list : list.slice(i);
  }

  function pushBounded(list: StoredEvent[] | undefined, ev: StoredEvent): StoredEvent[] {
    const arr = list ?? [];
    arr.push(ev);
    if (arr.length > t.maxEventsPerKey) {
      arr.shift(); // FIFO drop du plus vieux
    }
    return arr;
  }

  return {
    ingest(event: AuthEvent): void {
      ingested++;
      // Échecs uniquement : un login réussi n'alimente pas les heuristiques.
      if (event.success) {
        accepted++;
        return;
      }
      const nowMs = deps.now();
      const evTs = event.ts * 1000;
      // Reject les événements trop vieux (hors fenêtre) ou venant
      // du futur (> 5 min de skew) — anti-bidouillage du timestamp.
      if (evTs < nowMs - t.windowMs || evTs > nowMs + 5 * 60_000) {
        rejected++;
        return;
      }
      // Cap dur : si on dépasse, drop silencieux (en pratique le
      // control plane se logue mais on évite la croissance non bornée).
      if (
        !byUser.has(event.username_hash) &&
        byUser.size >= t.maxTrackedKeys
      ) {
        rejected++;
        return;
      }
      if (!byIP.has(event.source_ip) && byIP.size >= t.maxTrackedKeys) {
        rejected++;
        return;
      }
      const stored: StoredEvent = {
        ts: evTs,
        ip: event.source_ip,
        user: event.username_hash,
      };
      byUser.set(event.username_hash, pushBounded(byUser.get(event.username_hash), stored));
      byIP.set(event.source_ip, pushBounded(byIP.get(event.source_ip), stored));
      accepted++;
      version++;
    },

    state(): BehavioralCredStuffState {
      const nowMs = deps.now();
      const cutoff = nowMs - t.windowMs;

      // Trim & GC des clés vides.
      for (const [key, list] of byUser) {
        const next = trim(list, cutoff);
        if (next.length === 0) byUser.delete(key);
        else if (next !== list) byUser.set(key, next);
      }
      for (const [key, list] of byIP) {
        const next = trim(list, cutoff);
        if (next.length === 0) byIP.delete(key);
        else if (next !== list) byIP.set(key, next);
      }

      // Collecte des candidats.
      type Acc = { reasons: Set<BlocklistCandidate['reasons'][number]>; lastSeenMs: number };
      const acc = new Map<string, Acc>();

      const touch = (
        ip: string,
        reason: BlocklistCandidate['reasons'][number],
        lastSeenMs: number,
      ): void => {
        const cur = acc.get(ip);
        if (cur === undefined) {
          acc.set(ip, { reasons: new Set([reason]), lastSeenMs });
        } else {
          cur.reasons.add(reason);
          if (lastSeenMs > cur.lastSeenMs) cur.lastSeenMs = lastSeenMs;
        }
      };

      // Heuristique 1 & 2 : per-user.
      for (const list of byUser.values()) {
        if (list.length === 0) continue;
        const ips = new Set<string>();
        let lastSeen = 0;
        for (const ev of list) {
          ips.add(ev.ip);
          if (ev.ts > lastSeen) lastSeen = ev.ts;
        }
        const heur1 = list.length > t.maxFailedLoginsPerUser;
        const heur2 = ips.size > t.maxDistinctIPsPerUser;
        if (heur1 || heur2) {
          for (const ev of list) {
            if (heur1) touch(ev.ip, 'failed_per_user', ev.ts);
            if (heur2) touch(ev.ip, 'distinct_ips_per_user', ev.ts);
            if (ev.ts > lastSeen) lastSeen = ev.ts;
          }
        }
      }

      // Heuristique 3 : per-IP.
      for (const [ip, list] of byIP) {
        if (list.length > t.maxFailedLoginsPerIP) {
          let lastSeen = 0;
          for (const ev of list) if (ev.ts > lastSeen) lastSeen = ev.ts;
          touch(ip, 'failed_per_ip', lastSeen);
        }
      }

      const candidates: BlocklistCandidate[] = [];
      for (const [ip, v] of acc) {
        candidates.push({
          ip,
          reasons: [...v.reasons].sort(),
          lastSeenMs: v.lastSeenMs,
          expiresAtSec: Math.floor(v.lastSeenMs / 1000) + t.candidateTTLSeconds,
        });
      }
      candidates.sort((a, b) => b.lastSeenMs - a.lastSeenMs);

      return {
        version,
        computedAtMs: nowMs,
        candidates,
        trackedUsers: byUser.size,
        trackedIPs: byIP.size,
        totals: { ingested, accepted, rejected },
      };
    },

    reset(): void {
      byUser.clear();
      byIP.clear();
      version++;
    },
  };
}

// ---------------------------------------------------------------------
// Routes Fastify.
// ---------------------------------------------------------------------

const BlocklistCandidateSchema = Type.Object(
  {
    ip: Type.String(),
    reasons: Type.Array(
      Type.Union([
        Type.Literal('failed_per_user'),
        Type.Literal('distinct_ips_per_user'),
        Type.Literal('failed_per_ip'),
      ]),
    ),
    lastSeenMs: Type.Integer({ minimum: 0 }),
    expiresAtSec: Type.Integer({ minimum: 0 }),
  },
  { additionalProperties: false },
);

const StateSchema = Type.Object(
  {
    version: Type.Integer({ minimum: 0 }),
    computedAtMs: Type.Integer({ minimum: 0 }),
    candidates: Type.Array(BlocklistCandidateSchema),
    trackedUsers: Type.Integer({ minimum: 0 }),
    trackedIPs: Type.Integer({ minimum: 0 }),
    totals: Type.Object(
      {
        ingested: Type.Integer({ minimum: 0 }),
        accepted: Type.Integer({ minimum: 0 }),
        rejected: Type.Integer({ minimum: 0 }),
      },
      { additionalProperties: false },
    ),
  },
  { additionalProperties: false },
);

export function registerBehavioralCredStuffRoutes(
  app: FastifyInstance,
  store: BehavioralCredStuffStore,
): void {
  // ---- POST /v1/behavioral/credstuff/auth-event ----
  app.route({
    method: 'POST',
    url: '/v1/behavioral/credstuff/auth-event',
    schema: {
      response: {
        202: Type.Object(
          { status: Type.Literal('accepted'), version: Type.Integer({ minimum: 0 }) },
          { additionalProperties: false },
        ),
        400: Type.Object(
          {
            error: Type.Literal('invalid_event'),
            details: Type.Array(Type.String()),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async (req: FastifyRequest<{ Body: unknown }>, reply: FastifyReply) => {
      const body = req.body;
      if (!Value.Check(AuthEventSchema, body)) {
        const details = [...Value.Errors(AuthEventSchema, body)].map(
          (e) => `${e.path} ${e.message}`,
        );
        reply.code(400);
        return { error: 'invalid_event' as const, details };
      }
      store.ingest(body);
      reply.code(202);
      return { status: 'accepted' as const, version: store.state().version };
    },
  });

  // ---- POST /v1/behavioral/credstuff/auth-events  (batch) ----
  app.route({
    method: 'POST',
    url: '/v1/behavioral/credstuff/auth-events',
    schema: {
      response: {
        202: Type.Object(
          {
            status: Type.Literal('accepted'),
            ingested: Type.Integer({ minimum: 0 }),
            version: Type.Integer({ minimum: 0 }),
          },
          { additionalProperties: false },
        ),
        400: Type.Object(
          {
            error: Type.Literal('invalid_batch'),
            details: Type.Array(Type.String()),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async (req: FastifyRequest<{ Body: unknown }>, reply: FastifyReply) => {
      const body = req.body;
      if (!Value.Check(BatchSchema, body)) {
        const details = [...Value.Errors(BatchSchema, body)].map(
          (e) => `${e.path} ${e.message}`,
        );
        reply.code(400);
        return { error: 'invalid_batch' as const, details };
      }
      for (const ev of body.events) store.ingest(ev);
      reply.code(202);
      return {
        status: 'accepted' as const,
        ingested: body.events.length,
        version: store.state().version,
      };
    },
  });

  // ---- GET /v1/behavioral/credstuff/state ----
  app.route({
    method: 'GET',
    url: '/v1/behavioral/credstuff/state',
    schema: {
      response: {
        200: StateSchema,
      },
    },
    handler: async () => store.state(),
  });

  // ---- DELETE /v1/behavioral/credstuff/state ----
  app.route({
    method: 'DELETE',
    url: '/v1/behavioral/credstuff/state',
    schema: {
      response: {
        200: Type.Object(
          { status: Type.Literal('reset'), version: Type.Integer({ minimum: 0 }) },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => {
      store.reset();
      return { status: 'reset' as const, version: store.state().version };
    },
  });
}
