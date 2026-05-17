// Mitigations L3/L4 du control plane.
//
// Cinq familles avec le même cycle de vie (GET snapshot / PUT upsert)
// factorisées via une seule fabrique générique. Chaque famille
// définit son schéma TypeBox propre et un `id` littéral unique.
//
// Pour le push au data plane, voir control/src/app.ts (POST /v1/reload).
import { Type, type TSchema, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

// ---------------------------------------------------------------
// Schémas de paramètres
// ---------------------------------------------------------------

export const IPReputationParamsSchema = Type.Object(
  {
    allowlist: Type.Array(Type.String({ minLength: 1, maxLength: 64 })),
    allowlist_strict: Type.Optional(Type.Boolean()),
    blocklist: Type.Array(Type.String({ minLength: 1, maxLength: 64 })),
    max_dynamic_entries: Type.Integer({ minimum: 0, maximum: 10_000_000 }),
    default_block_ttl_ms: Type.Integer({ minimum: 0, maximum: 86_400_000 }),
  },
  { additionalProperties: false },
);

export const ConnFloodParamsSchema = Type.Object(
  {
    max_conns_per_ip: Type.Integer({ minimum: 0, maximum: 1_000_000 }),
    max_conns_per_subnet: Type.Optional(Type.Integer({ minimum: 0, maximum: 10_000_000 })),
  },
  { additionalProperties: false },
);

export const SynFloodParamsSchema = Type.Object(
  {
    accepts_per_second_per_ip: Type.Number({ minimum: 0, maximum: 1_000_000 }),
    burst_per_ip: Type.Integer({ minimum: 0, maximum: 1_000_000 }),
    accepts_per_second_per_subnet: Type.Optional(Type.Number({ minimum: 0, maximum: 10_000_000 })),
    burst_per_subnet: Type.Optional(Type.Integer({ minimum: 0, maximum: 10_000_000 })),
    report_ttl_ms: Type.Optional(Type.Integer({ minimum: 0, maximum: 86_400_000 })),
  },
  { additionalProperties: false },
);

export const HandshakeGuardParamsSchema = Type.Object(
  {
    handshake_window_ms: Type.Integer({ minimum: 100, maximum: 300_000 }),
    abandon_threshold: Type.Integer({ minimum: 1, maximum: 1_000_000 }),
    observe_window_ms: Type.Integer({ minimum: 1_000, maximum: 3_600_000 }),
    report_ttl_ms: Type.Optional(Type.Integer({ minimum: 0, maximum: 86_400_000 })),
  },
  { additionalProperties: false },
);

export const GeoBlockL4ParamsSchema = Type.Object(
  {
    allow: Type.Array(Type.String({ pattern: '^[A-Za-z]{2}$' }), { maxItems: 300 }),
    block: Type.Array(Type.String({ pattern: '^[A-Za-z]{2}$' }), { maxItems: 300 }),
  },
  { additionalProperties: false },
);

// ---------------------------------------------------------------
// Fabrique générique de famille
// ---------------------------------------------------------------

function makeRuleSchema<P extends TSchema, ID extends string>(id: ID, params: P) {
  return Type.Object(
    {
      id: Type.Literal(id),
      enabled: Type.Boolean(),
      on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
      params,
      notes: Type.Optional(Type.String({ maxLength: 1024 })),
      reason: Type.Optional(Type.String({ maxLength: 256 })),
    },
    { additionalProperties: false },
  );
}

export interface FamilyStore<R> {
  get(id: string): R | undefined;
  put(rule: R): { rev: number };
  list(): { rev: number; rules: R[] };
}

function createStore<R extends { id: string; enabled: boolean; reason?: string }>(): FamilyStore<R> {
  let rev = 0;
  const rules = new Map<string, R>();
  return {
    get: (id) => rules.get(id),
    put: (rule) => {
      if (!rule.enabled && (rule.reason === undefined || rule.reason.trim() === '')) {
        throw new Error('reason is required when enabled=false');
      }
      rules.set(rule.id, rule);
      rev += 1;
      return { rev };
    },
    list: () => ({ rev, rules: [...rules.values()] }),
  };
}

function registerFamily<R extends { id: string; enabled: boolean; reason?: string }>(
  app: FastifyInstance,
  baseUrl: string,
  ruleSchema: TSchema,
  store: FamilyStore<R>,
): void {
  app.route({
    method: 'GET',
    url: baseUrl,
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(ruleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: `${baseUrl}/:id`,
    schema: {
      params: Type.Object({ id: Type.String({ minLength: 1, maxLength: 64 }) }, { additionalProperties: false }),
    },
    handler: async (
      req: FastifyRequest<{ Params: { id: string }; Body: unknown }>,
      reply: FastifyReply,
    ) => {
      const body = req.body;
      if (!Value.Check(ruleSchema, body)) {
        const details = [...Value.Errors(ruleSchema, body)].map((e) => `${e.path} ${e.message}`);
        reply.code(400);
        return { error: 'invalid_rule' as const, details };
      }
      const r = body as R;
      if (r.id !== req.params.id) {
        reply.code(400);
        return { error: 'id_mismatch' as const, details: [`url id=${req.params.id} body id=${r.id}`] };
      }
      try {
        const { rev } = store.put(r);
        return { status: 'ok' as const, rev, rule: r };
      } catch (err) {
        reply.code(400);
        const msg = err instanceof Error ? err.message : String(err);
        return { error: 'disabled_without_reason' as const, details: [msg] };
      }
    },
  });
}

// ---------------------------------------------------------------
// Types publics
// ---------------------------------------------------------------

export const IPReputationRuleSchema = makeRuleSchema('ip-reputation', IPReputationParamsSchema);
export type IPReputationRule = Static<typeof IPReputationRuleSchema>;
export type IPReputationStore = FamilyStore<IPReputationRule>;
export const createInMemoryIPReputationStore = (): IPReputationStore => createStore<IPReputationRule>();

export const ConnFloodRuleSchema = makeRuleSchema('conn-flood', ConnFloodParamsSchema);
export type ConnFloodRule = Static<typeof ConnFloodRuleSchema>;
export type ConnFloodStore = FamilyStore<ConnFloodRule>;
export const createInMemoryConnFloodStore = (): ConnFloodStore => createStore<ConnFloodRule>();

export const SynFloodRuleSchema = makeRuleSchema('syn-flood', SynFloodParamsSchema);
export type SynFloodRule = Static<typeof SynFloodRuleSchema>;
export type SynFloodStore = FamilyStore<SynFloodRule>;
export const createInMemorySynFloodStore = (): SynFloodStore => createStore<SynFloodRule>();

export const HandshakeGuardRuleSchema = makeRuleSchema('handshake-guard', HandshakeGuardParamsSchema);
export type HandshakeGuardRule = Static<typeof HandshakeGuardRuleSchema>;
export type HandshakeGuardStore = FamilyStore<HandshakeGuardRule>;
export const createInMemoryHandshakeGuardStore = (): HandshakeGuardStore => createStore<HandshakeGuardRule>();

export const GeoBlockL4RuleSchema = makeRuleSchema('geoblock-l4', GeoBlockL4ParamsSchema);
export type GeoBlockL4Rule = Static<typeof GeoBlockL4RuleSchema>;
export type GeoBlockL4Store = FamilyStore<GeoBlockL4Rule>;
export const createInMemoryGeoBlockL4Store = (): GeoBlockL4Store => createStore<GeoBlockL4Rule>();

// ---------------------------------------------------------------
// Enregistrement des 5 routes
// ---------------------------------------------------------------

export function registerIPReputationRoutes(app: FastifyInstance, store: IPReputationStore): void {
  registerFamily(app, '/v1/mitigations/ip-reputation', IPReputationRuleSchema, store);
}
export function registerConnFloodRoutes(app: FastifyInstance, store: ConnFloodStore): void {
  registerFamily(app, '/v1/mitigations/conn-flood', ConnFloodRuleSchema, store);
}
export function registerSynFloodRoutes(app: FastifyInstance, store: SynFloodStore): void {
  registerFamily(app, '/v1/mitigations/syn-flood', SynFloodRuleSchema, store);
}
export function registerHandshakeGuardRoutes(app: FastifyInstance, store: HandshakeGuardStore): void {
  registerFamily(app, '/v1/mitigations/handshake-guard', HandshakeGuardRuleSchema, store);
}
export function registerGeoBlockL4Routes(app: FastifyInstance, store: GeoBlockL4Store): void {
  registerFamily(app, '/v1/mitigations/geoblock-l4', GeoBlockL4RuleSchema, store);
}
