import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params Slowloris. Doit rester aligné avec
 * configs/schemas/connections.schema.json (slowlorisParams).
 */
export const SlowlorisParamsSchema = Type.Object(
  {
    max_conns_per_ip: Type.Integer({ minimum: 1, maximum: 100_000 }),
  },
  { additionalProperties: false },
);
export type SlowlorisParams = Static<typeof SlowlorisParamsSchema>;

/**
 * Schéma d'une règle au niveau famille "connections".
 * Pour MVP : seul l'id "slowloris" est connu.
 */
export const ConnectionsRuleSchema = Type.Object(
  {
    id: Type.Literal('slowloris'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: SlowlorisParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type ConnectionsRule = Static<typeof ConnectionsRuleSchema>;

/**
 * Stockage en mémoire MVP (versionné). La persistance et le push au
 * data plane via POST /v1/reload arriveront plus tard.
 */
export interface ConnectionsStore {
  get(id: string): ConnectionsRule | undefined;
  put(rule: ConnectionsRule): { rev: number };
  list(): { rev: number; rules: ConnectionsRule[] };
}

export function createInMemoryStore(): ConnectionsStore {
  let rev = 0;
  const rules = new Map<string, ConnectionsRule>();
  return {
    get: (id) => rules.get(id),
    put: (rule) => {
      // Refus fail-closed : enabled=false sans reason → invalide.
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

/**
 * Enregistre les routes /v1/mitigations/connections sur app.
 *
 * Routes :
 *   GET  /v1/mitigations/connections          → snapshot complet
 *   PUT  /v1/mitigations/connections/:id      → upsert + dry-run validation
 *
 * Hot-reload : la modification est validée et stockée ; un appel
 * ultérieur à POST /v1/reload poussera l'état au data plane (à
 * implémenter avec un client HTTP vers le proxy).
 */
export function registerConnectionsRoutes(
  app: FastifyInstance,
  store: ConnectionsStore,
): void {
  // GET snapshot.
  app.route({
    method: 'GET',
    url: '/v1/mitigations/connections',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(ConnectionsRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  // PUT upsert.
  app.route({
    method: 'PUT',
    url: '/v1/mitigations/connections/:id',
    schema: {
      params: Type.Object(
        { id: Type.String({ minLength: 1, maxLength: 64 }) },
        { additionalProperties: false },
      ),
      response: {
        200: Type.Object(
          {
            status: Type.Literal('ok'),
            rev: Type.Integer({ minimum: 1 }),
            rule: ConnectionsRuleSchema,
          },
          { additionalProperties: false },
        ),
        400: Type.Object(
          {
            error: Type.Union([
              Type.Literal('id_mismatch'),
              Type.Literal('invalid_rule'),
              Type.Literal('disabled_without_reason'),
            ]),
            details: Type.Array(Type.String()),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async (
      req: FastifyRequest<{ Params: { id: string }; Body: unknown }>,
      reply: FastifyReply,
    ) => {
      const body = req.body;
      if (!Value.Check(ConnectionsRuleSchema, body)) {
        const details = [...Value.Errors(ConnectionsRuleSchema, body)].map(
          (e) => `${e.path} ${e.message}`,
        );
        reply.code(400);
        return { error: 'invalid_rule' as const, details };
      }
      if (body.id !== req.params.id) {
        reply.code(400);
        return {
          error: 'id_mismatch' as const,
          details: [`url id=${req.params.id} body id=${body.id}`],
        };
      }
      try {
        const { rev } = store.put(body);
        return { status: 'ok' as const, rev, rule: body };
      } catch (err) {
        reply.code(400);
        const msg = err instanceof Error ? err.message : String(err);
        return { error: 'disabled_without_reason' as const, details: [msg] };
      }
    },
  });
}
