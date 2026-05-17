import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params hash-flood. Aligné avec
 * configs/schemas/hashflood.schema.json et
 * proxy/mitigations/hashflood/hashflood.go.
 */
export const HashFloodParamsSchema = Type.Object(
  {
    max_query_params: Type.Integer({ minimum: 1, maximum: 10_000 }),
  },
  { additionalProperties: false },
);
export type HashFloodParams = Static<typeof HashFloodParamsSchema>;

/**
 * Règle de la famille "hash-flood". MVP : seul l'id "hash-flood"
 * (plafond du nombre de paramètres dans la query string).
 *
 * Défaut on_error="allow" (fail-open AGENTS.md §3) : la map Go étant
 * immunisée contre les collisions algorithmiques, le pire cas sur
 * erreur du compteur reste O(n) parsing — déjà accepté en temps normal.
 */
export const HashFloodRuleSchema = Type.Object(
  {
    id: Type.Literal('hash-flood'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: HashFloodParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type HashFloodRule = Static<typeof HashFloodRuleSchema>;

export interface HashFloodStore {
  get(id: string): HashFloodRule | undefined;
  put(rule: HashFloodRule): { rev: number };
  list(): { rev: number; rules: HashFloodRule[] };
}

export function createInMemoryHashFloodStore(): HashFloodStore {
  let rev = 0;
  const rules = new Map<string, HashFloodRule>();
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

/**
 * Enregistre les routes /v1/mitigations/hash-flood sur app.
 *
 *   GET  /v1/mitigations/hash-flood         → snapshot
 *   PUT  /v1/mitigations/hash-flood/:id     → upsert avec validation
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerHashFloodRoutes(app: FastifyInstance, store: HashFloodStore): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/hash-flood',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(HashFloodRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/hash-flood/:id',
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
            rule: HashFloodRuleSchema,
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
      if (!Value.Check(HashFloodRuleSchema, body)) {
        const details = [...Value.Errors(HashFloodRuleSchema, body)].map(
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
