import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params slow-post. Aligné avec
 * configs/schemas/bodies.schema.json et
 * proxy/mitigations/slowpost/slowpost.go.
 */
export const SlowPostParamsSchema = Type.Object(
  {
    max_body_bytes: Type.Integer({ minimum: 1, maximum: 1_073_741_824 }),
    min_bytes_per_second: Type.Integer({ minimum: 1, maximum: 1_048_576 }),
    grace_period_ms: Type.Integer({ minimum: 0, maximum: 60_000 }),
  },
  { additionalProperties: false },
);
export type SlowPostParams = Static<typeof SlowPostParamsSchema>;

/**
 * Règle de la famille "bodies". MVP : seul l'id "slow-post".
 *
 * Défaut on_error="allow" (fail-open AGENTS.md §3).
 */
export const BodiesRuleSchema = Type.Object(
  {
    id: Type.Literal('slow-post'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: SlowPostParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type BodiesRule = Static<typeof BodiesRuleSchema>;

export interface BodiesStore {
  get(id: string): BodiesRule | undefined;
  put(rule: BodiesRule): { rev: number };
  list(): { rev: number; rules: BodiesRule[] };
}

export function createInMemoryBodiesStore(): BodiesStore {
  let rev = 0;
  const rules = new Map<string, BodiesRule>();
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
 * Enregistre les routes /v1/mitigations/bodies sur app.
 *
 *   GET  /v1/mitigations/bodies         → snapshot
 *   PUT  /v1/mitigations/bodies/:id     → upsert avec validation
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerBodiesRoutes(app: FastifyInstance, store: BodiesStore): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/bodies',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(BodiesRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/bodies/:id',
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
            rule: BodiesRuleSchema,
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
      if (!Value.Check(BodiesRuleSchema, body)) {
        const details = [...Value.Errors(BodiesRuleSchema, body)].map(
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
