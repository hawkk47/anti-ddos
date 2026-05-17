import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params concurrency-cap. Aligné avec
 * configs/schemas/concurrency.schema.json et
 * proxy/mitigations/concurrency/concurrency.go.
 */
export const ConcurrencyParamsSchema = Type.Object(
  {
    max_in_flight: Type.Integer({ minimum: 1, maximum: 1_000_000 }),
  },
  { additionalProperties: false },
);
export type ConcurrencyParams = Static<typeof ConcurrencyParamsSchema>;

/**
 * Règle de la famille "concurrency-cap". Plafond global d'in-flight
 * (load shedding / backpressure). 503 + Retry-After=1 quand atteint.
 *
 * Défaut on_error="allow" (fail-open AGENTS.md §3) : un cap cassé qui
 * rejette tout est pire que pas de cap.
 */
export const ConcurrencyRuleSchema = Type.Object(
  {
    id: Type.Literal('concurrency-cap'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: ConcurrencyParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type ConcurrencyRule = Static<typeof ConcurrencyRuleSchema>;

export interface ConcurrencyStore {
  get(id: string): ConcurrencyRule | undefined;
  put(rule: ConcurrencyRule): { rev: number };
  list(): { rev: number; rules: ConcurrencyRule[] };
}

export function createInMemoryConcurrencyStore(): ConcurrencyStore {
  let rev = 0;
  const rules = new Map<string, ConcurrencyRule>();
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
 * Enregistre les routes /v1/mitigations/concurrency-cap sur app.
 *
 *   GET  /v1/mitigations/concurrency-cap         → snapshot
 *   PUT  /v1/mitigations/concurrency-cap/:id     → upsert avec validation
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerConcurrencyRoutes(
  app: FastifyInstance,
  store: ConcurrencyStore,
): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/concurrency-cap',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(ConcurrencyRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/concurrency-cap/:id',
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
            rule: ConcurrencyRuleSchema,
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
      if (!Value.Check(ConcurrencyRuleSchema, body)) {
        const details = [...Value.Errors(ConcurrencyRuleSchema, body)].map(
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
