import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params range-amp. Aligné avec
 * configs/schemas/rangeamp.schema.json et
 * proxy/mitigations/rangeamp/rangeamp.go.
 */
export const RangeAmpParamsSchema = Type.Object(
  {
    max_ranges: Type.Integer({ minimum: 1, maximum: 1_000 }),
  },
  { additionalProperties: false },
);
export type RangeAmpParams = Static<typeof RangeAmpParamsSchema>;

/**
 * Règle de la famille "range-amp" (CVE-2011-3192 Apache Killer).
 *
 * Défaut on_error="allow" (fail-open AGENTS.md §3) : le compteur de
 * ranges est un simple strings.Count sur un header court, tout échec
 * impliquerait un bug stdlib.
 */
export const RangeAmpRuleSchema = Type.Object(
  {
    id: Type.Literal('range-amp'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: RangeAmpParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type RangeAmpRule = Static<typeof RangeAmpRuleSchema>;

export interface RangeAmpStore {
  get(id: string): RangeAmpRule | undefined;
  put(rule: RangeAmpRule): { rev: number };
  list(): { rev: number; rules: RangeAmpRule[] };
}

export function createInMemoryRangeAmpStore(): RangeAmpStore {
  let rev = 0;
  const rules = new Map<string, RangeAmpRule>();
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
 * Enregistre les routes /v1/mitigations/range-amp sur app.
 *
 *   GET  /v1/mitigations/range-amp         → snapshot
 *   PUT  /v1/mitigations/range-amp/:id     → upsert avec validation
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerRangeAmpRoutes(app: FastifyInstance, store: RangeAmpStore): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/range-amp',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(RangeAmpRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/range-amp/:id',
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
            rule: RangeAmpRuleSchema,
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
      if (!Value.Check(RangeAmpRuleSchema, body)) {
        const details = [...Value.Errors(RangeAmpRuleSchema, body)].map(
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
