import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params http-flood-l7. Doit rester aligné avec
 * configs/schemas/ratelimit.schema.json (httpFloodParams) et
 * proxy/mitigations/httpflood/httpflood.go (Config).
 */
export const HTTPFloodParamsSchema = Type.Object(
  {
    requests_per_second: Type.Number({ exclusiveMinimum: 0, maximum: 1_000_000 }),
    burst: Type.Integer({ minimum: 1, maximum: 100_000 }),
  },
  { additionalProperties: false },
);
export type HTTPFloodParams = Static<typeof HTTPFloodParamsSchema>;

/**
 * Règle de la famille "ratelimit". Pour MVP : seul l'id
 * "http-flood-l7" est connu.
 *
 * Le défaut on_error="deny" reflète la décision ADR 0003 (fail-closed).
 */
export const RatelimitRuleSchema = Type.Object(
  {
    id: Type.Literal('http-flood-l7'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: HTTPFloodParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type RatelimitRule = Static<typeof RatelimitRuleSchema>;

export interface RatelimitStore {
  get(id: string): RatelimitRule | undefined;
  put(rule: RatelimitRule): { rev: number };
  list(): { rev: number; rules: RatelimitRule[] };
}

export function createInMemoryRatelimitStore(): RatelimitStore {
  let rev = 0;
  const rules = new Map<string, RatelimitRule>();
  return {
    get: (id) => rules.get(id),
    put: (rule) => {
      // Fail-closed : enabled=false sans reason → invalide.
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
 * Enregistre les routes /v1/mitigations/ratelimit sur app.
 *
 * Routes :
 *   GET  /v1/mitigations/ratelimit         → snapshot complet
 *   PUT  /v1/mitigations/ratelimit/:id     → upsert + dry-run validation
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerRatelimitRoutes(app: FastifyInstance, store: RatelimitStore): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/ratelimit',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(RatelimitRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/ratelimit/:id',
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
            rule: RatelimitRuleSchema,
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
      if (!Value.Check(RatelimitRuleSchema, body)) {
        const details = [...Value.Errors(RatelimitRuleSchema, body)].map(
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
