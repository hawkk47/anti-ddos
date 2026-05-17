import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params large-header. Aligné avec
 * configs/schemas/headers.schema.json et
 * proxy/mitigations/largeheader/largeheader.go.
 */
export const LargeHeaderParamsSchema = Type.Object(
  {
    max_header_count: Type.Integer({ minimum: 1, maximum: 10_000 }),
    max_value_bytes: Type.Integer({ minimum: 1, maximum: 16 * 1024 * 1024 }),
  },
  { additionalProperties: false },
);
export type LargeHeaderParams = Static<typeof LargeHeaderParamsSchema>;

/**
 * Règle de la famille "headers". MVP : seul l'id "large-header".
 *
 * Défaut on_error="allow" (fail-open AGENTS.md §3).
 */
export const HeadersRuleSchema = Type.Object(
  {
    id: Type.Literal('large-header'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: LargeHeaderParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type HeadersRule = Static<typeof HeadersRuleSchema>;

export interface HeadersStore {
  get(id: string): HeadersRule | undefined;
  put(rule: HeadersRule): { rev: number };
  list(): { rev: number; rules: HeadersRule[] };
}

export function createInMemoryHeadersStore(): HeadersStore {
  let rev = 0;
  const rules = new Map<string, HeadersRule>();
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
 * Enregistre les routes /v1/mitigations/headers sur app.
 *
 *   GET  /v1/mitigations/headers         → snapshot
 *   PUT  /v1/mitigations/headers/:id     → upsert avec validation
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerHeadersRoutes(app: FastifyInstance, store: HeadersStore): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/headers',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(HeadersRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/headers/:id',
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
            rule: HeadersRuleSchema,
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
      if (!Value.Check(HeadersRuleSchema, body)) {
        const details = [...Value.Errors(HeadersRuleSchema, body)].map(
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
