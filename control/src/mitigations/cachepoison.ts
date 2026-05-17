import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params cache-poison. Aligné avec
 * configs/schemas/cachepoison.schema.json et
 * proxy/mitigations/cachepoison/cachepoison.go.
 */
export const CachePoisonParamsSchema = Type.Object(
  {
    headers: Type.Array(
      Type.String({
        minLength: 1,
        maxLength: 128,
        // RFC 9110 token grammar (ABNF) : "!#$%&'*+-.^_`|~" + alphanum.
        pattern: "^[A-Za-z0-9!#$%&'*+\\-.^_`|~]+$",
      }),
      { minItems: 1, maxItems: 64 },
    ),
  },
  { additionalProperties: false },
);
export type CachePoisonParams = Static<typeof CachePoisonParamsSchema>;

/**
 * Règle de la famille "cache-poison".
 *
 * Référence : J. Kettle, "Practical Web Cache Poisoning" (Black Hat
 * USA 2018). Liste de request-headers "unkeyed" à retirer (action=
 * "strip", défaut) ou à rejeter en 400 (action="deny") avant forward
 * upstream.
 */
export const CachePoisonRuleSchema = Type.Object(
  {
    id: Type.Literal('cache-poison'),
    enabled: Type.Boolean(),
    action: Type.Union([Type.Literal('strip'), Type.Literal('deny')]),
    params: CachePoisonParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type CachePoisonRule = Static<typeof CachePoisonRuleSchema>;

export interface CachePoisonStore {
  get(id: string): CachePoisonRule | undefined;
  put(rule: CachePoisonRule): { rev: number };
  list(): { rev: number; rules: CachePoisonRule[] };
}

export function createInMemoryCachePoisonStore(): CachePoisonStore {
  let rev = 0;
  const rules = new Map<string, CachePoisonRule>();
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
 * Enregistre les routes /v1/mitigations/cache-poison sur app.
 *
 *   GET  /v1/mitigations/cache-poison         → snapshot
 *   PUT  /v1/mitigations/cache-poison/:id     → upsert avec validation
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerCachePoisonRoutes(
  app: FastifyInstance,
  store: CachePoisonStore,
): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/cache-poison',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(CachePoisonRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/cache-poison/:id',
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
            rule: CachePoisonRuleSchema,
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
      if (!Value.Check(CachePoisonRuleSchema, body)) {
        const details = [...Value.Errors(CachePoisonRuleSchema, body)].map(
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
