import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params scraping-aggressif. Aligné avec
 * configs/schemas/scraping.schema.json et
 * proxy/mitigations/scraping/scraping.go.
 */
export const ScrapingParamsSchema = Type.Object(
  {
    user_agent_deny: Type.Optional(
      Type.Array(Type.String({ minLength: 1, maxLength: 128 }), {
        maxItems: 128,
      }),
    ),
    require_accept_language: Type.Optional(Type.Boolean()),
    require_accept_encoding: Type.Optional(Type.Boolean()),
  },
  { additionalProperties: false },
);
export type ScrapingParams = Static<typeof ScrapingParamsSchema>;

/**
 * Règle de la famille "scraping".
 *
 * Référence : signature-based bot detection. AVERTISSEMENT : un
 * scraper déterminé spoofe trivialement ces signaux. Filtre le bruit
 * de fond uniquement.
 */
export const ScrapingRuleSchema = Type.Object(
  {
    id: Type.Literal('scraping'),
    enabled: Type.Boolean(),
    action: Type.Union([Type.Literal('log'), Type.Literal('deny')]),
    params: ScrapingParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type ScrapingRule = Static<typeof ScrapingRuleSchema>;

export interface ScrapingStore {
  get(id: string): ScrapingRule | undefined;
  put(rule: ScrapingRule): { rev: number };
  list(): { rev: number; rules: ScrapingRule[] };
}

function hasAnySignal(params: ScrapingParams): boolean {
  return (
    (params.user_agent_deny !== undefined && params.user_agent_deny.length > 0) ||
    params.require_accept_language === true ||
    params.require_accept_encoding === true
  );
}

export function createInMemoryScrapingStore(): ScrapingStore {
  let rev = 0;
  const rules = new Map<string, ScrapingRule>();
  return {
    get: (id) => rules.get(id),
    put: (rule) => {
      if (!rule.enabled && (rule.reason === undefined || rule.reason.trim() === '')) {
        throw new Error('reason is required when enabled=false');
      }
      if (rule.enabled && !hasAnySignal(rule.params)) {
        throw new Error(
          'at least one signal must be active when enabled=true ' +
            '(user_agent_deny non-empty / require_accept_language / require_accept_encoding)',
        );
      }
      rules.set(rule.id, rule);
      rev += 1;
      return { rev };
    },
    list: () => ({ rev, rules: [...rules.values()] }),
  };
}

/**
 * Enregistre les routes /v1/mitigations/scraping sur app.
 *
 *   GET  /v1/mitigations/scraping        → snapshot
 *   PUT  /v1/mitigations/scraping/:id    → upsert avec validation
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerScrapingRoutes(
  app: FastifyInstance,
  store: ScrapingStore,
): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/scraping',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(ScrapingRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/scraping/:id',
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
            rule: ScrapingRuleSchema,
          },
          { additionalProperties: false },
        ),
        400: Type.Object(
          {
            error: Type.Union([
              Type.Literal('id_mismatch'),
              Type.Literal('invalid_rule'),
              Type.Literal('disabled_without_reason'),
              Type.Literal('no_signal'),
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
      if (!Value.Check(ScrapingRuleSchema, body)) {
        const details = [...Value.Errors(ScrapingRuleSchema, body)].map(
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
        const msg = err instanceof Error ? err.message : String(err);
        reply.code(400);
        const errorCode = msg.startsWith('reason')
          ? ('disabled_without_reason' as const)
          : ('no_signal' as const);
        return { error: errorCode, details: [msg] };
      }
    },
  });
}
