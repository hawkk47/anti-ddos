import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params http2-rapid-reset. Aligné avec
 * configs/schemas/http2.schema.json et
 * proxy/mitigations/http2reset/http2reset.go.
 */
export const Http2ParamsSchema = Type.Object(
  {
    max_resets_per_conn: Type.Integer({ minimum: 1, maximum: 1_000_000 }),
    window_ms: Type.Integer({ minimum: 1, maximum: 300_000 }),
    max_concurrent_streams: Type.Integer({ minimum: 1, maximum: 100_000 }),
  },
  { additionalProperties: false },
);
export type Http2Params = Static<typeof Http2ParamsSchema>;

/**
 * Règle de la famille "http2". MVP : seul l'id "http2-rapid-reset"
 * (CVE-2023-44487).
 *
 * Défaut on_error="allow" (fail-open AGENTS.md §3) : sur erreur interne
 * du compteur par connexion, on laisse passer ; le rate-limit reste
 * appliqué côté SETTINGS_MAX_CONCURRENT_STREAMS comme seconde défense.
 */
export const Http2RuleSchema = Type.Object(
  {
    id: Type.Literal('http2-rapid-reset'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: Http2ParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type Http2Rule = Static<typeof Http2RuleSchema>;

export interface Http2Store {
  get(id: string): Http2Rule | undefined;
  put(rule: Http2Rule): { rev: number };
  list(): { rev: number; rules: Http2Rule[] };
}

export function createInMemoryHttp2Store(): Http2Store {
  let rev = 0;
  const rules = new Map<string, Http2Rule>();
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
 * Enregistre les routes /v1/mitigations/http2 sur app.
 *
 *   GET  /v1/mitigations/http2         → snapshot
 *   PUT  /v1/mitigations/http2/:id     → upsert avec validation
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerHttp2Routes(app: FastifyInstance, store: Http2Store): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/http2',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(Http2RuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/http2/:id',
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
            rule: Http2RuleSchema,
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
      if (!Value.Check(Http2RuleSchema, body)) {
        const details = [...Value.Errors(Http2RuleSchema, body)].map(
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
