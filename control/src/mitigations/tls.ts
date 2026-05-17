import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params tls-renegotiation-flood. Aligné avec
 * configs/schemas/tls.schema.json et
 * proxy/mitigations/tlsreneg/tlsreneg.go.
 */
export const TLSParamsSchema = Type.Object(
  {
    min_tls_version: Type.Union([Type.Literal('1.2'), Type.Literal('1.3')]),
    handshakes_per_second_per_ip: Type.Number({
      exclusiveMinimum: 0,
      maximum: 1_000_000,
    }),
    burst: Type.Integer({ minimum: 1, maximum: 100_000 }),
  },
  { additionalProperties: false },
);
export type TLSParams = Static<typeof TLSParamsSchema>;

/**
 * Règle de la famille "tls". MVP : seul l'id "tls-renegotiation-flood".
 *
 * Défaut on_error="allow" (fail-open AGENTS.md §3) ; la renégociation
 * cliente est toujours refusée au niveau crypto/tls (non négociable).
 */
export const TLSRuleSchema = Type.Object(
  {
    id: Type.Literal('tls-renegotiation-flood'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: TLSParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type TLSRule = Static<typeof TLSRuleSchema>;

export interface TLSStore {
  get(id: string): TLSRule | undefined;
  put(rule: TLSRule): { rev: number };
  list(): { rev: number; rules: TLSRule[] };
}

export function createInMemoryTLSStore(): TLSStore {
  let rev = 0;
  const rules = new Map<string, TLSRule>();
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
 * Enregistre les routes /v1/mitigations/tls sur app.
 *
 *   GET  /v1/mitigations/tls         → snapshot
 *   PUT  /v1/mitigations/tls/:id     → upsert avec validation
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerTLSRoutes(app: FastifyInstance, store: TLSStore): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/tls',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(TLSRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/tls/:id',
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
            rule: TLSRuleSchema,
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
      if (!Value.Check(TLSRuleSchema, body)) {
        const details = [...Value.Errors(TLSRuleSchema, body)].map(
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
