import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params tls-fingerprint. Aligné avec
 * configs/schemas/tls-fingerprint.schema.json et
 * proxy/mitigations/tlsfingerprint/tlsfingerprint.go.
 *
 * blocked_ja3 : hash MD5 hex lowercase (32 caractères) — format
 *               canonique Salesforce 2017.
 * blocked_ja4 : chaîne format FoxIO 'tXXYnnmmALPN_<sha12>_<sha12>',
 *               exactement 2 underscores, longueur 10..64.
 */
export const TLSFingerprintParamsSchema = Type.Object(
  {
    blocked_ja3: Type.Array(Type.String({ pattern: '^[a-f0-9]{32}$' }), {
      uniqueItems: true,
      maxItems: 1024,
    }),
    blocked_ja4: Type.Array(
      Type.String({
        minLength: 10,
        maxLength: 64,
        pattern: '^[^_]+_[^_]+_[^_]+$',
      }),
      { uniqueItems: true, maxItems: 1024 },
    ),
  },
  { additionalProperties: false },
);
export type TLSFingerprintParams = Static<typeof TLSFingerprintParamsSchema>;

/**
 * Règle de la famille "tls-fingerprint" : blocklist d'empreintes JA3 /
 * JA4 du ClientHello, appliquée au handshake TLS. Dormant tant que le
 * proxy n'a pas de terminaison TLS branchée.
 *
 * Défaut on_error="allow" : fail-open. Une erreur de calcul d'empreinte
 * ne doit jamais empêcher un client légitime de négocier.
 */
export const TLSFingerprintRuleSchema = Type.Object(
  {
    id: Type.Literal('tls-fingerprint'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: TLSFingerprintParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 2048 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type TLSFingerprintRule = Static<typeof TLSFingerprintRuleSchema>;

export interface TLSFingerprintStore {
  get(id: string): TLSFingerprintRule | undefined;
  put(rule: TLSFingerprintRule): { rev: number };
  list(): { rev: number; rules: TLSFingerprintRule[] };
}

export function createInMemoryTLSFingerprintStore(): TLSFingerprintStore {
  let rev = 0;
  const rules = new Map<string, TLSFingerprintRule>();
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
 * Enregistre les routes /v1/mitigations/tls-fingerprint sur app.
 *
 *   GET  /v1/mitigations/tls-fingerprint         → snapshot
 *   PUT  /v1/mitigations/tls-fingerprint/:id     → upsert avec validation
 */
export function registerTLSFingerprintRoutes(
  app: FastifyInstance,
  store: TLSFingerprintStore,
): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/tls-fingerprint',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(TLSFingerprintRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/tls-fingerprint/:id',
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
            rule: TLSFingerprintRuleSchema,
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
      if (!Value.Check(TLSFingerprintRuleSchema, body)) {
        const details = [...Value.Errors(TLSFingerprintRuleSchema, body)].map(
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
