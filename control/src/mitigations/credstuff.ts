import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params credential-stuffing. Aligné avec
 * configs/schemas/credstuff.schema.json et
 * proxy/mitigations/credstuff/credstuff.go.
 */
export const CredStuffParamsSchema = Type.Object(
  {
    login_paths: Type.Array(
      Type.String({ minLength: 1, maxLength: 256, pattern: '^/' }),
      { maxItems: 32 },
    ),
    methods: Type.Optional(
      Type.Array(Type.String({ minLength: 1, maxLength: 16 }), {
        maxItems: 8,
      }),
    ),
    max_attempts_per_minute: Type.Integer({ minimum: 1, maximum: 10_000 }),
    blocklist_enabled: Type.Optional(Type.Boolean()),
  },
  { additionalProperties: false },
);
export type CredStuffParams = Static<typeof CredStuffParamsSchema>;

/**
 * Règle de la famille "credential-stuffing".
 *
 * AVERTISSEMENT : rate-limit per-IP. Contre du stuffing distribué
 * (botnet, proxies résidentiels), combiner avec une couche
 * comportementale (CAPTCHA, MFA, contrôles applicatifs).
 */
export const CredStuffRuleSchema = Type.Object(
  {
    id: Type.Literal('credential-stuffing'),
    enabled: Type.Boolean(),
    action: Type.Union([Type.Literal('log'), Type.Literal('deny')]),
    params: CredStuffParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type CredStuffRule = Static<typeof CredStuffRuleSchema>;

export interface CredStuffStore {
  get(id: string): CredStuffRule | undefined;
  put(rule: CredStuffRule): { rev: number };
  list(): { rev: number; rules: CredStuffRule[] };
}

export function createInMemoryCredStuffStore(): CredStuffStore {
  let rev = 0;
  const rules = new Map<string, CredStuffRule>();
  return {
    get: (id) => rules.get(id),
    put: (rule) => {
      if (!rule.enabled && (rule.reason === undefined || rule.reason.trim() === '')) {
        throw new Error('reason is required when enabled=false');
      }
      if (rule.enabled && rule.params.login_paths.length === 0) {
        throw new Error('login_paths must contain at least one entry when enabled');
      }
      rules.set(rule.id, rule);
      rev += 1;
      return { rev };
    },
    list: () => ({ rev, rules: [...rules.values()] }),
  };
}

/**
 * Enregistre les routes /v1/mitigations/credential-stuffing sur app.
 *
 *   GET  /v1/mitigations/credential-stuffing
 *   PUT  /v1/mitigations/credential-stuffing/:id
 *
 * Le push effectif au data plane passe par POST /v1/reload.
 */
export function registerCredStuffRoutes(
  app: FastifyInstance,
  store: CredStuffStore,
): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/credential-stuffing',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(CredStuffRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/credential-stuffing/:id',
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
            rule: CredStuffRuleSchema,
          },
          { additionalProperties: false },
        ),
        400: Type.Object(
          {
            error: Type.Union([
              Type.Literal('id_mismatch'),
              Type.Literal('invalid_rule'),
              Type.Literal('disabled_without_reason'),
              Type.Literal('empty_login_paths'),
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
      if (!Value.Check(CredStuffRuleSchema, body)) {
        const details = [...Value.Errors(CredStuffRuleSchema, body)].map(
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
          : ('empty_login_paths' as const);
        return { error: errorCode, details: [msg] };
      }
    },
  });
}
