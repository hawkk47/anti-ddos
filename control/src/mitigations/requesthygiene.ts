import { Type, type Static } from '@sinclair/typebox';
import { Value } from '@sinclair/typebox/value';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';

/**
 * Schéma TypeBox des params request-hygiene. Aligné avec
 * configs/schemas/request-hygiene.schema.json et
 * proxy/mitigations/requesthygiene/requesthygiene.go.
 */
export const RequestHygieneParamsSchema = Type.Object(
  {
    allowed_methods: Type.Array(
      Type.String({ pattern: '^[A-Z]+$', minLength: 1, maxLength: 32 }),
      { uniqueItems: true },
    ),
    max_uri_length: Type.Integer({ minimum: 0, maximum: 1_048_576 }),
    reject_te_cl_conflict: Type.Boolean(),
    reject_duplicate_content_length: Type.Boolean(),
    reject_invalid_transfer_encoding: Type.Boolean(),
    reject_empty_host: Type.Boolean(),
  },
  { additionalProperties: false },
);
export type RequestHygieneParams = Static<typeof RequestHygieneParamsSchema>;

/**
 * Règle de la famille "request-hygiene". Politique d'hygiène HTTP en
 * tête de chaîne : méthode whitelist, URI bornée, framing strict
 * (anti-smuggling), Host non vide. Sur violation : 400 sans header de
 * raison.
 *
 * Défaut on_error="deny" : une erreur dans le parser d'hygiène indique
 * une requête vraiment hostile/malformée ; fail-closed est ici cohérent.
 */
export const RequestHygieneRuleSchema = Type.Object(
  {
    id: Type.Literal('request-hygiene'),
    enabled: Type.Boolean(),
    on_error: Type.Union([Type.Literal('allow'), Type.Literal('deny')]),
    params: RequestHygieneParamsSchema,
    notes: Type.Optional(Type.String({ maxLength: 1024 })),
    reason: Type.Optional(Type.String({ maxLength: 256 })),
  },
  { additionalProperties: false },
);
export type RequestHygieneRule = Static<typeof RequestHygieneRuleSchema>;

export interface RequestHygieneStore {
  get(id: string): RequestHygieneRule | undefined;
  put(rule: RequestHygieneRule): { rev: number };
  list(): { rev: number; rules: RequestHygieneRule[] };
}

export function createInMemoryRequestHygieneStore(): RequestHygieneStore {
  let rev = 0;
  const rules = new Map<string, RequestHygieneRule>();
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
 * Enregistre les routes /v1/mitigations/request-hygiene sur app.
 *
 *   GET  /v1/mitigations/request-hygiene         → snapshot
 *   PUT  /v1/mitigations/request-hygiene/:id     → upsert avec validation
 */
export function registerRequestHygieneRoutes(
  app: FastifyInstance,
  store: RequestHygieneStore,
): void {
  app.route({
    method: 'GET',
    url: '/v1/mitigations/request-hygiene',
    schema: {
      response: {
        200: Type.Object(
          {
            rev: Type.Integer({ minimum: 0 }),
            rules: Type.Array(RequestHygieneRuleSchema),
          },
          { additionalProperties: false },
        ),
      },
    },
    handler: async () => store.list(),
  });

  app.route({
    method: 'PUT',
    url: '/v1/mitigations/request-hygiene/:id',
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
            rule: RequestHygieneRuleSchema,
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
      if (!Value.Check(RequestHygieneRuleSchema, body)) {
        const details = [...Value.Errors(RequestHygieneRuleSchema, body)].map(
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
