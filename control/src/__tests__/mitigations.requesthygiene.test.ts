import { describe, it, expect, afterEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app.js';

let app: FastifyInstance | undefined;

afterEach(async () => {
  if (app) {
    await app.close();
    app = undefined;
  }
});

const baseConfig = {
  listenHost: '127.0.0.1',
  listenPort: 0,
  logLevel: 'fatal' as const,
  proxyAdminUrl: 'http://127.0.0.1:8081',
};

const validRule = {
  id: 'request-hygiene',
  enabled: true,
  on_error: 'deny',
  params: {
    allowed_methods: ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    max_uri_length: 8192,
    reject_te_cl_conflict: true,
    reject_duplicate_content_length: true,
    reject_invalid_transfer_encoding: true,
    reject_empty_host: true,
  },
};

describe('PUT /v1/mitigations/request-hygiene/:id', () => {
  it('accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: validRule,
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { status: string; rev: number }).rev).toBe(1);
  });

  it('rejects unknown fields', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: { ...validRule, extra: 'x' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects lowercase method', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: {
        ...validRule,
        params: { ...validRule.params, allowed_methods: ['get'] },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects duplicate method entries', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: {
        ...validRule,
        params: { ...validRule.params, allowed_methods: ['GET', 'GET'] },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects negative max_uri_length', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: {
        ...validRule,
        params: { ...validRule.params, max_uri_length: -1 },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects max_uri_length > 1 MiB', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: {
        ...validRule,
        params: { ...validRule.params, max_uri_length: 2_000_000 },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects unknown id literal', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: { ...validRule, id: 'other' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects on_error not in {allow,deny}', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: { ...validRule, on_error: 'log' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects id mismatch (url vs body)', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/other',
      payload: validRule,
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('id_mismatch');
  });

  it('refuses enabled=false without reason', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: { ...validRule, enabled: false },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('disabled_without_reason');
  });

  it('accepts enabled=false with reason', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: { ...validRule, enabled: false, reason: 'temporarily off' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('GET /v1/mitigations/request-hygiene', () => {
  it('returns empty snapshot initially', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'GET',
      url: '/v1/mitigations/request-hygiene',
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ rev: 0, rules: [] });
  });

  it('returns snapshot after PUT', async () => {
    app = buildApp({ config: baseConfig });
    await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/request-hygiene/request-hygiene',
      payload: validRule,
      headers: { 'content-type': 'application/json' },
    });
    const res = await app.inject({
      method: 'GET',
      url: '/v1/mitigations/request-hygiene',
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { rev: number; rules: typeof validRule[] };
    expect(body.rev).toBe(1);
    expect(body.rules).toHaveLength(1);
    expect(body.rules[0]).toEqual(validRule);
  });
});
