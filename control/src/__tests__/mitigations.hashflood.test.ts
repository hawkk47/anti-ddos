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
  id: 'hash-flood',
  enabled: true,
  on_error: 'allow',
  params: {
    max_query_params: 64,
  },
};

describe('PUT /v1/mitigations/hash-flood/:id', () => {
  it('accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/hash-flood/hash-flood',
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
      url: '/v1/mitigations/hash-flood/hash-flood',
      payload: { ...validRule, extra: 'x' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects max_query_params < 1', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/hash-flood/hash-flood',
      payload: { ...validRule, params: { max_query_params: 0 } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects max_query_params > 10000', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/hash-flood/hash-flood',
      payload: { ...validRule, params: { max_query_params: 10_001 } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects unknown id literal', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/hash-flood/hash-flood',
      payload: { ...validRule, id: 'other' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects id mismatch (url vs body)', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/hash-flood/other',
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
      url: '/v1/mitigations/hash-flood/hash-flood',
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
      url: '/v1/mitigations/hash-flood/hash-flood',
      payload: { ...validRule, enabled: false, reason: 'maintenance API' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('GET /v1/mitigations/hash-flood', () => {
  it('returns empty snapshot initially', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({ method: 'GET', url: '/v1/mitigations/hash-flood' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ rev: 0, rules: [] });
  });
});
