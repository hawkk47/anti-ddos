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
  id: 'http2-rapid-reset',
  enabled: true,
  on_error: 'allow',
  params: {
    max_resets_per_conn: 100,
    window_ms: 10_000,
    max_concurrent_streams: 100,
  },
};

describe('PUT /v1/mitigations/http2/:id', () => {
  it('accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/http2/http2-rapid-reset',
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
      url: '/v1/mitigations/http2/http2-rapid-reset',
      payload: { ...validRule, extra: 'x' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects max_resets_per_conn < 1', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/http2/http2-rapid-reset',
      payload: {
        ...validRule,
        params: { ...validRule.params, max_resets_per_conn: 0 },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects window_ms > 5min', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/http2/http2-rapid-reset',
      payload: {
        ...validRule,
        params: { ...validRule.params, window_ms: 300_001 },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects max_concurrent_streams > 100_000', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/http2/http2-rapid-reset',
      payload: {
        ...validRule,
        params: { ...validRule.params, max_concurrent_streams: 200_000 },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects id mismatch', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/http2/other',
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
      url: '/v1/mitigations/http2/http2-rapid-reset',
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
      url: '/v1/mitigations/http2/http2-rapid-reset',
      payload: { ...validRule, enabled: false, reason: 'pilote prod #18' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('GET /v1/mitigations/http2', () => {
  it('returns empty snapshot initially', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({ method: 'GET', url: '/v1/mitigations/http2' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ rev: 0, rules: [] });
  });
});
