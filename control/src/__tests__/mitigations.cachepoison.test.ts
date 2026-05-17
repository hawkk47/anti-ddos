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
  id: 'cache-poison',
  enabled: true,
  action: 'strip',
  params: {
    headers: ['X-Forwarded-Host', 'X-Original-URL'],
  },
};

describe('PUT /v1/mitigations/cache-poison/:id', () => {
  it('accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/cache-poison/cache-poison',
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
      url: '/v1/mitigations/cache-poison/cache-poison',
      payload: { ...validRule, extra: 'x' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects empty headers array', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/cache-poison/cache-poison',
      payload: { ...validRule, params: { headers: [] } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects more than 64 headers', async () => {
    app = buildApp({ config: baseConfig });
    const headers = Array.from({ length: 65 }, (_, i) => `X-Test-${i}`);
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/cache-poison/cache-poison',
      payload: { ...validRule, params: { headers } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects header names with invalid characters', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/cache-poison/cache-poison',
      payload: { ...validRule, params: { headers: ['X Bad Space'] } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects unknown id literal', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/cache-poison/cache-poison',
      payload: { ...validRule, id: 'other' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects id mismatch (url vs body)', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/cache-poison/other',
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
      url: '/v1/mitigations/cache-poison/cache-poison',
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
      url: '/v1/mitigations/cache-poison/cache-poison',
      payload: { ...validRule, enabled: false, reason: 'CDN gère le strip' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });

  it('accepts action=deny', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/cache-poison/cache-poison',
      payload: { ...validRule, action: 'deny' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('GET /v1/mitigations/cache-poison', () => {
  it('returns empty snapshot initially', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({ method: 'GET', url: '/v1/mitigations/cache-poison' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ rev: 0, rules: [] });
  });
});
