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
  id: 'credential-stuffing',
  enabled: true,
  action: 'deny',
  params: {
    login_paths: ['/login', '/api/auth/'],
    methods: ['POST'],
    max_attempts_per_minute: 10,
  },
};

describe('PUT /v1/mitigations/credential-stuffing/:id', () => {
  it('accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: validRule,
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { rev: number }).rev).toBe(1);
  });

  it('accepts action=log', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: { ...validRule, action: 'log' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });

  it('accepts rule without methods (all methods)', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: {
        id: 'credential-stuffing',
        enabled: true,
        action: 'deny',
        params: { login_paths: ['/login'], max_attempts_per_minute: 5 },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });

  it('rejects unknown fields', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: { ...validRule, extra: 'x' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects login_paths not starting with /', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: {
        ...validRule,
        params: { ...validRule.params, login_paths: ['login'] },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects more than 32 login_paths', async () => {
    app = buildApp({ config: baseConfig });
    const paths = Array.from({ length: 33 }, (_, i) => `/p${i}`);
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: {
        ...validRule,
        params: { ...validRule.params, login_paths: paths },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects max_attempts_per_minute = 0', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: {
        ...validRule,
        params: { ...validRule.params, max_attempts_per_minute: 0 },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects max_attempts_per_minute over cap', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: {
        ...validRule,
        params: { ...validRule.params, max_attempts_per_minute: 10_001 },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects unknown action', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: { ...validRule, action: 'tarpit' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects unknown id literal', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: { ...validRule, id: 'other' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects id mismatch (url vs body)', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/credential-stuffing/other',
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
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
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
      url: '/v1/mitigations/credential-stuffing/credential-stuffing',
      payload: {
        ...validRule,
        enabled: false,
        reason: 'WAF amont fait le boulot',
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('GET /v1/mitigations/credential-stuffing', () => {
  it('returns empty snapshot initially', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'GET',
      url: '/v1/mitigations/credential-stuffing',
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ rev: 0, rules: [] });
  });
});
