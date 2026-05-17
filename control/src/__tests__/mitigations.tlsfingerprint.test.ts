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

const validJA3 = 'a'.repeat(32);
const validJA4 = 't13d1517h2_8daaf6152771_b186095e22b6';

const validRule = {
  id: 'tls-fingerprint',
  enabled: true,
  on_error: 'allow',
  params: {
    blocked_ja3: [validJA3],
    blocked_ja4: [validJA4],
  },
};

describe('PUT /v1/mitigations/tls-fingerprint/:id', () => {
  it('accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: validRule,
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
    expect((res.json() as { status: string; rev: number }).rev).toBe(1);
  });

  it('accepts empty blocklists', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, params: { blocked_ja3: [], blocked_ja4: [] } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });

  it('rejects unknown fields', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, extra: 'nope' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('invalid_rule');
  });

  it('rejects JA3 with uppercase hex', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, params: { ...validRule.params, blocked_ja3: ['A'.repeat(32)] } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects JA3 of wrong length', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, params: { ...validRule.params, blocked_ja3: ['a'.repeat(31)] } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects JA3 with non-hex chars', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, params: { ...validRule.params, blocked_ja3: ['g'.repeat(32)] } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects duplicate JA3', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, params: { ...validRule.params, blocked_ja3: [validJA3, validJA3] } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects JA4 missing underscores', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, params: { ...validRule.params, blocked_ja4: ['t13d1517h2nounderscores'] } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects JA4 too short', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, params: { ...validRule.params, blocked_ja4: ['a_b_c'] } },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects unknown id', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, id: 'other' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects invalid on_error', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, on_error: 'bogus' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects id mismatch URL vs body', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/wrong',
      payload: validRule,
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('id_mismatch');
  });

  it('rejects disabled without reason', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, enabled: false },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('disabled_without_reason');
  });

  it('accepts disabled with reason', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: { ...validRule, enabled: false, reason: 'maintenance' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('GET /v1/mitigations/tls-fingerprint', () => {
  it('returns empty list initially', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({ method: 'GET', url: '/v1/mitigations/tls-fingerprint' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ rev: 0, rules: [] });
  });

  it('returns the rule after PUT', async () => {
    app = buildApp({ config: baseConfig });
    await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls-fingerprint/tls-fingerprint',
      payload: validRule,
      headers: { 'content-type': 'application/json' },
    });
    const res = await app.inject({ method: 'GET', url: '/v1/mitigations/tls-fingerprint' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { rev: number; rules: unknown[] };
    expect(body.rev).toBe(1);
    expect(body.rules).toHaveLength(1);
  });
});
