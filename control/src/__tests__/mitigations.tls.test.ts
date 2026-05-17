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
  id: 'tls-renegotiation-flood',
  enabled: true,
  on_error: 'allow',
  params: { min_tls_version: '1.2', handshakes_per_second_per_ip: 50, burst: 20 },
};

describe('PUT /v1/mitigations/tls/:id', () => {
  it('accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls/tls-renegotiation-flood',
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
      url: '/v1/mitigations/tls/tls-renegotiation-flood',
      payload: { ...validRule, extra: 'x' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects invalid min_tls_version', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls/tls-renegotiation-flood',
      payload: {
        ...validRule,
        params: { min_tls_version: '1.1', handshakes_per_second_per_ip: 50, burst: 20 },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects handshakes_per_second_per_ip <= 0', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls/tls-renegotiation-flood',
      payload: {
        ...validRule,
        params: { min_tls_version: '1.2', handshakes_per_second_per_ip: 0, burst: 20 },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects burst > 100_000', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls/tls-renegotiation-flood',
      payload: {
        ...validRule,
        params: {
          min_tls_version: '1.2',
          handshakes_per_second_per_ip: 50,
          burst: 200_000,
        },
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects id mismatch', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/tls/other',
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
      url: '/v1/mitigations/tls/tls-renegotiation-flood',
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
      url: '/v1/mitigations/tls/tls-renegotiation-flood',
      payload: { ...validRule, enabled: false, reason: 'pilote prod #17' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(200);
  });
});

describe('GET /v1/mitigations/tls', () => {
  it('returns empty snapshot initially', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({ method: 'GET', url: '/v1/mitigations/tls' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ rev: 0, rules: [] });
  });
});
