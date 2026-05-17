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
  proxyAdminUrl: 'http://127.0.0.1:8080',
};

const validRule = {
  id: 'slowloris',
  enabled: true,
  on_error: 'allow',
  params: { max_conns_per_ip: 64 },
};

describe('PUT /v1/mitigations/connections/:id', () => {
  it('accepts a valid slowloris rule and increments rev', async () => {
    app = buildApp({ config: baseConfig });

    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/connections/slowloris',
      headers: { 'content-type': 'application/json' },
      payload: validRule,
    });

    expect(res.statusCode).toBe(200);
    const body = res.json();
    expect(body.status).toBe('ok');
    expect(body.rev).toBe(1);
    expect(body.rule).toEqual(validRule);
  });

  it('rejects unknown id (additionalProperties: false on union)', async () => {
    app = buildApp({ config: baseConfig });

    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/connections/foobar',
      headers: { 'content-type': 'application/json' },
      payload: { ...validRule, id: 'foobar' },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_rule');
  });

  it('rejects id mismatch between url and body', async () => {
    app = buildApp({ config: baseConfig });

    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/connections/other',
      headers: { 'content-type': 'application/json' },
      payload: validRule,
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('id_mismatch');
  });

  it('rejects out-of-range max_conns_per_ip', async () => {
    app = buildApp({ config: baseConfig });

    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/connections/slowloris',
      headers: { 'content-type': 'application/json' },
      payload: { ...validRule, params: { max_conns_per_ip: 0 } },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('invalid_rule');
  });

  it('requires reason when enabled=false', async () => {
    app = buildApp({ config: baseConfig });

    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/connections/slowloris',
      headers: { 'content-type': 'application/json' },
      payload: { ...validRule, enabled: false },
    });

    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('disabled_without_reason');
  });
});

describe('GET /v1/mitigations/connections', () => {
  it('returns empty store with rev=0 initially', async () => {
    app = buildApp({ config: baseConfig });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/mitigations/connections',
    });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ rev: 0, rules: [] });
  });

  it('reflects PUT updates', async () => {
    app = buildApp({ config: baseConfig });

    await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/connections/slowloris',
      headers: { 'content-type': 'application/json' },
      payload: validRule,
    });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/mitigations/connections',
    });

    const body = res.json();
    expect(body.rev).toBe(1);
    expect(body.rules).toEqual([validRule]);
  });
});
