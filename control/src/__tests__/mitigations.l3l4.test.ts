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

describe('L3/L4 mitigation routes', () => {
  it('PUT /v1/mitigations/ip-reputation/ip-reputation accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const rule = {
      id: 'ip-reputation',
      enabled: true,
      on_error: 'allow',
      params: {
        allowlist: ['127.0.0.1/32'],
        blocklist: ['10.0.0.0/8'],
        max_dynamic_entries: 1000,
        default_block_ttl_ms: 60_000,
      },
    };
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/ip-reputation/ip-reputation',
      headers: { 'content-type': 'application/json' },
      payload: rule,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().rule).toEqual(rule);
  });

  it('PUT /v1/mitigations/conn-flood/conn-flood accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const rule = {
      id: 'conn-flood',
      enabled: true,
      on_error: 'allow',
      params: { max_conns_per_ip: 200, max_conns_per_subnet: 1000 },
    };
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/conn-flood/conn-flood',
      headers: { 'content-type': 'application/json' },
      payload: rule,
    });
    expect(res.statusCode).toBe(200);
  });

  it('PUT /v1/mitigations/syn-flood/syn-flood accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const rule = {
      id: 'syn-flood',
      enabled: true,
      on_error: 'allow',
      params: { accepts_per_second_per_ip: 50, burst_per_ip: 100 },
    };
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/syn-flood/syn-flood',
      headers: { 'content-type': 'application/json' },
      payload: rule,
    });
    expect(res.statusCode).toBe(200);
  });

  it('PUT /v1/mitigations/handshake-guard/handshake-guard accepts a valid rule', async () => {
    app = buildApp({ config: baseConfig });
    const rule = {
      id: 'handshake-guard',
      enabled: true,
      on_error: 'allow',
      params: { handshake_window_ms: 5000, abandon_threshold: 50, observe_window_ms: 60_000 },
    };
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/handshake-guard/handshake-guard',
      headers: { 'content-type': 'application/json' },
      payload: rule,
    });
    expect(res.statusCode).toBe(200);
  });

  it('PUT /v1/mitigations/geoblock-l4/geoblock-l4 accepts ISO alpha-2 codes', async () => {
    app = buildApp({ config: baseConfig });
    const rule = {
      id: 'geoblock-l4',
      enabled: true,
      on_error: 'allow',
      params: { allow: [], block: ['CN', 'RU'] },
    };
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/geoblock-l4/geoblock-l4',
      headers: { 'content-type': 'application/json' },
      payload: rule,
    });
    expect(res.statusCode).toBe(200);
  });

  it('rejects geoblock-l4 with invalid country code', async () => {
    app = buildApp({ config: baseConfig });
    const rule = {
      id: 'geoblock-l4',
      enabled: true,
      on_error: 'allow',
      params: { allow: [], block: ['FRANCE'] },
    };
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/geoblock-l4/geoblock-l4',
      headers: { 'content-type': 'application/json' },
      payload: rule,
    });
    expect(res.statusCode).toBe(400);
  });

  it('rejects disabled rule without reason', async () => {
    app = buildApp({ config: baseConfig });
    const rule = {
      id: 'conn-flood',
      enabled: false,
      on_error: 'allow',
      params: { max_conns_per_ip: 200 },
    };
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/conn-flood/conn-flood',
      headers: { 'content-type': 'application/json' },
      payload: rule,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('disabled_without_reason');
  });

  it('rejects id mismatch', async () => {
    app = buildApp({ config: baseConfig });
    const rule = {
      id: 'syn-flood',
      enabled: true,
      on_error: 'allow',
      params: { accepts_per_second_per_ip: 1, burst_per_ip: 1 },
    };
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/syn-flood/other',
      headers: { 'content-type': 'application/json' },
      payload: rule,
    });
    expect(res.statusCode).toBe(400);
    expect(res.json().error).toBe('id_mismatch');
  });

  it('GET snapshot returns rev=0 and empty rules by default', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({ method: 'GET', url: '/v1/mitigations/ip-reputation' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ rev: 0, rules: [] });
  });
});
