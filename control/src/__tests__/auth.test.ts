import { describe, it, expect, afterEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app.js';
import { loadConfigFromEnv } from '../config.js';

let app: FastifyInstance | undefined;

afterEach(async () => {
  if (app) {
    await app.close();
    app = undefined;
  }
});

const TOKEN = 'a'.repeat(32);

const authedConfig = {
  listenHost: '127.0.0.1',
  listenPort: 0,
  logLevel: 'fatal' as const,
  proxyAdminUrl: 'http://127.0.0.1:8081',
  apiToken: TOKEN,
};

describe('loadConfigFromEnv — apiToken validation', () => {
  it('accepte un token >= 16 chars', () => {
    const cfg = loadConfigFromEnv({ ANTIDDOS_CTRL_API_TOKEN: 'x'.repeat(32) });
    expect(cfg.apiToken).toBe('x'.repeat(32));
  });

  it('rejette un token trop court', () => {
    expect(() =>
      loadConfigFromEnv({ ANTIDDOS_CTRL_API_TOKEN: 'short' }),
    ).toThrow(/at least 16/);
  });

  it('rejette un token trop long', () => {
    expect(() =>
      loadConfigFromEnv({ ANTIDDOS_CTRL_API_TOKEN: 'a'.repeat(513) }),
    ).toThrow(/too long/);
  });

  it('autorise un token absent en bind loopback (défaut 127.0.0.1)', () => {
    const cfg = loadConfigFromEnv({});
    expect(cfg.apiToken).toBeNull();
    expect(cfg.listenHost).toBe('127.0.0.1');
  });

  it('fail-fast si bind non-loopback et token absent', () => {
    expect(() =>
      loadConfigFromEnv({ ANTIDDOS_CTRL_HOST: '0.0.0.0' }),
    ).toThrow(/ANTIDDOS_CTRL_API_TOKEN is required/);
  });

  it('accepte non-loopback si token fourni', () => {
    const cfg = loadConfigFromEnv({
      ANTIDDOS_CTRL_HOST: '0.0.0.0',
      ANTIDDOS_CTRL_API_TOKEN: 'z'.repeat(32),
    });
    expect(cfg.listenHost).toBe('0.0.0.0');
    expect(cfg.apiToken).toBe('z'.repeat(32));
  });
});

describe('Auth Bearer hook — routes publiques toujours accessibles', () => {
  it('GET /v1/health 200 sans token même si auth activée', async () => {
    app = buildApp({ config: authedConfig });
    const res = await app.inject({ method: 'GET', url: '/v1/health' });
    expect(res.statusCode).toBe(200);
  });

  it('GET /metrics 200 sans token même si auth activée', async () => {
    app = buildApp({ config: authedConfig });
    const res = await app.inject({ method: 'GET', url: '/metrics' });
    expect(res.statusCode).toBe(200);
  });
});

describe('Auth Bearer hook — protection des routes sensibles', () => {
  it('refuse 401 sans header Authorization', async () => {
    app = buildApp({ config: authedConfig });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/auth-event',
      payload: {
        username_hash: '0'.repeat(64),
        success: false,
        source_ip: '203.0.113.10',
        ts: Math.floor(Date.now() / 1000),
      },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(401);
    expect((res.json() as { error: string }).error).toBe('unauthorized');
  });

  it('refuse 401 avec header non-Bearer', async () => {
    app = buildApp({ config: authedConfig });
    const res = await app.inject({
      method: 'GET',
      url: '/v1/behavioral/credstuff/state',
      headers: { authorization: `Basic ${Buffer.from('x:y').toString('base64')}` },
    });
    expect(res.statusCode).toBe(401);
  });

  it('refuse 401 avec token erroné', async () => {
    app = buildApp({ config: authedConfig });
    const res = await app.inject({
      method: 'GET',
      url: '/v1/behavioral/credstuff/state',
      headers: { authorization: 'Bearer wrong-token-that-is-long-enough-abcdef' },
    });
    expect(res.statusCode).toBe(401);
  });

  it('refuse 401 même si le token diffère sur la longueur', async () => {
    app = buildApp({ config: authedConfig });
    const res = await app.inject({
      method: 'GET',
      url: '/v1/behavioral/credstuff/state',
      headers: { authorization: 'Bearer too-short' },
    });
    expect(res.statusCode).toBe(401);
  });

  it('accepte 200 avec le bon token', async () => {
    app = buildApp({ config: authedConfig });
    const res = await app.inject({
      method: 'GET',
      url: '/v1/behavioral/credstuff/state',
      headers: { authorization: `Bearer ${TOKEN}` },
    });
    expect(res.statusCode).toBe(200);
  });

  it('protège POST /v1/reload', async () => {
    app = buildApp({ config: authedConfig });
    const res = await app.inject({ method: 'POST', url: '/v1/reload', payload: {} });
    expect(res.statusCode).toBe(401);
  });

  it('protège DELETE /v1/behavioral/credstuff/state', async () => {
    app = buildApp({ config: authedConfig });
    const res = await app.inject({ method: 'DELETE', url: '/v1/behavioral/credstuff/state' });
    expect(res.statusCode).toBe(401);
  });

  it('protège POST /v1/behavioral/credstuff/push/mode (mutation enforce)', async () => {
    app = buildApp({ config: authedConfig });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/push/mode',
      payload: { mode: 'enforce' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(401);
  });

  it('avec apiToken: null désactive l\'auth (loopback dev)', async () => {
    app = buildApp({
      config: {
        listenHost: '127.0.0.1',
        listenPort: 0,
        logLevel: 'fatal' as const,
        proxyAdminUrl: 'http://127.0.0.1:8081',
        apiToken: null,
      },
    });
    const res = await app.inject({ method: 'GET', url: '/v1/behavioral/credstuff/state' });
    expect(res.statusCode).toBe(200);
  });
});
