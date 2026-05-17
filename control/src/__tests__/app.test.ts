import { describe, it, expect, afterEach, vi } from 'vitest';
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

const baseConfig = {
  listenHost: '127.0.0.1',
  listenPort: 0,
  logLevel: 'fatal' as const,
  proxyAdminUrl: 'http://127.0.0.1:8081',
};

/** fetch mock qui retourne toujours 200 OK. */
function okFetcher(): typeof fetch {
  return vi.fn(async () => new Response('{"status":"applied"}', { status: 200 })) as unknown as typeof fetch;
}

describe('GET /v1/health', () => {
  it('returns ok with monotonic uptime', async () => {
    let t = 1000;
    app = buildApp({ config: baseConfig, now: () => t });
    t = 1500;

    const res = await app.inject({ method: 'GET', url: '/v1/health' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok', uptimeMs: 500 });
  });
});

describe('POST /v1/reload', () => {
  it('accepts empty body and pushes empty snapshot', async () => {
    const fetcher = okFetcher();
    app = buildApp({ config: baseConfig, now: () => 42, fetcher });

    const res = await app.inject({ method: 'POST', url: '/v1/reload' });

    expect(res.statusCode).toBe(202);
    expect(res.json()).toEqual({ status: 'accepted', at: 42, pushed: 0 });
    // 14 familles poussées : connections + ratelimit + headers + bodies + tls + http2 + hash-flood + range-amp + cache-poison + scraping + credential-stuffing + concurrency + request-hygiene + tls-fingerprint.
    expect(fetcher).toHaveBeenCalledTimes(14);
    const calls = (fetcher as unknown as ReturnType<typeof vi.fn>).mock.calls;
    const urls = calls.map((c) => c[0] as string).sort();
    expect(urls).toEqual([
      'http://127.0.0.1:8081/_admin/v1/mitigations/bodies',
      'http://127.0.0.1:8081/_admin/v1/mitigations/cache-poison',
      'http://127.0.0.1:8081/_admin/v1/mitigations/concurrency',
      'http://127.0.0.1:8081/_admin/v1/mitigations/connections',
      'http://127.0.0.1:8081/_admin/v1/mitigations/credential-stuffing',
      'http://127.0.0.1:8081/_admin/v1/mitigations/hash-flood',
      'http://127.0.0.1:8081/_admin/v1/mitigations/headers',
      'http://127.0.0.1:8081/_admin/v1/mitigations/http2',
      'http://127.0.0.1:8081/_admin/v1/mitigations/range-amp',
      'http://127.0.0.1:8081/_admin/v1/mitigations/ratelimit',
      'http://127.0.0.1:8081/_admin/v1/mitigations/request-hygiene',
      'http://127.0.0.1:8081/_admin/v1/mitigations/scraping',
      'http://127.0.0.1:8081/_admin/v1/mitigations/tls',
      'http://127.0.0.1:8081/_admin/v1/mitigations/tls-fingerprint',
    ]);
    for (const [, init] of calls) {
      expect((init as RequestInit).method).toBe('PUT');
    }
  });

  it('accepts a reason field', async () => {
    app = buildApp({ config: baseConfig, now: () => 7, fetcher: okFetcher() });

    const res = await app.inject({
      method: 'POST',
      url: '/v1/reload',
      payload: { reason: 'rotated rules' },
      headers: { 'content-type': 'application/json' },
    });

    expect(res.statusCode).toBe(202);
  });

  it('rejects unknown fields (additionalProperties: false)', async () => {
    app = buildApp({ config: baseConfig, now: () => 0, fetcher: okFetcher() });

    const res = await app.inject({
      method: 'POST',
      url: '/v1/reload',
      payload: { unexpected: true },
      headers: { 'content-type': 'application/json' },
    });

    expect(res.statusCode).toBe(400);
  });

  it('returns 502 when proxy is unreachable', async () => {
    const fetcher = vi.fn(async () => {
      throw new Error('ECONNREFUSED');
    }) as unknown as typeof fetch;
    app = buildApp({ config: baseConfig, fetcher });

    const res = await app.inject({ method: 'POST', url: '/v1/reload' });

    expect(res.statusCode).toBe(502);
    expect(res.json()).toMatchObject({ error: 'proxy_unreachable' });
  });

  it('returns 502 when proxy rejects the push', async () => {
    const fetcher = vi.fn(async () =>
      new Response('bad config', { status: 400 }),
    ) as unknown as typeof fetch;
    app = buildApp({ config: baseConfig, fetcher });

    const res = await app.inject({ method: 'POST', url: '/v1/reload' });

    expect(res.statusCode).toBe(502);
  });
});

describe('not found handler', () => {
  it('returns JSON 404 for unknown route', async () => {
    app = buildApp({ config: baseConfig });

    const res = await app.inject({ method: 'GET', url: '/nope' });

    expect(res.statusCode).toBe(404);
    expect(res.json()).toEqual({ error: 'not_found', path: '/nope' });
  });
});

describe('loadConfigFromEnv', () => {
  it('uses loopback defaults', () => {
    const cfg = loadConfigFromEnv({});
    expect(cfg.listenHost).toBe('127.0.0.1');
    expect(cfg.listenPort).toBe(9090);
    expect(cfg.logLevel).toBe('info');
    expect(cfg.proxyAdminUrl).toBe('http://127.0.0.1:8081');
  });

  it('parses overrides', () => {
    const cfg = loadConfigFromEnv({
      ANTIDDOS_CTRL_HOST: '127.0.0.1',
      ANTIDDOS_CTRL_PORT: '9999',
      ANTIDDOS_CTRL_LOG_LEVEL: 'warn',
      ANTIDDOS_PROXY_ADMIN_URL: 'http://127.0.0.1:8081',
    });
    expect(cfg.listenPort).toBe(9999);
    expect(cfg.logLevel).toBe('warn');
  });

  it('rejects invalid port', () => {
    expect(() => loadConfigFromEnv({ ANTIDDOS_CTRL_PORT: 'abc' })).toThrow(/invalid/);
    expect(() => loadConfigFromEnv({ ANTIDDOS_CTRL_PORT: '70000' })).toThrow(/invalid/);
  });

  it('rejects invalid log level', () => {
    expect(() => loadConfigFromEnv({ ANTIDDOS_CTRL_LOG_LEVEL: 'verbose' })).toThrow(/invalid/);
  });
});
