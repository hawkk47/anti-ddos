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

function userHash(nibble: string): string {
  return '0'.repeat(63) + nibble;
}

describe('GET /metrics', () => {
  it('expose les compteurs behavioral en text/plain Prometheus', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({ method: 'GET', url: '/metrics' });
    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/plain');
    expect(res.headers['content-type']).toContain('version=0.0.4');
    const body = res.body;
    // Headers HELP/TYPE présents et compteurs à 0 au boot.
    expect(body).toContain('# TYPE behavioral_credstuff_events_total counter');
    expect(body).toContain('behavioral_credstuff_events_total{result="accepted"} 0');
    expect(body).toContain('# TYPE behavioral_credstuff_candidates gauge');
    expect(body).toContain('behavioral_credstuff_candidates 0');
    expect(body).toContain('# TYPE behavioral_credstuff_push_total counter');
    expect(body).toContain('behavioral_credstuff_push_total{status="shadow"} 0');
    expect(body).toContain('behavioral_credstuff_push_mode{mode="shadow"} 1');
    expect(body).toContain('behavioral_credstuff_push_mode{mode="enforce"} 0');
  });

  it('incrémente les compteurs après ingestion et push', async () => {
    app = buildApp({ config: baseConfig });
    // 6 IPs distinctes pour déclencher heuristique 2.
    for (let i = 1; i <= 6; i++) {
      const r = await app.inject({
        method: 'POST',
        url: '/v1/behavioral/credstuff/auth-event',
        payload: {
          username_hash: userHash('a'),
          success: false,
          source_ip: `203.0.113.${i}`,
          ts: Math.floor(Date.now() / 1000),
        },
        headers: { 'content-type': 'application/json' },
      });
      expect(r.statusCode).toBe(202);
    }
    await app.inject({ method: 'POST', url: '/v1/behavioral/credstuff/push' });

    const res = await app.inject({ method: 'GET', url: '/metrics' });
    expect(res.statusCode).toBe(200);
    const body = res.body;
    expect(body).toMatch(/behavioral_credstuff_events_total\{result="accepted"\} 6/);
    expect(body).toMatch(/behavioral_credstuff_candidates 6/);
    expect(body).toMatch(/behavioral_credstuff_push_total\{status="shadow"\} 1/);
    expect(body).toMatch(/behavioral_credstuff_push_last_pushed 0/);
    expect(body).toMatch(/behavioral_credstuff_push_last_candidates 6/);
  });

  it('reflète le mode enforce dans push_mode et push_total[ok]', async () => {
    app = buildApp({
      config: baseConfig,
      behavioralCredStuffPushMode: 'enforce',
      fetcher: async () => new Response('', { status: 200 }),
    });
    await app.inject({ method: 'POST', url: '/v1/behavioral/credstuff/push' });
    const res = await app.inject({ method: 'GET', url: '/metrics' });
    const body = res.body;
    expect(body).toContain('behavioral_credstuff_push_mode{mode="enforce"} 1');
    expect(body).toContain('behavioral_credstuff_push_mode{mode="shadow"} 0');
    expect(body).toMatch(/behavioral_credstuff_push_total\{status="ok"\} 1/);
    expect(body).toMatch(/behavioral_credstuff_push_last_pushed 1/);
  });

  it('reflète une erreur réseau dans push_total[error]', async () => {
    app = buildApp({
      config: baseConfig,
      behavioralCredStuffPushMode: 'enforce',
      fetcher: async () => {
        throw new TypeError('ECONNREFUSED');
      },
    });
    await app.inject({ method: 'POST', url: '/v1/behavioral/credstuff/push' });
    const res = await app.inject({ method: 'GET', url: '/metrics' });
    expect(res.body).toMatch(/behavioral_credstuff_push_total\{status="error"\} 1/);
  });
});
