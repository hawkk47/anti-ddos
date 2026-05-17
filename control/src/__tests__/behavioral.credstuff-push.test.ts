import { describe, it, expect, afterEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app.js';
import {
  createInMemoryBehavioralCredStuffStore,
  type BehavioralCredStuffStore,
} from '../behavioral/credstuff.js';
import {
  createBehavioralCredStuffPusher,
  type PushResult,
} from '../behavioral/credstuff-push.js';

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

function fillCandidates(
  store: BehavioralCredStuffStore,
  nowMs: number,
  ips: string[],
): void {
  // Trigger heuristic 2 (distinct IPs per user) en envoyant N IPs distinctes.
  for (const ip of ips) {
    store.ingest({
      username_hash: userHash('a'),
      success: false,
      source_ip: ip,
      ts: Math.floor(nowMs / 1000),
    });
  }
}

describe('createBehavioralCredStuffPusher — shadow mode', () => {
  it('ne fait aucun appel réseau et retourne status=shadow', async () => {
    const nowMs = 1_700_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({ now: () => nowMs });
    fillCandidates(store, nowMs, [
      '203.0.113.1',
      '203.0.113.2',
      '203.0.113.3',
      '203.0.113.4',
      '203.0.113.5',
      '203.0.113.6',
    ]);

    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls += 1;
      return new Response('nope', { status: 500 });
    };
    const pusher = createBehavioralCredStuffPusher({
      store,
      proxyAdminUrl: 'http://127.0.0.1:8081',
      fetcher,
      now: () => nowMs,
      initialMode: 'shadow',
    });

    const r = await pusher.push();
    expect(calls).toBe(0);
    expect(r.status).toBe('shadow');
    expect(r.pushed).toBe(false);
    expect(r.candidates).toBe(6);
    expect(r.version).toBe(1);
    expect(pusher.lastResult()).toEqual(r);
  });

  it('incrémente la version monotone à chaque push', async () => {
    const store = createInMemoryBehavioralCredStuffStore({ now: () => 0 });
    const pusher = createBehavioralCredStuffPusher({
      store,
      proxyAdminUrl: 'http://127.0.0.1:8081',
      fetcher: async () => new Response('', { status: 200 }),
      initialMode: 'shadow',
    });
    const v1 = (await pusher.push()).version;
    const v2 = (await pusher.push()).version;
    const v3 = (await pusher.push()).version;
    expect(v1).toBe(1);
    expect(v2).toBe(2);
    expect(v3).toBe(3);
  });
});

describe('createBehavioralCredStuffPusher — enforce mode', () => {
  it('envoie un PUT JSON avec entries RFC 3339 sur succès', async () => {
    const nowMs = 1_700_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({ now: () => nowMs });
    fillCandidates(store, nowMs, [
      '203.0.113.1',
      '203.0.113.2',
      '203.0.113.3',
      '203.0.113.4',
      '203.0.113.5',
      '203.0.113.6',
    ]);

    type Captured = { url: string; init: RequestInit };
    const captured: Captured[] = [];
    const fetcher: typeof fetch = async (input, init) => {
      captured.push({ url: String(input), init: init ?? {} });
      return new Response('', { status: 200 });
    };
    const pusher = createBehavioralCredStuffPusher({
      store,
      proxyAdminUrl: 'http://127.0.0.1:8081/',
      fetcher,
      now: () => nowMs,
      initialMode: 'enforce',
    });

    const r = await pusher.push();
    expect(r.status).toBe('ok');
    expect(r.pushed).toBe(true);
    expect(r.candidates).toBe(6);
    expect(captured).toHaveLength(1);
    expect(captured[0].url).toBe('http://127.0.0.1:8081/_admin/v1/blocklist/credstuff');
    expect(captured[0].init.method).toBe('PUT');
    const body = JSON.parse(String(captured[0].init.body)) as {
      version: number;
      entries: Array<{ ip: string; expires_at: string; reason: string }>;
    };
    expect(body.version).toBe(1);
    expect(body.entries).toHaveLength(6);
    // RFC 3339 with Z suffix.
    expect(body.entries[0].expires_at).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.*Z$/);
    expect(body.entries[0].reason).toContain('distinct_ips_per_user');
  });

  it('mappe un 409 proxy en status=stale_version', async () => {
    const store = createInMemoryBehavioralCredStuffStore({ now: () => 0 });
    const pusher = createBehavioralCredStuffPusher({
      store,
      proxyAdminUrl: 'http://127.0.0.1:8081',
      fetcher: async () => new Response('{"error":"replace_failed"}', { status: 409 }),
      initialMode: 'enforce',
    });
    const r = await pusher.push();
    expect(r.status).toBe('stale_version');
    expect(r.pushed).toBe(false);
    expect(r.error).toContain('409');
  });

  it('mappe une erreur réseau en status=error', async () => {
    const store = createInMemoryBehavioralCredStuffStore({ now: () => 0 });
    const pusher = createBehavioralCredStuffPusher({
      store,
      proxyAdminUrl: 'http://127.0.0.1:8081',
      fetcher: async () => {
        throw new TypeError('connect ECONNREFUSED');
      },
      initialMode: 'enforce',
    });
    const r = await pusher.push();
    expect(r.status).toBe('error');
    expect(r.pushed).toBe(false);
    expect(r.error).toContain('ECONNREFUSED');
  });

  it('envoie le header Authorization Bearer si proxyAdminToken fourni', async () => {
    const nowMs = 1_700_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({ now: () => nowMs });
    fillCandidates(store, nowMs, [
      '203.0.113.10',
      '203.0.113.11',
      '203.0.113.12',
      '203.0.113.13',
      '203.0.113.14',
      '203.0.113.15',
    ]);
    let captured: Record<string, string> | undefined;
    const fetcher: typeof fetch = async (_input, init) => {
      const h = (init?.headers ?? {}) as Record<string, string>;
      captured = h;
      return new Response('', { status: 200 });
    };
    const pusher = createBehavioralCredStuffPusher({
      store,
      proxyAdminUrl: 'http://127.0.0.1:8081',
      proxyAdminToken: 'proxy-secret-token-1234567890',
      fetcher,
      now: () => nowMs,
      initialMode: 'enforce',
    });
    const r = await pusher.push();
    expect(r.status).toBe('ok');
    expect(captured?.['authorization']).toBe('Bearer proxy-secret-token-1234567890');
    expect(captured?.['content-type']).toBe('application/json');
  });

  it('n\'envoie pas Authorization si proxyAdminToken absent', async () => {
    const nowMs = 1_700_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({ now: () => nowMs });
    fillCandidates(store, nowMs, [
      '203.0.113.20',
      '203.0.113.21',
      '203.0.113.22',
      '203.0.113.23',
      '203.0.113.24',
      '203.0.113.25',
    ]);
    let captured: Record<string, string> | undefined;
    const fetcher: typeof fetch = async (_input, init) => {
      captured = (init?.headers ?? {}) as Record<string, string>;
      return new Response('', { status: 200 });
    };
    const pusher = createBehavioralCredStuffPusher({
      store,
      proxyAdminUrl: 'http://127.0.0.1:8081',
      fetcher,
      now: () => nowMs,
      initialMode: 'enforce',
    });
    await pusher.push();
    expect(captured?.['authorization']).toBeUndefined();
  });
});

describe('routes HTTP /v1/behavioral/credstuff/push', () => {
  it('POST /push retourne PushResult en shadow par défaut', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({ method: 'POST', url: '/v1/behavioral/credstuff/push' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as PushResult;
    expect(body.mode).toBe('shadow');
    expect(body.status).toBe('shadow');
    expect(body.pushed).toBe(false);
    expect(body.candidates).toBe(0);
  });

  it('GET /push renvoie 404 tant qu\'aucun push n\'a eu lieu', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({ method: 'GET', url: '/v1/behavioral/credstuff/push' });
    expect(res.statusCode).toBe(404);
    expect((res.json() as { error: string; mode: string }).error).toBe('no_push_yet');
  });

  it('GET /push renvoie le dernier résultat après push', async () => {
    app = buildApp({ config: baseConfig });
    await app.inject({ method: 'POST', url: '/v1/behavioral/credstuff/push' });
    const res = await app.inject({ method: 'GET', url: '/v1/behavioral/credstuff/push' });
    expect(res.statusCode).toBe(200);
    expect((res.json() as PushResult).version).toBe(1);
  });

  it('POST /push/mode bascule shadow → enforce', async () => {
    app = buildApp({ config: baseConfig });
    const r1 = await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/push/mode',
      payload: { mode: 'enforce' },
      headers: { 'content-type': 'application/json' },
    });
    expect(r1.statusCode).toBe(200);
    expect((r1.json() as { mode: string }).mode).toBe('enforce');

    const r2 = await app.inject({ method: 'GET', url: '/v1/behavioral/credstuff/push/mode' });
    expect((r2.json() as { mode: string }).mode).toBe('enforce');
  });

  it('POST /push/mode rejette un mode invalide', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/push/mode',
      payload: { mode: 'paranoid' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });

  it('en enforce avec fetcher injecté, /push appelle le data plane', async () => {
    let calls = 0;
    const fetcher: typeof fetch = async () => {
      calls += 1;
      return new Response('', { status: 200 });
    };
    app = buildApp({
      config: baseConfig,
      fetcher,
      behavioralCredStuffPushMode: 'enforce',
    });
    const res = await app.inject({ method: 'POST', url: '/v1/behavioral/credstuff/push' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as PushResult;
    expect(body.status).toBe('ok');
    expect(body.pushed).toBe(true);
    expect(calls).toBe(1);
  });
});
