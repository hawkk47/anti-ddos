import { describe, it, expect, afterEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../app.js';
import { createInMemoryBehavioralCredStuffStore } from '../behavioral/credstuff.js';

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

// 64 chars hex (SHA-256 placeholder). On varie le dernier nibble pour
// avoir des users distincts sans recoder la moindre logique de hash.
function userHash(nibble: string): string {
  return '0'.repeat(63) + nibble;
}

function event(opts: {
  user?: string;
  ip?: string;
  success?: boolean;
  ts?: number;
  ua?: string;
}): Record<string, unknown> {
  const ev: Record<string, unknown> = {
    username_hash: opts.user ?? userHash('a'),
    success: opts.success ?? false,
    source_ip: opts.ip ?? '203.0.113.10',
    ts: opts.ts ?? Math.floor(Date.now() / 1000),
  };
  if (opts.ua !== undefined) ev.user_agent = opts.ua;
  return ev;
}

describe('POST /v1/behavioral/credstuff/auth-event', () => {
  it('accepts a single failed event', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/auth-event',
      payload: event({}),
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(202);
    const body = res.json() as { status: string; version: number };
    expect(body.status).toBe('accepted');
    expect(body.version).toBe(1);
  });

  it('accepts a successful event but does not feed heuristics', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/auth-event',
      payload: event({ success: true }),
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(202);
    const state = await app.inject({
      method: 'GET',
      url: '/v1/behavioral/credstuff/state',
    });
    const body = state.json() as { totals: { accepted: number }; trackedIPs: number };
    expect(body.totals.accepted).toBe(1);
    expect(body.trackedIPs).toBe(0);
  });

  it('rejects malformed payload (short hash)', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/auth-event',
      payload: { ...event({}), username_hash: 'too-short' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
    expect((res.json() as { error: string }).error).toBe('invalid_event');
  });

  it('rejects invalid source_ip length only when out of bounds', async () => {
    app = buildApp({ config: baseConfig });
    // < 3 chars
    const res = await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/auth-event',
      payload: { ...event({}), source_ip: 'a' },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('POST /v1/behavioral/credstuff/auth-events (batch)', () => {
  it('accepts a batch and counts ingestion', async () => {
    app = buildApp({ config: baseConfig });
    const evs = Array.from({ length: 5 }, (_, i) =>
      event({ ip: `203.0.113.${i + 1}` }),
    );
    const res = await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/auth-events',
      payload: { events: evs },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(202);
    const body = res.json() as { ingested: number };
    expect(body.ingested).toBe(5);
  });

  it('rejects an empty batch', async () => {
    app = buildApp({ config: baseConfig });
    const res = await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/auth-events',
      payload: { events: [] },
      headers: { 'content-type': 'application/json' },
    });
    expect(res.statusCode).toBe(400);
  });
});

describe('GET /v1/behavioral/credstuff/state — heuristiques', () => {
  it('heuristique 1 : > 20 échecs par user → toutes ses IPs candidates', async () => {
    let nowMs = 1_000_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({
      now: () => nowMs,
    });
    // 21 échecs depuis la même IP, même user.
    for (let i = 0; i < 21; i++) {
      store.ingest({
        username_hash: userHash('a'),
        success: false,
        source_ip: '203.0.113.10',
        ts: Math.floor(nowMs / 1000),
      });
    }
    const s = store.state();
    expect(s.candidates).toHaveLength(1);
    expect(s.candidates[0].ip).toBe('203.0.113.10');
    expect(s.candidates[0].reasons).toContain('failed_per_user');
  });

  it('heuristique 2 : > 5 IPs distinctes par user → toutes candidates', async () => {
    const nowMs = 1_000_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({
      now: () => nowMs,
    });
    for (let i = 1; i <= 6; i++) {
      store.ingest({
        username_hash: userHash('a'),
        success: false,
        source_ip: `203.0.113.${i}`,
        ts: Math.floor(nowMs / 1000),
      });
    }
    const s = store.state();
    expect(s.candidates).toHaveLength(6);
    for (const c of s.candidates) {
      expect(c.reasons).toContain('distinct_ips_per_user');
    }
  });

  it('heuristique 3 : > 50 échecs par IP → cette IP candidate', async () => {
    const nowMs = 1_000_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({
      now: () => nowMs,
    });
    // 51 échecs depuis la même IP, users variés (chiffres 0-9 + lettres a-f).
    const nibbles = '0123456789abcdef';
    for (let i = 0; i < 51; i++) {
      store.ingest({
        username_hash: userHash(nibbles[i % 16]) + '_pad'.padEnd(0),
        success: false,
        source_ip: '198.51.100.7',
        ts: Math.floor(nowMs / 1000),
      });
    }
    const s = store.state();
    const target = s.candidates.find((c) => c.ip === '198.51.100.7');
    expect(target).toBeDefined();
    expect(target!.reasons).toContain('failed_per_ip');
  });

  it('seuils sous le déclenchement : aucun candidat', async () => {
    const nowMs = 1_000_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({
      now: () => nowMs,
    });
    for (let i = 0; i < 5; i++) {
      store.ingest({
        username_hash: userHash('a'),
        success: false,
        source_ip: '203.0.113.10',
        ts: Math.floor(nowMs / 1000),
      });
    }
    expect(store.state().candidates).toHaveLength(0);
  });

  it('événement hors fenêtre est rejeté', async () => {
    let nowMs = 1_000_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({
      now: () => nowMs,
      thresholds: { windowMs: 60_000 },
    });
    store.ingest({
      username_hash: userHash('a'),
      success: false,
      source_ip: '203.0.113.10',
      ts: Math.floor(nowMs / 1000) - 3600, // 1h dans le passé
    });
    expect(store.state().totals.rejected).toBe(1);
    expect(store.state().trackedIPs).toBe(0);
  });

  it('événement du futur (> 5 min) est rejeté', async () => {
    const nowMs = 1_000_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({
      now: () => nowMs,
    });
    store.ingest({
      username_hash: userHash('a'),
      success: false,
      source_ip: '203.0.113.10',
      ts: Math.floor(nowMs / 1000) + 10 * 60, // 10 min dans le futur
    });
    expect(store.state().totals.rejected).toBe(1);
  });

  it('expiration : événements vieillis dégagent les candidats', async () => {
    let nowMs = 1_000_000_000_000;
    const store = createInMemoryBehavioralCredStuffStore({
      now: () => nowMs,
      thresholds: { windowMs: 60_000 },
    });
    for (let i = 0; i < 21; i++) {
      store.ingest({
        username_hash: userHash('a'),
        success: false,
        source_ip: '203.0.113.10',
        ts: Math.floor(nowMs / 1000),
      });
    }
    expect(store.state().candidates).toHaveLength(1);
    // Avance horloge au-delà de la fenêtre.
    nowMs += 120_000;
    expect(store.state().candidates).toHaveLength(0);
    expect(store.state().trackedIPs).toBe(0);
  });
});

describe('DELETE /v1/behavioral/credstuff/state', () => {
  it('reset purge l\'état mais incrémente la version', async () => {
    app = buildApp({ config: baseConfig });
    await app.inject({
      method: 'POST',
      url: '/v1/behavioral/credstuff/auth-event',
      payload: event({}),
      headers: { 'content-type': 'application/json' },
    });
    const v1 = (
      (await app.inject({ method: 'GET', url: '/v1/behavioral/credstuff/state' })).json() as {
        version: number;
        trackedIPs: number;
      }
    );
    expect(v1.trackedIPs).toBe(1);

    const reset = await app.inject({
      method: 'DELETE',
      url: '/v1/behavioral/credstuff/state',
    });
    expect(reset.statusCode).toBe(200);

    const v2 = (
      (await app.inject({ method: 'GET', url: '/v1/behavioral/credstuff/state' })).json() as {
        version: number;
        trackedIPs: number;
      }
    );
    expect(v2.trackedIPs).toBe(0);
    expect(v2.version).toBeGreaterThan(v1.version);
  });
});
