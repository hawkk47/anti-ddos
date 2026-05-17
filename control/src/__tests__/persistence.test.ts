import { describe, it, expect, afterEach, beforeEach } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { mkdtempSync, rmSync, existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { buildApp } from '../app.js';

let app: FastifyInstance | undefined;
let stateDir: string;

beforeEach(() => {
  stateDir = mkdtempSync(join(tmpdir(), 'antiddos-state-'));
});

afterEach(async () => {
  if (app) {
    await app.close();
    app = undefined;
  }
  try {
    rmSync(stateDir, { recursive: true, force: true });
  } catch {
    /* ignore */
  }
});

const baseConfig = () => ({
  listenHost: '127.0.0.1',
  listenPort: 0,
  logLevel: 'fatal' as const,
  proxyAdminUrl: 'http://127.0.0.1:8080',
  stateDir,
});

const slowloris = {
  id: 'slowloris',
  enabled: true,
  on_error: 'allow',
  params: { max_conns_per_ip: 64 },
};

describe('state persistence', () => {
  it('dumps a snapshot file after a successful PUT', async () => {
    app = buildApp({ config: baseConfig() });

    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/connections/slowloris',
      headers: { 'content-type': 'application/json' },
      payload: slowloris,
    });
    expect(res.statusCode).toBe(200);

    const path = join(stateDir, 'connections.json');
    expect(existsSync(path)).toBe(true);
    const parsed = JSON.parse(readFileSync(path, 'utf8')) as {
      version: number;
      rules: Array<{ id: string }>;
    };
    expect(parsed.version).toBe(1);
    expect(parsed.rules).toHaveLength(1);
    expect(parsed.rules[0]?.id).toBe('slowloris');
  });

  it('replays a snapshot on boot into the store', async () => {
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(
      join(stateDir, 'connections.json'),
      JSON.stringify({ version: 1, rules: [slowloris] }),
      'utf8',
    );

    app = buildApp({ config: baseConfig() });

    const res = await app.inject({
      method: 'GET',
      url: '/v1/mitigations/connections',
    });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { rev: number; rules: Array<{ id: string }> };
    expect(body.rules).toHaveLength(1);
    expect(body.rules[0]?.id).toBe('slowloris');
    expect(body.rev).toBeGreaterThanOrEqual(1);
  });

  it('survives a full restart cycle (PUT, close, rebuild, GET)', async () => {
    app = buildApp({ config: baseConfig() });
    const put = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/connections/slowloris',
      headers: { 'content-type': 'application/json' },
      payload: slowloris,
    });
    expect(put.statusCode).toBe(200);
    await app.close();

    app = buildApp({ config: baseConfig() });
    const res = await app.inject({ method: 'GET', url: '/v1/mitigations/connections' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { rules: Array<{ id: string }> };
    expect(body.rules).toHaveLength(1);
    expect(body.rules[0]?.id).toBe('slowloris');
  });

  it('ignores a corrupt snapshot and starts empty', async () => {
    mkdirSync(stateDir, { recursive: true });
    writeFileSync(join(stateDir, 'connections.json'), '{not json', 'utf8');

    app = buildApp({ config: baseConfig() });
    const res = await app.inject({ method: 'GET', url: '/v1/mitigations/connections' });
    expect(res.statusCode).toBe(200);
    const body = res.json() as { rules: unknown[] };
    expect(body.rules).toHaveLength(0);
  });

  it('does NOT dump for a 4xx response (validation failure)', async () => {
    app = buildApp({ config: baseConfig() });
    const res = await app.inject({
      method: 'PUT',
      url: '/v1/mitigations/connections/slowloris',
      headers: { 'content-type': 'application/json' },
      payload: { id: 'wrong-id', enabled: true, on_error: 'allow', params: {} },
    });
    expect(res.statusCode).toBeGreaterThanOrEqual(400);
    expect(existsSync(join(stateDir, 'connections.json'))).toBe(false);
  });
});
