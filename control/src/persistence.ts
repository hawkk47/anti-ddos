// State persistence for mitigation stores.
//
// Each family snapshot is stored as `<stateDir>/<family>.json` :
//   { "version": 1, "rules": [<rule>, ...] }
//
// Loaded once at boot (replaying `store.put(rule)`), then dumped on
// every successful PUT via a Fastify `onResponse` hook. Writes are
// atomic (tmp + rename) so a crash mid-write leaves the previous
// snapshot intact.
//
// Fail-open philosophy: corrupted or missing snapshots log a warning
// and start empty rather than blocking the control plane. Cf.
// .github/instructions/control-plane.instructions.md.

import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';

const SNAPSHOT_VERSION = 1;

/**
 * Minimal contract every mitigation store satisfies.
 * `put` may throw on validation failure — restored rules are trusted
 * since they were previously accepted, but errors are caught and
 * logged at load time.
 */
export interface PersistableStore<TRule> {
  list(): { rev: number; rules: TRule[] };
  put(rule: TRule): { rev: number };
}

export interface FamilyBinding {
  family: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  store: PersistableStore<any>;
}

interface SnapshotFile {
  version: number;
  rules: unknown[];
}

function snapshotPath(stateDir: string, family: string): string {
  return join(stateDir, `${family}.json`);
}

function ensureDir(stateDir: string): void {
  if (!existsSync(stateDir)) {
    mkdirSync(stateDir, { recursive: true });
  }
}

/**
 * Read `<stateDir>/<family>.json` and replay each rule into the
 * store. Missing or corrupt files are skipped with a log line.
 */
export function loadSnapshot(
  app: FastifyInstance,
  stateDir: string,
  binding: FamilyBinding,
): number {
  const path = snapshotPath(stateDir, binding.family);
  if (!existsSync(path)) return 0;
  let parsed: SnapshotFile;
  try {
    const raw = readFileSync(path, 'utf8');
    parsed = JSON.parse(raw) as SnapshotFile;
  } catch (err) {
    app.log.warn({ msg: 'snapshot read failed', family: binding.family, path, err: (err as Error).message });
    return 0;
  }
  if (parsed.version !== SNAPSHOT_VERSION || !Array.isArray(parsed.rules)) {
    app.log.warn({ msg: 'snapshot schema mismatch', family: binding.family, path });
    return 0;
  }
  let restored = 0;
  for (const rule of parsed.rules) {
    try {
      binding.store.put(rule);
      restored += 1;
    } catch (err) {
      app.log.warn({
        msg: 'snapshot rule rejected',
        family: binding.family,
        err: (err as Error).message,
      });
    }
  }
  return restored;
}

/**
 * Write the current snapshot of one family atomically.
 * Writes a tmp file then renames over the destination — safe on
 * Windows and POSIX.
 */
export function saveSnapshot(
  app: FastifyInstance,
  stateDir: string,
  binding: FamilyBinding,
): void {
  ensureDir(stateDir);
  const path = snapshotPath(stateDir, binding.family);
  const tmp = `${path}.tmp`;
  const data: SnapshotFile = {
    version: SNAPSHOT_VERSION,
    rules: binding.store.list().rules,
  };
  try {
    writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
    renameSync(tmp, path);
  } catch (err) {
    app.log.error({ msg: 'snapshot write failed', family: binding.family, path, err: (err as Error).message });
  }
}

/**
 * Wire persistence to a Fastify app:
 *   1. ensures the state dir exists,
 *   2. replays every snapshot into its store synchronously,
 *   3. registers an `onResponse` hook that dumps the matching
 *      family when a 2xx PUT lands on `/v1/mitigations/<family>/...`.
 */
export function registerPersistence(
  app: FastifyInstance,
  stateDir: string,
  bindings: FamilyBinding[],
): void {
  // Opt-out: empty stateDir disables persistence entirely (test mode).
  if (stateDir === '') {
    app.log.debug({ msg: 'persistence disabled (empty stateDir)' });
    return;
  }
  ensureDir(stateDir);

  const byFamily = new Map<string, FamilyBinding>();
  for (const b of bindings) {
    byFamily.set(b.family, b);
    const restored = loadSnapshot(app, stateDir, b);
    if (restored > 0) {
      app.log.info({ msg: 'snapshot restored', family: b.family, rules: restored });
    }
  }

  app.addHook('onResponse', (req, reply, done) => {
    if (req.method !== 'PUT' || reply.statusCode < 200 || reply.statusCode >= 300) {
      done();
      return;
    }
    // Match /v1/mitigations/<family>/<rid>
    const m = /^\/v1\/mitigations\/([^/?]+)\//.exec(req.url);
    if (!m) {
      done();
      return;
    }
    const family = m[1] ?? '';
    const binding = byFamily.get(family);
    if (binding) saveSnapshot(app, stateDir, binding);
    done();
  });
}
