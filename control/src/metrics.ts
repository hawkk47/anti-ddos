/**
 * Phase 5 ADR 0004 — Endpoint /metrics control plane.
 *
 * Expose les compteurs du store behavioral (phase 3) et du pusher
 * (phase 4) au format Prometheus text exposition 0.0.4. Aucun
 * dépendance externe : on génère le texte à la main, comme le data
 * plane (proxy/internal/adminapi/metrics.go).
 *
 * Mêmes contraintes que côté proxy : pas de PII, pas de label
 * dynamique avec IP ou username_hash. Les seuls labels sont des
 * énumérations finies (result, status, mode).
 */
import type { FastifyInstance } from 'fastify';
import type { BehavioralCredStuffStore } from './behavioral/credstuff.js';
import type { BehavioralCredStuffPusher, PushResult } from './behavioral/credstuff-push.js';

export interface ControlMetricsDeps {
  behavioralStore: BehavioralCredStuffStore;
  behavioralPusher: BehavioralCredStuffPusher;
}

const STATUSES: ReadonlyArray<PushResult['status']> = [
  'shadow',
  'ok',
  'stale_version',
  'error',
  'noop',
];

export function registerMetricsRoute(app: FastifyInstance, deps: ControlMetricsDeps): void {
  app.route({
    method: 'GET',
    url: '/metrics',
    // Pas de schéma JSON : on retourne du text/plain.
    handler: async (_req, reply) => {
      const state = deps.behavioralStore.state();
      const m = deps.behavioralPusher.metrics();
      const lines: string[] = [];

      // --- ingestion ---
      lines.push('# HELP behavioral_credstuff_events_total Auth events seen by ingestion endpoint, partitioned by result.');
      lines.push('# TYPE behavioral_credstuff_events_total counter');
      lines.push(`behavioral_credstuff_events_total{result="ingested"} ${state.totals.ingested}`);
      lines.push(`behavioral_credstuff_events_total{result="accepted"} ${state.totals.accepted}`);
      lines.push(`behavioral_credstuff_events_total{result="rejected"} ${state.totals.rejected}`);

      // --- état candidat ---
      lines.push('# HELP behavioral_credstuff_candidates Current IPs flagged as candidates for blocklist push.');
      lines.push('# TYPE behavioral_credstuff_candidates gauge');
      lines.push(`behavioral_credstuff_candidates ${state.candidates.length}`);

      lines.push('# HELP behavioral_credstuff_tracked_users Current distinct username_hash tracked in sliding window.');
      lines.push('# TYPE behavioral_credstuff_tracked_users gauge');
      lines.push(`behavioral_credstuff_tracked_users ${state.trackedUsers}`);

      lines.push('# HELP behavioral_credstuff_tracked_ips Current distinct source_ip tracked in sliding window.');
      lines.push('# TYPE behavioral_credstuff_tracked_ips gauge');
      lines.push(`behavioral_credstuff_tracked_ips ${state.trackedIPs}`);

      lines.push('# HELP behavioral_credstuff_state_version Monotonic state version (bumped on every mutation).');
      lines.push('# TYPE behavioral_credstuff_state_version gauge');
      lines.push(`behavioral_credstuff_state_version ${state.version}`);

      // --- pushes ---
      lines.push('# HELP behavioral_credstuff_push_total Push attempts to data plane partitioned by terminal status.');
      lines.push('# TYPE behavioral_credstuff_push_total counter');
      for (const s of STATUSES) {
        lines.push(`behavioral_credstuff_push_total{status="${s}"} ${m.pushTotals[s]}`);
      }

      lines.push('# HELP behavioral_credstuff_push_mode Active pusher mode (1 if active, 0 otherwise).');
      lines.push('# TYPE behavioral_credstuff_push_mode gauge');
      lines.push(`behavioral_credstuff_push_mode{mode="shadow"} ${m.mode === 'shadow' ? 1 : 0}`);
      lines.push(`behavioral_credstuff_push_mode{mode="enforce"} ${m.mode === 'enforce' ? 1 : 0}`);

      lines.push('# HELP behavioral_credstuff_push_last_version Monotonic version of the most recent push attempt.');
      lines.push('# TYPE behavioral_credstuff_push_last_version gauge');
      lines.push(`behavioral_credstuff_push_last_version ${m.lastVersion}`);

      lines.push('# HELP behavioral_credstuff_push_last_at_seconds UNIX timestamp (seconds) of the most recent push attempt.');
      lines.push('# TYPE behavioral_credstuff_push_last_at_seconds gauge');
      lines.push(`behavioral_credstuff_push_last_at_seconds ${m.lastAtMs > 0 ? (m.lastAtMs / 1000).toFixed(3) : '0'}`);

      lines.push('# HELP behavioral_credstuff_push_last_pushed 1 if last push reached the data plane (HTTP 2xx), 0 otherwise.');
      lines.push('# TYPE behavioral_credstuff_push_last_pushed gauge');
      lines.push(`behavioral_credstuff_push_last_pushed ${m.lastPushed}`);

      lines.push('# HELP behavioral_credstuff_push_last_candidates Number of candidates included in the last push.');
      lines.push('# TYPE behavioral_credstuff_push_last_candidates gauge');
      lines.push(`behavioral_credstuff_push_last_candidates ${m.lastCandidates}`);

      reply
        .header('content-type', 'text/plain; version=0.0.4; charset=utf-8')
        .code(200)
        .send(lines.join('\n') + '\n');
    },
  });
}
