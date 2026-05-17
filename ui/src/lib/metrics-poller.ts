// Poller unique partagé entre les pages Overview / Pipeline / Dashboard.
// Démarre dès qu'au moins un consommateur s'abonne, s'arrête quand le
// compteur retombe à 0 — pas de polling fantôme.

import { writable, type Readable } from 'svelte/store';
import { api } from './api';
import { parsePromText, type MetricFamily } from './prom';
import { FAMILIES, type FamilyDef } from './families';
import { pushHistory, setControlUp, setProxyUp } from './stores';

interface CounterSnap { value: number; at: number }
export interface FamilyState {
  rev?: number;
  total: number;
  enabled: number;
  err?: string;
}

export interface MetricsSnapshot {
  metricsByFamily: Record<string, MetricFamily>;
  famState: Record<string, FamilyState>;
  blockedByMetric: Record<string, number>;
  evaluatedByMetric: Record<string, number>;
  ratesByMetric: Record<string, number>;
  evalRatesByMetric: Record<string, number>;
  metricsError: string | null;
  lastTickAt: Date | null;
  proxyUp: boolean;
}

const initial: MetricsSnapshot = {
  metricsByFamily: {},
  famState: {},
  blockedByMetric: {},
  evaluatedByMetric: {},
  ratesByMetric: {},
  evalRatesByMetric: {},
  metricsError: null,
  lastTickAt: null,
  proxyUp: false,
};

const snapStore = writable<MetricsSnapshot>(initial);
const pollMsStore = writable<number>(2000);

let prevBlocked: Record<string, CounterSnap> = {};
let lastBlocked: Record<string, CounterSnap> = {};
let prevEval: Record<string, CounterSnap> = {};
let lastEval: Record<string, CounterSnap> = {};
let timer: ReturnType<typeof setInterval> | null = null;
let refCount = 0;
let currentPoll = 2000;

function sumSamples(m?: MetricFamily): number {
  if (!m) return 0;
  return m.samples.reduce((a, s) => a + (Number.isFinite(s.value) ? s.value : 0), 0);
}

function deltaRate(prev: Record<string, CounterSnap>, last: Record<string, CounterSnap>, key: string): number {
  const a = prev[key];
  const b = last[key];
  if (!a || !b) return 0;
  const dt = (b.at - a.at) / 1000;
  if (dt <= 0) return 0;
  const d = b.value - a.value;
  return d > 0 ? d / dt : 0;
}

async function tickFamilies(): Promise<Record<string, FamilyState>> {
  const results = await Promise.all(
    FAMILIES.map(async (f) => {
      try {
        const p = await api.listFamily(f.id);
        return [f.id, {
          rev: p.rev,
          total: p.rules.length,
          enabled: p.rules.filter((r) => r.enabled).length,
        }] as const;
      } catch (e) {
        return [f.id, { total: 0, enabled: 0, err: (e as Error).message }] as const;
      }
    }),
  );
  setControlUp(results.some(([, s]) => !('err' in s)));
  return Object.fromEntries(results);
}

async function tickMetrics(): Promise<Omit<MetricsSnapshot, 'famState'>> {
  try {
    const txt = await api.metrics();
    const list = parsePromText(txt);
    const idx: Record<string, MetricFamily> = {};
    for (const m of list) idx[m.name] = m;

    const now = Date.now();
    const nextBlk: Record<string, CounterSnap> = {};
    const nextEv: Record<string, CounterSnap> = {};
    const blockedByMetric: Record<string, number> = {};
    const evaluatedByMetric: Record<string, number> = {};
    for (const f of FAMILIES) {
      const blk = sumSamples(idx[`${f.metric}_blocked_total`]);
      const ev  = sumSamples(idx[`${f.metric}_evaluated_total`]);
      blockedByMetric[f.metric]   = blk;
      evaluatedByMetric[f.metric] = ev;
      nextBlk[f.metric] = { value: blk, at: now };
      nextEv[f.metric]  = { value: ev, at: now };
    }
    prevBlocked = lastBlocked; lastBlocked = nextBlk;
    prevEval    = lastEval;    lastEval    = nextEv;

    const ratesByMetric: Record<string, number> = {};
    const evalRatesByMetric: Record<string, number> = {};
    for (const f of FAMILIES) {
      ratesByMetric[f.metric]     = deltaRate(prevBlocked, lastBlocked, f.metric);
      evalRatesByMetric[f.metric] = deltaRate(prevEval, lastEval, f.metric);
      pushHistory(f.metric, ratesByMetric[f.metric]);
    }
    const totalRps = Math.max(...Object.values(evalRatesByMetric), 0);
    pushHistory('__total_rps', totalRps);
    const totalBlk = Object.values(ratesByMetric).reduce((a, b) => a + b, 0);
    pushHistory('__total_blk', totalBlk);

    setProxyUp(true);
    return {
      metricsByFamily: idx,
      blockedByMetric,
      evaluatedByMetric,
      ratesByMetric,
      evalRatesByMetric,
      metricsError: null,
      proxyUp: true,
      lastTickAt: new Date(now),
    };
  } catch (e) {
    setProxyUp(false);
    return {
      metricsByFamily: {},
      blockedByMetric: {},
      evaluatedByMetric: {},
      ratesByMetric: {},
      evalRatesByMetric: {},
      lastTickAt: null,
      metricsError: (e as Error).message,
      proxyUp: false,
    };
  }
}

async function tick(): Promise<void> {
  const [fams, mets] = await Promise.all([tickFamilies(), tickMetrics()]);
  snapStore.set({ ...mets, famState: fams });
}

function startTimer(): void {
  stopTimer();
  void tick();
  timer = setInterval(() => { void tick(); }, currentPoll);
}
function stopTimer(): void {
  if (timer) { clearInterval(timer); timer = null; }
}

pollMsStore.subscribe((ms) => {
  if (ms !== currentPoll) {
    currentPoll = ms;
    if (refCount > 0) startTimer();
  }
});

/**
 * S'abonne au poller partagé. Renvoie un objet `stop()` à appeler en
 * `onDestroy` pour décrémenter le compteur de refs.
 */
export function usePoller(): { stop: () => void } {
  refCount++;
  if (refCount === 1) startTimer();
  return {
    stop: () => {
      refCount = Math.max(0, refCount - 1);
      if (refCount === 0) stopTimer();
    },
  };
}

export const snapshot: Readable<MetricsSnapshot> = { subscribe: snapStore.subscribe };
export const pollMs = pollMsStore;

export function famStatusOf(s: MetricsSnapshot, f: FamilyDef): 'active' | 'dormant' | 'error' | 'unknown' {
  const st = s.famState[f.id];
  if (!st) return 'unknown';
  if (st.err) return 'error';
  if (st.enabled > 0) return 'active';
  return 'dormant';
}

export function fmt(n: number): string {
  if (!Number.isFinite(n)) return '0';
  if (n === 0) return '0';
  if (n < 1) return n.toFixed(2);
  if (n < 10) return n.toFixed(1);
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
  return n.toFixed(0);
}
