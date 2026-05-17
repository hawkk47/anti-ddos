<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api } from '../lib/api';
  import { parsePromText, type MetricFamily } from '../lib/prom';
  import { FAMILIES, type FamilyDef } from '../lib/families';
  import HeroSpike from './HeroSpike.svelte';
  import PipelineDiagram from './PipelineDiagram.svelte';
  import WorldHeat from './WorldHeat.svelte';
  import { history, pushHistory, setControlUp, setProxyUp } from '../lib/stores';

  interface CounterSnap { value: number; at: number }

  let metricsByFamily: Record<string, MetricFamily> = {};
  let prevBlocked: Record<string, CounterSnap> = {};
  let lastBlocked: Record<string, CounterSnap> = {};
  let prevEval: Record<string, CounterSnap> = {};
  let lastEval: Record<string, CounterSnap> = {};
  let famState: Record<string, { rev?: number; total: number; enabled: number; err?: string }> = {};
  let metricsError: string | null = null;
  let lastTickAt: Date | null = null;
  let proxyUp = false;
  let pollMs = 2000;
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  function sumSamples(m?: MetricFamily): number {
    if (!m) return 0;
    return m.samples.reduce((a, s) => a + (Number.isFinite(s.value) ? s.value : 0), 0);
  }
  function familyBlocked(f: FamilyDef): number {
    return sumSamples(metricsByFamily[`${f.metric}_blocked_total`]);
  }
  function familyEvaluated(f: FamilyDef): number {
    return sumSamples(metricsByFamily[`${f.metric}_evaluated_total`]);
  }
  function delta(prev: Record<string, CounterSnap>, last: Record<string, CounterSnap>, key: string): number {
    const a = prev[key];
    const b = last[key];
    if (!a || !b) return 0;
    const dt = (b.at - a.at) / 1000;
    if (dt <= 0) return 0;
    const d = b.value - a.value;
    if (d <= 0) return 0;
    return d / dt;
  }
  function blockedRate(metricKey: string): number {
    return delta(prevBlocked, lastBlocked, metricKey);
  }
  function evalRate(metricKey: string): number {
    return delta(prevEval, lastEval, metricKey);
  }
  function fmt(n: number): string {
    if (!Number.isFinite(n)) return '0';
    if (n === 0) return '0';
    if (n < 1) return n.toFixed(2);
    if (n < 10) return n.toFixed(1);
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
    return n.toFixed(0);
  }
  function famStatus(f: FamilyDef): 'active' | 'dormant' | 'error' | 'unknown' {
    const s = famState[f.id];
    if (!s) return 'unknown';
    if (s.err) return 'error';
    if (s.enabled > 0) return 'active';
    return 'dormant';
  }

  async function tickFamilies(): Promise<void> {
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
    famState = Object.fromEntries(results);
    setControlUp(results.some(([, s]) => !('err' in s)));
  }

  async function tickMetrics(): Promise<void> {
    try {
      const txt = await api.metrics();
      const list = parsePromText(txt);
      const idx: Record<string, MetricFamily> = {};
      for (const m of list) idx[m.name] = m;
      metricsByFamily = idx;

      const now = Date.now();
      const nextBlk: Record<string, CounterSnap> = {};
      const nextEv: Record<string, CounterSnap> = {};
      for (const f of FAMILIES) {
        nextBlk[f.metric] = { value: familyBlocked(f), at: now };
        nextEv[f.metric] = { value: familyEvaluated(f), at: now };
      }
      prevBlocked = lastBlocked; lastBlocked = nextBlk;
      prevEval = lastEval; lastEval = nextEv;

      // Historiques individuels (sparklines familles) + agrégés.
      for (const f of FAMILIES) {
        pushHistory(f.metric, blockedRate(f.metric));
      }
      // Total RPS = max des Δ/s evaluated d'une famille qui voit tout le
      // trafic — toutes les familles passent par chaque requête mais on
      // prend le max pour absorber les familles désactivées qui n'incrémentent pas.
      const totalRps = Math.max(
        ...FAMILIES.map((f) => evalRate(f.metric)),
        0,
      );
      pushHistory('__total_rps', totalRps);
      const totalBlk = FAMILIES.reduce((a, f) => a + blockedRate(f.metric), 0);
      pushHistory('__total_blk', totalBlk);

      metricsError = null;
      proxyUp = true;
      setProxyUp(true);
      lastTickAt = new Date(now);
    } catch (e) {
      metricsError = (e as Error).message;
      proxyUp = false;
      setProxyUp(false);
    }
  }

  async function tickAll(): Promise<void> {
    await Promise.all([tickFamilies(), tickMetrics()]);
  }
  function startPolling(): void {
    stopPolling();
    pollTimer = setInterval(() => { tickAll(); }, pollMs);
  }
  function stopPolling(): void {
    if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  }

  onMount(() => { tickAll(); startPolling(); });
  onDestroy(() => { stopPolling(); });

  // Vues dérivées passées aux composants enfants.
  $: ratesByMetric = Object.fromEntries(FAMILIES.map((f) => [f.metric, blockedRate(f.metric)]));
  $: blockedByMetric = Object.fromEntries(FAMILIES.map((f) => [f.metric, familyBlocked(f)]));

  $: totalBlocked = FAMILIES.reduce((a, f) => a + familyBlocked(f), 0);
  $: totalEvaluated = FAMILIES.reduce((a, f) => a + familyEvaluated(f), 0);
  $: totalRate = FAMILIES.reduce((a, f) => a + blockedRate(f.metric), 0);
  $: passRate = totalEvaluated > 0 ? (1 - totalBlocked / totalEvaluated) * 100 : 100;
</script>

<div class="page">
  <!-- ===== Page header ===== -->
  <header class="page-head">
    <div>
      <h1>Pipeline</h1>
      <p>Vue temps réel des mitigations, du débit observé et de la géo-distribution.</p>
    </div>
    <div class="controls">
      <span class="pill" class:ok={proxyUp} class:err={!proxyUp}>
        <span class="live-dot" class:green={proxyUp} class:red={!proxyUp}></span>
        {proxyUp ? 'data plane up' : 'data plane down'}
      </span>
      <label class="poll" title="Intervalle de rafraîchissement">
        <span>refresh</span>
        <select bind:value={pollMs} on:change={startPolling}>
          <option value={1000}>1s</option>
          <option value={2000}>2s</option>
          <option value={5000}>5s</option>
          <option value={10000}>10s</option>
        </select>
      </label>
      <span class="tick mono" title="Dernier poll">
        {lastTickAt ? lastTickAt.toLocaleTimeString() : '—'}
      </span>
    </div>
  </header>

  {#if metricsError}
    <div class="banner-err mono">métriques injoignables : {metricsError}</div>
  {/if}

  <!-- ===== KPI strip ===== -->
  <div class="kpi-strip">
    <i class="corners"><i></i></i>
    <div class="kpi">
      <div class="kpi-lbl">requests / s</div>
      <div class="kpi-val mono accent">{fmt($history['__total_rps']?.slice(-1)[0] ?? 0)}</div>
    </div>
    <div class="sep"></div>
    <div class="kpi">
      <div class="kpi-lbl">total evaluated</div>
      <div class="kpi-val mono">{fmt(totalEvaluated)}</div>
    </div>
    <div class="sep"></div>
    <div class="kpi">
      <div class="kpi-lbl">total blocked</div>
      <div class="kpi-val mono">{fmt(totalBlocked)}</div>
    </div>
    <div class="sep"></div>
    <div class="kpi">
      <div class="kpi-lbl">block Δ/s</div>
      <div class="kpi-val mono" class:hot={totalRate > 0}>{fmt(totalRate)}</div>
    </div>
    <div class="sep"></div>
    <div class="kpi">
      <div class="kpi-lbl">pass ratio</div>
      <div class="kpi-val mono">{passRate.toFixed(1)}<span class="unit">%</span></div>
    </div>
  </div>

  <!-- ===== Hero spike ===== -->
  <HeroSpike
    values={$history['__total_rps'] ?? []}
    label="req/s"
    title="Débit data plane"
    subtitle="Évalué tous les {pollMs / 1000}s · Δ/s sur la fenêtre courante"
    height={96}
  />

  <!-- ===== Architecture diagram ===== -->
  <section class="panel">
    <i class="corners"><i></i></i>
    <header class="panel-head">
      <h2>Architecture de mitigation</h2>
      <p>Clients → 5 étages de protection → upstream. Lignes ambre = trafic actif.</p>
    </header>
    <div class="panel-body">
      <PipelineDiagram
        families={FAMILIES}
        rates={ratesByMetric}
        blocked={blockedByMetric}
        statusOf={famStatus}
      />
    </div>
  </section>

  <!-- ===== Bottom row : WorldHeat + Activity table ===== -->
  <div class="bottom-row">
    <WorldHeat metrics={metricsByFamily} />

    <section class="panel activity">
      <i class="corners blue"><i></i></i>
      <header class="panel-head">
        <h2>Activité par famille</h2>
        <p>Compteurs cumulés et taux de blocage instantané par famille de mitigation.</p>
      </header>
      <div class="panel-body no-pad">
        <table class="fam-table">
          <thead>
            <tr>
              <th>Famille</th>
              <th class="num">Stage</th>
              <th class="num">Évalués</th>
              <th class="num">Bloqués</th>
              <th class="num">Δ/s</th>
              <th class="num">Règles</th>
              <th>Statut</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {#each FAMILIES as f (f.id)}
              {@const stat = famStatus(f)}
              {@const ev = familyEvaluated(f)}
              {@const blk = familyBlocked(f)}
              {@const rate = blockedRate(f.metric)}
              <tr class:hot={rate > 0}>
                <td><a class="fam-name" href="#/m/{f.id}">{f.label}</a></td>
                <td class="mono dim num">S{f.stage}</td>
                <td class="mono num">{fmt(ev)}</td>
                <td class="mono num">{fmt(blk)}</td>
                <td class="mono num" class:hot-text={rate > 0}>{rate > 0 ? '+' + fmt(rate) : '—'}</td>
                <td class="mono num dim">{famState[f.id]?.enabled ?? 0}/{famState[f.id]?.total ?? 0}</td>
                <td>
                  <span class="badge"
                        class:ok={stat === 'active'}
                        class:warn={stat === 'dormant'}
                        class:err={stat === 'error'}>{stat}</span>
                </td>
                <td class="cfg-col"><a class="cfg" href="#/m/{f.id}">→</a></td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    </section>
  </div>
</div>

<style>
  .page { display: flex; flex-direction: column; gap: 20px; max-width: 1440px; }

  /* === Page header === */
  .page-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    flex-wrap: wrap;
  }
  .page-head h1 {
    margin: 0;
    font-size: 20px;
    font-weight: 600;
    letter-spacing: -0.3px;
    color: var(--text);
  }
  .page-head p {
    margin: 4px 0 0;
    font-size: 12.5px;
    color: var(--text-faint);
  }
  .controls {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .pill {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    font-size: 11.5px;
    font-weight: 500;
    padding: 5px 10px;
    border-radius: 999px;
    border: 1px solid var(--border-strong);
    background: var(--bg-elev);
    color: var(--text-dim);
  }
  .pill.ok  { color: var(--ok);  border-color: rgba(16, 185, 129, 0.35); }
  .pill.err { color: var(--err); border-color: rgba(239, 68, 68, 0.35); background: rgba(239, 68, 68, 0.05); }

  .poll {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    color: var(--text-faint);
  }
  .poll select {
    font-size: 11.5px;
    padding: 3px 6px;
  }
  .tick {
    font-size: 11px;
    color: var(--text-faint);
    font-variant-numeric: tabular-nums;
  }

  .banner-err {
    color: var(--err);
    font-size: 12px;
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid rgba(239, 68, 68, 0.35);
    background: rgba(239, 68, 68, 0.06);
  }

  /* === KPI strip === */
  .kpi-strip {
    position: relative;
    display: flex;
    align-items: stretch;
    gap: 0;
    padding: 16px 20px;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 10px;
  }
  .kpi {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding-right: 18px;
  }
  .sep {
    width: 1px;
    background: var(--border);
    margin-right: 18px;
  }
  .kpi-lbl {
    font-size: 10.5px;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--text-faint);
  }
  .kpi-val {
    font-size: 22px;
    font-weight: 600;
    color: var(--text);
    line-height: 1;
    font-variant-numeric: tabular-nums;
    letter-spacing: -0.3px;
  }
  .kpi-val.accent { color: var(--neon-orange); text-shadow: 0 0 12px var(--neon-orange-glow); }
  .kpi-val.hot    { color: var(--neon-orange); text-shadow: 0 0 12px var(--neon-orange-glow); }
  .kpi-val .unit  { font-size: 13px; color: var(--text-faint); margin-left: 2px; font-weight: 500; }

  @media (max-width: 900px) {
    .kpi-strip { flex-wrap: wrap; }
    .sep { display: none; }
    .kpi { flex: 1 1 45%; padding: 0; }
  }

  /* === Panel générique === */
  .panel {
    position: relative;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }
  .panel-head {
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
  }
  .panel-head h2 {
    margin: 0;
    font-size: 13.5px;
    font-weight: 600;
    color: var(--text);
  }
  .panel-head p {
    margin: 3px 0 0;
    font-size: 12px;
    color: var(--text-faint);
  }
  .panel-body { padding: 16px 18px; }
  .panel-body.no-pad { padding: 0; }

  /* === Bottom row === */
  .bottom-row {
    display: grid;
    grid-template-columns: minmax(320px, 1fr) minmax(0, 1.7fr);
    gap: 16px;
    align-items: start;
  }
  @media (max-width: 1100px) {
    .bottom-row { grid-template-columns: 1fr; }
  }

  /* === Family table === */
  .fam-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  .fam-table th, .fam-table td {
    padding: 9px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border);
    vertical-align: middle;
  }
  .fam-table thead th {
    color: var(--text-faint);
    font-weight: 500;
    font-size: 10.5px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    background: transparent;
    border-bottom: 1px solid var(--border-strong);
  }
  .fam-table tbody tr:last-child td { border-bottom: none; }
  .fam-table tbody tr:hover td { background: var(--bg-row); }
  .fam-table tr.hot td { background: var(--accent-tint); }
  .fam-table .num { text-align: right; font-variant-numeric: tabular-nums; }
  .fam-table .dim { color: var(--text-faint); }
  .fam-table .hot-text { color: var(--accent); font-weight: 600; }
  .fam-table .fam-name { color: var(--text); font-weight: 500; }
  .fam-table .fam-name:hover { color: var(--accent); }
  .fam-table .cfg-col { text-align: right; }
  .fam-table .cfg {
    color: var(--text-faint);
    font-size: 14px;
    line-height: 1;
    padding: 4px 8px;
    border-radius: 4px;
  }
  .fam-table .cfg:hover { color: var(--accent); background: var(--accent-tint); }
</style>
