<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { FAMILIES, type FamilyDef } from '../lib/families';
  import HeroSpike from './HeroSpike.svelte';
  import WorldHeat from './WorldHeat.svelte';
  import { history } from '../lib/stores';
  import {
    usePoller,
    snapshot,
    pollMs,
    famStatusOf,
    fmt,
    type MetricsSnapshot,
  } from '../lib/metrics-poller';

  let poller: { stop: () => void } | null = null;
  onMount(() => { poller = usePoller(); });
  onDestroy(() => { poller?.stop(); });

  function familyEvaluated(s: MetricsSnapshot, f: FamilyDef): number {
    return s.evaluatedByMetric[f.metric] ?? 0;
  }
  function familyBlocked(s: MetricsSnapshot, f: FamilyDef): number {
    return s.blockedByMetric[f.metric] ?? 0;
  }
  function rateOf(s: MetricsSnapshot, f: FamilyDef): number {
    return s.ratesByMetric[f.metric] ?? 0;
  }

  $: totalBlocked   = FAMILIES.reduce((a, f) => a + familyBlocked($snapshot, f), 0);
  $: totalEvaluated = FAMILIES.reduce((a, f) => a + familyEvaluated($snapshot, f), 0);
  $: totalRate      = FAMILIES.reduce((a, f) => a + rateOf($snapshot, f), 0);
  $: passRate       = totalEvaluated > 0 ? (1 - totalBlocked / totalEvaluated) * 100 : 100;
</script>

<div class="page">
  <header class="page-head">
    <div>
      <h1>Overview</h1>
      <p>État global du data plane — débit, blocages, géographie.</p>
    </div>
    <div class="controls">
      <label class="poll" title="Intervalle de rafraîchissement">
        <span>refresh</span>
        <select bind:value={$pollMs}>
          <option value={1000}>1s</option>
          <option value={2000}>2s</option>
          <option value={5000}>5s</option>
          <option value={10000}>10s</option>
        </select>
      </label>
      <span class="tick mono" title="Dernier poll">
        {$snapshot.lastTickAt ? $snapshot.lastTickAt.toLocaleTimeString() : '—'}
      </span>
    </div>
  </header>

  {#if $snapshot.metricsError}
    <div class="banner-err mono">métriques injoignables : {$snapshot.metricsError}</div>
  {/if}

  <div class="kpi-strip">
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

  <HeroSpike
    values={$history['__total_rps'] ?? []}
    label="req/s"
    title="Débit data plane"
    subtitle="Δ/s sur la fenêtre courante"
    height={88}
  />

  <div class="bottom-row">
    <WorldHeat metrics={$snapshot.metricsByFamily} />

    <section class="panel activity">
      <header class="panel-head">
        <h2>Activité par famille</h2>
        <p>Compteurs cumulés et taux de blocage instantané.</p>
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
              {@const stat = famStatusOf($snapshot, f)}
              {@const ev = familyEvaluated($snapshot, f)}
              {@const blk = familyBlocked($snapshot, f)}
              {@const rate = rateOf($snapshot, f)}
              <tr class:hot={rate > 0}>
                <td><a class="fam-name" href="#/m/{f.id}">{f.label}</a></td>
                <td class="mono dim num">S{f.stage}</td>
                <td class="mono num">{fmt(ev)}</td>
                <td class="mono num">{fmt(blk)}</td>
                <td class="mono num" class:hot-text={rate > 0}>{rate > 0 ? '+' + fmt(rate) : '—'}</td>
                <td class="mono num dim">{$snapshot.famState[f.id]?.enabled ?? 0}/{$snapshot.famState[f.id]?.total ?? 0}</td>
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
  .controls { display: flex; align-items: center; gap: 10px; }

  .poll {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    color: var(--text-faint);
  }
  .poll select { font-size: 11.5px; padding: 3px 6px; }
  .tick { font-size: 11px; color: var(--text-faint); font-variant-numeric: tabular-nums; }

  .banner-err {
    color: var(--err);
    font-size: 12px;
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid rgba(239, 68, 68, 0.35);
    background: rgba(239, 68, 68, 0.06);
  }

  .kpi-strip {
    display: flex;
    align-items: stretch;
    padding: 16px 20px;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 10px;
  }
  .kpi { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 6px; padding-right: 18px; }
  .sep { width: 1px; background: var(--border); margin-right: 18px; }
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

  .panel {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
  }
  .panel-head { padding: 14px 18px; border-bottom: 1px solid var(--border); }
  .panel-head h2 { margin: 0; font-size: 13.5px; font-weight: 600; color: var(--text); }
  .panel-head p { margin: 3px 0 0; font-size: 12px; color: var(--text-faint); }
  .panel-body { padding: 16px 18px; }
  .panel-body.no-pad { padding: 0; }

  .bottom-row {
    display: grid;
    grid-template-columns: minmax(320px, 1fr) minmax(0, 1.7fr);
    gap: 16px;
    align-items: start;
  }
  @media (max-width: 1100px) {
    .bottom-row { grid-template-columns: 1fr; }
  }

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

  .badge {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 999px;
    font-size: 10.5px;
    font-weight: 500;
    border: 1px solid var(--border-strong);
    color: var(--text-faint);
  }
  .badge.ok   { color: var(--ok);  border-color: rgba(16, 185, 129, 0.35); }
  .badge.warn { color: var(--warn); border-color: rgba(245, 158, 11, 0.35); }
  .badge.err  { color: var(--err); border-color: rgba(239, 68, 68, 0.35); }
</style>
