<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { FAMILIES, type FamilyDef } from '../lib/families';
  import Sparkline from './Sparkline.svelte';
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

  function ev(s: MetricsSnapshot, f: FamilyDef): number  { return s.evaluatedByMetric[f.metric] ?? 0; }
  function blk(s: MetricsSnapshot, f: FamilyDef): number { return s.blockedByMetric[f.metric] ?? 0; }
  function rt(s: MetricsSnapshot, f: FamilyDef): number  { return s.ratesByMetric[f.metric] ?? 0; }

  $: totalEv  = FAMILIES.reduce((a, f) => a + ev($snapshot, f), 0);
  $: totalBlk = FAMILIES.reduce((a, f) => a + blk($snapshot, f), 0);
  $: totalRt  = FAMILIES.reduce((a, f) => a + rt($snapshot, f), 0);
  $: passPct  = totalEv > 0 ? (1 - totalBlk / totalEv) * 100 : 100;
  $: rps      = $history['__total_rps']?.slice(-1)[0] ?? 0;
  $: activeFams = FAMILIES.filter((f) => famStatusOf($snapshot, f) === 'active').length;
</script>

<section class="page">
  <header class="head">
    <div>
      <h1>Overview</h1>
      <p>État global — débit, mitigations, blocages.</p>
    </div>
    <div class="meta">
      <label>
        refresh
        <select bind:value={$pollMs}>
          <option value={1000}>1s</option>
          <option value={2000}>2s</option>
          <option value={5000}>5s</option>
          <option value={10000}>10s</option>
        </select>
      </label>
      <span class="tick mono">{$snapshot.lastTickAt ? $snapshot.lastTickAt.toLocaleTimeString() : '—'}</span>
    </div>
  </header>

  {#if $snapshot.metricsError}
    <div class="err mono">métriques injoignables : {$snapshot.metricsError}</div>
  {/if}

  <div class="kpis">
    <div class="kpi">
      <span class="lbl">req / s</span>
      <span class="val mono">{fmt(rps)}</span>
      <Sparkline values={$history['__total_rps'] ?? []} width={120} height={22} />
    </div>
    <div class="kpi">
      <span class="lbl">évalués</span>
      <span class="val mono">{fmt(totalEv)}</span>
    </div>
    <div class="kpi">
      <span class="lbl">bloqués</span>
      <span class="val mono">{fmt(totalBlk)}</span>
    </div>
    <div class="kpi">
      <span class="lbl">block Δ/s</span>
      <span class="val mono" class:hot={totalRt > 0}>{totalRt > 0 ? '+' + fmt(totalRt) : '0'}</span>
    </div>
    <div class="kpi">
      <span class="lbl">pass</span>
      <span class="val mono">{passPct.toFixed(1)}<span class="unit">%</span></span>
    </div>
    <div class="kpi">
      <span class="lbl">familles actives</span>
      <span class="val mono">{activeFams}<span class="unit">/{FAMILIES.length}</span></span>
    </div>
  </div>

  <table class="t">
    <thead>
      <tr>
        <th>Famille</th>
        <th class="num">Stage</th>
        <th class="num">Évalués</th>
        <th class="num">Bloqués</th>
        <th class="num">Δ/s</th>
        <th class="num">Règles</th>
        <th>Statut</th>
      </tr>
    </thead>
    <tbody>
      {#each FAMILIES as f (f.id)}
        {@const st = famStatusOf($snapshot, f)}
        {@const r = rt($snapshot, f)}
        <tr>
          <td><a href="#/m/{f.id}">{f.label}</a></td>
          <td class="mono num dim">S{f.stage}</td>
          <td class="mono num">{fmt(ev($snapshot, f))}</td>
          <td class="mono num">{fmt(blk($snapshot, f))}</td>
          <td class="mono num" class:hot={r > 0}>{r > 0 ? '+' + fmt(r) : '—'}</td>
          <td class="mono num dim">{$snapshot.famState[f.id]?.enabled ?? 0}/{$snapshot.famState[f.id]?.total ?? 0}</td>
          <td><span class="badge {st}">{st}</span></td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>

<style>
  .page { display: flex; flex-direction: column; gap: 16px; max-width: 1280px; }

  .head {
    display: flex; justify-content: space-between; align-items: flex-start;
    gap: 16px; flex-wrap: wrap;
  }
  h1 { margin: 0; font-size: 17px; font-weight: 600; color: var(--text); letter-spacing: -0.2px; }
  .head p { margin: 2px 0 0; font-size: 12px; color: var(--text-faint); }

  .meta { display: flex; align-items: center; gap: 10px; font-size: 11.5px; color: var(--text-faint); }
  .meta select { font-size: 11.5px; padding: 2px 6px; }
  .tick { font-variant-numeric: tabular-nums; }

  .err {
    padding: 8px 12px; font-size: 12px;
    border: 1px solid var(--border-strong); border-radius: 6px;
    color: var(--err); background: var(--bg-elev);
  }

  .kpis {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 1px;
    background: var(--border);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  .kpi {
    background: var(--bg-elev);
    padding: 12px 14px;
    display: flex; flex-direction: column; gap: 4px;
    min-width: 0;
  }
  .kpi .lbl {
    font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.5px;
    color: var(--text-faint); font-weight: 500;
  }
  .kpi .val {
    font-size: 18px; font-weight: 600; color: var(--text);
    font-variant-numeric: tabular-nums; line-height: 1.1;
  }
  .kpi .val.hot { color: var(--accent); }
  .kpi .unit   { font-size: 12px; color: var(--text-faint); font-weight: 500; margin-left: 1px; }

  @media (max-width: 1100px) { .kpis { grid-template-columns: repeat(3, 1fr); } }
  @media (max-width: 640px)  { .kpis { grid-template-columns: repeat(2, 1fr); } }

  .t {
    width: 100%; border-collapse: collapse; font-size: 12.5px;
    background: var(--bg-elev); border: 1px solid var(--border); border-radius: 8px;
    overflow: hidden;
  }
  .t th, .t td {
    padding: 9px 14px; text-align: left;
    border-bottom: 1px solid var(--border); vertical-align: middle;
  }
  .t thead th {
    font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.5px;
    font-weight: 500; color: var(--text-faint);
    background: transparent;
  }
  .t tbody tr:last-child td { border-bottom: none; }
  .t tbody tr:hover td { background: var(--bg-row); }
  .t .num { text-align: right; font-variant-numeric: tabular-nums; }
  .t .dim { color: var(--text-faint); }
  .t .hot { color: var(--accent); font-weight: 600; }
  .t a { color: var(--text); }
  .t a:hover { color: var(--accent); }

  .badge {
    display: inline-block; padding: 1px 7px;
    border: 1px solid var(--border-strong); border-radius: 999px;
    font-size: 10.5px; font-weight: 500; color: var(--text-faint);
  }
  .badge.active  { color: var(--ok);  border-color: rgba(47, 224, 161, 0.4); }
  .badge.dormant { color: var(--text-faint); }
  .badge.error   { color: var(--err); border-color: rgba(255, 90, 106, 0.4); }
</style>
