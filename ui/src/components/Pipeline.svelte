<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { FAMILIES, PIPELINE_STAGES, type FamilyDef } from '../lib/families';
  import PipelineDiagram from './PipelineDiagram.svelte';
  import { usePoller, snapshot, pollMs, famStatusOf, fmt } from '../lib/metrics-poller';

  let poller: { stop: () => void } | null = null;
  onMount(() => { poller = usePoller(); });
  onDestroy(() => { poller?.stop(); });

  function statusOf(f: FamilyDef) {
    return famStatusOf($snapshot, f);
  }

  $: stageStats = PIPELINE_STAGES.map((s) => {
    const fams = FAMILIES.filter((f) => f.stage === s.id);
    const blocked = fams.reduce((a, f) => a + ($snapshot.blockedByMetric[f.metric] ?? 0), 0);
    const rate    = fams.reduce((a, f) => a + ($snapshot.ratesByMetric[f.metric]   ?? 0), 0);
    const enabled = fams.reduce((a, f) => a + ($snapshot.famState[f.id]?.enabled ?? 0), 0);
    const total   = fams.reduce((a, f) => a + ($snapshot.famState[f.id]?.total ?? 0), 0);
    return { id: s.id, label: s.label, count: fams.length, blocked, rate, enabled, total };
  });
</script>

<section class="page">
  <header class="head">
    <div>
      <h1>Pipeline</h1>
      <p>Étages de mitigation traversés par chaque requête.</p>
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

  <div class="diagram">
    <PipelineDiagram
      families={FAMILIES}
      rates={$snapshot.ratesByMetric}
      blocked={$snapshot.blockedByMetric}
      statusOf={statusOf}
    />
  </div>

  <div class="legend">
    <span><i class="dot ok"></i> active</span>
    <span><i class="dot dim"></i> dormant</span>
    <span><i class="dot err"></i> erreur</span>
    <span><i class="line cold"></i> nominal</span>
    <span><i class="line hot"></i> blocages</span>
  </div>

  <table class="t">
    <thead>
      <tr>
        <th>Stage</th>
        <th>Nom</th>
        <th class="num">Familles</th>
        <th class="num">Règles actives</th>
        <th class="num">Bloqués</th>
        <th class="num">Δ/s</th>
      </tr>
    </thead>
    <tbody>
      {#each stageStats as s (s.id)}
        <tr>
          <td class="mono dim">S{s.id}</td>
          <td>{s.label}</td>
          <td class="mono num">{s.count}</td>
          <td class="mono num dim">{s.enabled}/{s.total}</td>
          <td class="mono num">{fmt(s.blocked)}</td>
          <td class="mono num" class:hot={s.rate > 0}>{s.rate > 0 ? '+' + fmt(s.rate) : '—'}</td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>

<style>
  .page { display: flex; flex-direction: column; gap: 16px; max-width: 1400px; }

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

  .diagram {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
  }

  .legend {
    display: flex; flex-wrap: wrap; gap: 16px;
    padding: 8px 14px;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 11.5px; color: var(--text-faint);
  }
  .legend span { display: inline-flex; align-items: center; gap: 6px; }
  .dot { width: 7px; height: 7px; border-radius: 50%; display: inline-block; }
  .dot.ok  { background: var(--ok); }
  .dot.dim { background: var(--text-faint); }
  .dot.err { background: var(--err); }
  .line { width: 20px; height: 1px; display: inline-block; }
  .line.cold { background: var(--border-strong); }
  .line.hot  { background: var(--accent); }

  .t {
    width: 100%; border-collapse: collapse; font-size: 12.5px;
    background: var(--bg-elev); border: 1px solid var(--border); border-radius: 8px;
    overflow: hidden;
  }
  .t th, .t td {
    padding: 9px 14px; text-align: left;
    border-bottom: 1px solid var(--border);
  }
  .t thead th {
    font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.5px;
    font-weight: 500; color: var(--text-faint);
  }
  .t tbody tr:last-child td { border-bottom: none; }
  .t tbody tr:hover td { background: var(--bg-row); }
  .t .num { text-align: right; font-variant-numeric: tabular-nums; }
  .t .dim { color: var(--text-faint); }
  .t .hot { color: var(--accent); font-weight: 600; }
</style>
