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
    return { id: s.id, label: s.label, count: fams.length, blocked, rate, enabled };
  });
</script>

<div class="page">
  <header class="page-head">
    <div>
      <h1>Pipeline</h1>
      <p>Architecture des étages de mitigation traversés par chaque requête.</p>
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
      <span class="tick mono">
        {$snapshot.lastTickAt ? $snapshot.lastTickAt.toLocaleTimeString() : '—'}
      </span>
    </div>
  </header>

  {#if $snapshot.metricsError}
    <div class="banner-err mono">métriques injoignables : {$snapshot.metricsError}</div>
  {/if}

  <section class="diagram-wrap">
    <PipelineDiagram
      families={FAMILIES}
      rates={$snapshot.ratesByMetric}
      blocked={$snapshot.blockedByMetric}
      statusOf={statusOf}
    />
  </section>

  <section class="legend">
    <div class="legend-item"><span class="dot active"></span> active</div>
    <div class="legend-item"><span class="dot dormant"></span> dormant</div>
    <div class="legend-item"><span class="dot error"></span> erreur control plane</div>
    <div class="legend-item"><span class="line-cold"></span> flux nominal</div>
    <div class="legend-item"><span class="line-hot"></span> flux avec blocages</div>
  </section>

  <section class="stages-grid">
    {#each stageStats as s (s.id)}
      <div class="stage-card">
        <div class="stage-num mono">S{s.id}</div>
        <div class="stage-name">{s.label}</div>
        <div class="stage-stats mono">
          <span title="familles">{s.count} fam.</span>
          <span class="dim">·</span>
          <span title="règles activées">{s.enabled} actives</span>
          <span class="dim">·</span>
          <span class:hot={s.rate > 0}>{s.rate > 0 ? '+' + fmt(s.rate) + '/s' : fmt(s.blocked)}</span>
        </div>
      </div>
    {/each}
  </section>
</div>

<style>
  .page { display: flex; flex-direction: column; gap: 18px; max-width: 1600px; }

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

  .diagram-wrap {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 8px;
  }

  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    padding: 10px 14px;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 11.5px;
    color: var(--text-faint);
  }
  .legend-item { display: inline-flex; align-items: center; gap: 6px; }
  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    display: inline-block;
  }
  .dot.active  { background: var(--ok); box-shadow: 0 0 6px rgba(16, 185, 129, 0.6); }
  .dot.dormant { background: var(--text-faint); }
  .dot.error   { background: var(--err); box-shadow: 0 0 6px rgba(239, 68, 68, 0.6); }
  .line-cold {
    width: 22px; height: 1px;
    background: var(--border-strong);
    display: inline-block;
  }
  .line-hot {
    width: 22px; height: 1px;
    background: var(--neon-orange);
    box-shadow: 0 0 6px var(--neon-orange-glow);
    display: inline-block;
  }

  .stages-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 10px;
  }
  @media (max-width: 1100px) {
    .stages-grid { grid-template-columns: repeat(2, 1fr); }
  }
  .stage-card {
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px 14px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }
  .stage-num {
    font-size: 10.5px;
    color: var(--text-faint);
    letter-spacing: 0.6px;
    font-weight: 600;
  }
  .stage-name {
    font-size: 13px;
    color: var(--text);
    font-weight: 500;
  }
  .stage-stats {
    display: flex;
    gap: 6px;
    font-size: 11.5px;
    color: var(--text-dim);
    font-variant-numeric: tabular-nums;
  }
  .stage-stats .dim { color: var(--text-faint); }
  .stage-stats .hot { color: var(--neon-orange); font-weight: 600; }
</style>
