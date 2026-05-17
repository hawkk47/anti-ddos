<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api } from '../lib/api';
  import { parsePromText, type MetricFamily } from '../lib/prom';
  import type { FamilyDef } from '../lib/families';
  import StatusPill from './StatusPill.svelte';

  let pollTimer: ReturnType<typeof setInterval> | null = null;

  export let families: FamilyDef[];

  // État par famille : rev + nb règles + nb actives + erreur.
  interface FamilyState {
    loading: boolean;
    error?: string;
    rev?: number;
    total: number;
    enabled: number;
  }
  let state: Record<string, FamilyState> = Object.fromEntries(
    families.map((f) => [f.id, { loading: true, total: 0, enabled: 0 }]),
  );

  let metrics: MetricFamily[] = [];
  let metricsError: string | null = null;
  let metricsAt: Date | null = null;
  let reloading = false;
  let reloadMsg: string | null = null;

  async function refreshAll() {
    await Promise.all(families.map(refreshOne));
    await refreshMetrics();
  }

  async function refreshOne(f: FamilyDef) {
    state = { ...state, [f.id]: { ...state[f.id]!, loading: true, error: undefined } };
    try {
      const p = await api.listFamily(f.id);
      state = {
        ...state,
        [f.id]: {
          loading: false,
          rev: p.rev,
          total: p.rules.length,
          enabled: p.rules.filter((r) => r.enabled).length,
        },
      };
    } catch (e) {
      state = {
        ...state,
        [f.id]: { loading: false, total: 0, enabled: 0, error: (e as Error).message },
      };
    }
  }

  async function refreshMetrics() {
    try {
      const txt = await api.metrics();
      metrics = parsePromText(txt);
      metricsError = null;
      metricsAt = new Date();
    } catch (e) {
      metricsError = (e as Error).message;
    }
  }

  async function triggerReload() {
    reloading = true; reloadMsg = null;
    try {
      const res = await api.reload();
      reloadMsg = `OK — ${res.pushed} règles poussées.`;
      await refreshAll();
    } catch (e) {
      reloadMsg = `Erreur : ${(e as Error).message}`;
    } finally {
      reloading = false;
    }
  }

  function summaryFilter(name: string): boolean {
    return name.startsWith('mitigation_') &&
      (name.endsWith('_blocked_total') ||
        name.endsWith('_denied_total') ||
        name.endsWith('_rejected_total') ||
        name.endsWith('_dropped_total') ||
        name.endsWith('_throttled_total') ||
        name.endsWith('_active'));
  }

  function labelsOf(l: Record<string, string>): string {
    const keys = Object.keys(l);
    if (keys.length === 0) return '—';
    return keys.map((k) => `${k}="${l[k]}"`).join(', ');
  }
  function formatNum(v: number): string {
    if (Number.isInteger(v)) return v.toLocaleString('en-US');
    return v.toFixed(3);
  }

  $: summary = metrics.filter((m) => summaryFilter(m.name));

  onMount(() => {
    refreshAll();
    pollTimer = setInterval(() => { refreshMetrics(); }, 5000);
  });
  onDestroy(() => {
    if (pollTimer) clearInterval(pollTimer);
  });
</script>

<header class="bar">
  <div>
    <h1>Dashboard</h1>
    <div class="sub">vue d'ensemble des familles et des métriques exposées.</div>
  </div>
  <div class="actions">
    <button on:click={refreshAll}>Rafraîchir</button>
    <button class="primary" on:click={triggerReload} disabled={reloading}>
      {reloading ? 'Reload…' : 'POST /v1/reload'}
    </button>
    {#if reloadMsg}<span class="msg mono">{reloadMsg}</span>{/if}
  </div>
</header>

<section class="neon-card"><i class="corners"><i></i></i>
  <div class="sec-head">
    <span class="neon-label">families</span>
    <span class="sec-title">État des familles</span>
  </div>
  <table class="neon-table">
    <thead>
      <tr>
        <th>ID</th>
        <th>Famille</th>
        <th>Rev</th>
        <th>Règles</th>
        <th>Actives</th>
        <th>Statut</th>
        <th></th>
      </tr>
    </thead>
    <tbody>
      {#each families as f (f.id)}
        <tr>
          <td class="mono">{f.id}</td>
          <td>{f.label}</td>
          <td class="mono num">{state[f.id]?.rev ?? '—'}</td>
          <td class="num">{state[f.id]?.total ?? 0}</td>
          <td class="num">{state[f.id]?.enabled ?? 0}</td>
          <td>
            {#if state[f.id]?.loading}<span class="badge dim">…</span>
            {:else if state[f.id]?.error}<StatusPill kind="err" label={state[f.id]?.error ?? ''} />
            {:else if (state[f.id]?.enabled ?? 0) === 0}<StatusPill kind="warn" label="dormant" />
            {:else}<StatusPill kind="ok" label="actif" />
            {/if}
          </td>
          <td><a href="#/m/{f.id}">configurer →</a></td>
        </tr>
      {/each}
    </tbody>
  </table>
</section>

<section class="neon-card blue"><i class="corners"><i></i></i>
  <div class="sec-head">
    <span class="neon-label blue">metrics</span>
    <span class="sec-title">
      Métriques — synthèse
      {#if metricsAt}<span class="ts mono">@ {metricsAt.toLocaleTimeString()}</span>{/if}
    </span>
  </div>
  {#if metricsError}
    <p class="err">Erreur : <code>{metricsError}</code></p>
  {:else if summary.length === 0}
    <p class="dim pad">Aucune métrique anti-ddos exposée pour l'instant.</p>
  {:else}
    <table class="neon-table">
      <thead>
        <tr><th>Métrique</th><th>Labels</th><th class="num">Valeur</th></tr>
      </thead>
      <tbody>
        {#each summary as fam (fam.name)}
          {#each fam.samples as s, i (fam.name + i)}
            <tr>
              <td class="mono">{fam.name}</td>
              <td class="mono lbls">{labelsOf(s.labels)}</td>
              <td class="mono num">{formatNum(s.value)}</td>
            </tr>
          {/each}
        {/each}
      </tbody>
    </table>
  {/if}
</section>

<style>
  .bar {
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    margin-bottom: 16px;
    padding-bottom: 10px;
    border-bottom: 1px solid var(--neon-card-border);
    gap: 12px;
  }
  h1 { font-size: 18px; margin: 0; font-weight: 600; color: var(--text); }
  .sub { color: var(--text-dim); font-size: 12px; margin-top: 2px; }
  .actions { display: flex; gap: 8px; align-items: center; }
  .msg { color: var(--text-dim); }
  section { padding: 12px; margin-bottom: 14px; }
  .sec-head {
    display: flex; align-items: baseline; gap: 10px;
    padding-bottom: 8px;
  }
  .sec-title { color: var(--text); font-size: 13px; font-weight: 500; }
  .ts { color: var(--text-faint); font-size: 11px; margin-left: 6px; font-weight: normal; text-transform: none; letter-spacing: 0; }
  .pad { padding: 6px 4px; }

  .neon-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  .neon-table th, .neon-table td {
    padding: 6px 10px;
    border-bottom: 1px solid var(--neon-card-border);
    text-align: left;
    vertical-align: middle;
  }
  .neon-table th {
    background: rgba(255,255,255,0.02);
    color: var(--text-dim);
    font-weight: 500;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }
  .neon-table .num { text-align: right; }
  .neon-table .dim { color: var(--text-faint); }
  .neon-table tr:hover td { background: rgba(255,255,255,0.02); }
  .num { text-align: right; }
  .lbls { color: var(--text-dim); max-width: 480px; word-break: break-all; }
  .err { color: var(--err); }
  .dim { color: var(--text-faint); }
</style>
