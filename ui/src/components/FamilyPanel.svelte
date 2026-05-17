<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { api, type Rule, ApiCallError } from '../lib/api';
  import { parsePromText, type MetricFamily } from '../lib/prom';
  import { PIPELINE_STAGES, type FamilyDef, type FieldDef } from '../lib/families';
  import Sparkline from './Sparkline.svelte';
  import { history, pushHistory, pushToast, setControlUp, setProxyUp } from '../lib/stores';

  export let family: FamilyDef;

  // -------- State --------
  let loading = true;
  let rev: number | null = null;

  // drafts = état édité en cours ; originals = dernier état chargé depuis le
  // serveur (snapshot par règle après chaque GET/PUT). Dirty = drafts ≠ originals.
  let drafts: Record<string, Rule> = {};
  let originals: Record<string, Rule> = {};

  // Per-row busy state, pour ne pas bloquer toutes les règles en même temps.
  let busy: Record<string, boolean> = {};
  let reloadBusy = false;

  // Live metrics pour cette famille uniquement (eval / blocked + Δ/s).
  interface Snap { value: number; at: number }
  let blockedTotal = 0;
  let evaluatedTotal = 0;
  let prevSnap: Snap | null = null;
  let lastSnap: Snap | null = null;
  let proxyUp = false;
  let metricsErr: string | null = null;
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  // Recharge à chaque changement de famille (id).
  let lastLoaded = '';
  $: if (family.id !== lastLoaded) {
    lastLoaded = family.id;
    loadFamily();
    tickMetrics();
  }

  // -------- Helpers --------
  function clone<T>(v: T): T {
    return structuredClone(v);
  }
  function isDirty(id: string): boolean {
    const a = originals[id];
    const b = drafts[id];
    if (!b) return false;
    if (!a) return true; // nouveau brouillon non sauvegardé
    return JSON.stringify(a) !== JSON.stringify(b);
  }
  function anyDirty(): boolean {
    return Object.keys(drafts).some(isDirty);
  }
  function fmt(n: number): string {
    if (n === 0) return '0';
    if (n < 1) return n.toFixed(2);
    if (n < 10) return n.toFixed(1);
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
    return n.toFixed(0);
  }
  function deltaPerSec(): number {
    if (!prevSnap || !lastSnap) return 0;
    const dt = (lastSnap.at - prevSnap.at) / 1000;
    if (dt <= 0) return 0;
    const d = lastSnap.value - prevSnap.value;
    return d > 0 ? d / dt : 0;
  }

  $: enabledCount = Object.values(drafts).filter((r) => r.enabled).length;
  $: totalCount = Object.values(drafts).length;
  $: stageMeta = PIPELINE_STAGES.find((s) => s.id === family.stage);
  $: famStatus = (() => {
    if (metricsErr) return 'error';
    if (enabledCount > 0) return 'active';
    return 'dormant';
  })();
  $: rate = deltaPerSec();
  $: passRate = evaluatedTotal > 0 ? (1 - blockedTotal / evaluatedTotal) * 100 : 100;

  // -------- API ops --------
  async function loadFamily(): Promise<void> {
    loading = true;
    try {
      const p = await api.listFamily(family.id);
      rev = p.rev;
      const next: Record<string, Rule> = {};
      for (const r of p.rules) next[r.id] = clone(r);
      // On préserve les brouillons non encore enregistrés (id non présent côté serveur).
      const localOnly: Record<string, Rule> = {};
      for (const [id, r] of Object.entries(drafts)) {
        if (!next[id] && !originals[id]) localOnly[id] = r;
      }
      originals = next;
      drafts = { ...clone(next), ...localOnly };
      setControlUp(true);
    } catch (e) {
      pushToast('err', `Chargement échoué : ${formatErr(e)}`);
      setControlUp(false);
    } finally {
      loading = false;
    }
  }

  async function tickMetrics(): Promise<void> {
    try {
      const txt = await api.metrics();
      const list = parsePromText(txt);
      const idx: Record<string, MetricFamily> = {};
      for (const m of list) idx[m.name] = m;
      const blk = idx[`${family.metric}_blocked_total`];
      const ev = idx[`${family.metric}_evaluated_total`];
      const sum = (m?: MetricFamily) =>
        m?.samples.reduce((a, s) => a + (Number.isFinite(s.value) ? s.value : 0), 0) ?? 0;
      blockedTotal = sum(blk);
      evaluatedTotal = sum(ev);
      const now = Date.now();
      prevSnap = lastSnap;
      lastSnap = { value: blockedTotal, at: now };
      pushHistory(family.metric, deltaPerSec());
      proxyUp = true;
      setProxyUp(true);
      metricsErr = null;
    } catch (e) {
      metricsErr = formatErr(e);
      proxyUp = false;
      setProxyUp(false);
    }
  }

  async function save(rule: Rule): Promise<void> {
    busy = { ...busy, [rule.id]: true };
    try {
      const res = await api.upsertRule(family.id, rule);
      rev = res.rev;
      originals = { ...originals, [rule.id]: clone(res.rule ?? rule) };
      drafts = { ...drafts, [rule.id]: clone(res.rule ?? rule) };
      pushToast('ok', `${rule.id} enregistré — rev=${res.rev}. Pense à recharger le data plane.`);
    } catch (e) {
      pushToast('err', `Save échoué (${rule.id}) : ${formatErr(e)}`);
    } finally {
      busy = { ...busy, [rule.id]: false };
    }
  }

  async function saveAllDirty(): Promise<void> {
    for (const r of Object.values(drafts)) {
      if (isDirty(r.id)) await save(r);
    }
  }

  function revertRule(id: string): void {
    const orig = originals[id];
    if (!orig) {
      const { [id]: _drop, ...rest } = drafts;
      drafts = rest;
    } else {
      drafts = { ...drafts, [id]: clone(orig) };
    }
  }

  async function reloadDataPlane(): Promise<void> {
    reloadBusy = true;
    try {
      const res = await api.reload();
      pushToast('ok', `Data plane rechargé — ${res.pushed} règles poussées.`);
    } catch (e) {
      pushToast('err', `Reload échoué : ${formatErr(e)}`);
    } finally {
      reloadBusy = false;
    }
  }

  function newRule(): void {
    const suggested = drafts[family.rid] ? `${family.rid}-${Object.keys(drafts).length + 1}` : family.rid;
    const id = window.prompt(`Nouvel id de règle pour ${family.id} :`, suggested);
    if (!id) return;
    const trimmed = id.trim();
    if (!trimmed || drafts[trimmed]) return;
    drafts = {
      ...drafts,
      [trimmed]: {
        id: trimmed,
        enabled: false,
        on_error: 'allow',
        reason: 'created via UI — to be tuned',
        params: emptyParams(family.fields),
      },
    };
  }

  function emptyParams(fields: FieldDef[]): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    for (const f of fields) {
      switch (f.type.kind) {
        case 'bool': out[f.name] = false; break;
        case 'int': out[f.name] = f.type.min ?? 0; break;
        case 'duration': out[f.name] = '0s'; break;
        case 'string': out[f.name] = ''; break;
        case 'enum': out[f.name] = f.type.values[0] ?? ''; break;
        case 'csv': out[f.name] = []; break;
      }
    }
    return out;
  }

  function formatErr(e: unknown): string {
    if (e instanceof ApiCallError) {
      const b = e.body as { code?: string; message?: string } | null;
      return `${e.status} ${b?.code ?? ''} ${b?.message ?? e.message}`.trim();
    }
    return (e as Error).message;
  }

  // CSV chips helpers.
  function csvToString(v: unknown): string {
    return Array.isArray(v) ? v.join(',') : '';
  }
  function stringToCsv(s: string): string[] {
    return s.split(',').map((x) => x.trim()).filter(Boolean);
  }
  function csvChips(v: unknown): string[] {
    return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : [];
  }

  // Param value getters/setters typés pour l'UI.
  function setParam(r: Rule, name: string, value: unknown): void {
    r.params[name] = value;
    drafts = { ...drafts, [r.id]: r };
  }

  // Ctrl+S → save all dirty.
  function onKey(e: KeyboardEvent): void {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's') {
      e.preventDefault();
      if (anyDirty()) saveAllDirty();
    }
  }

  // -------- Lifecycle --------
  onMount(() => {
    window.addEventListener('keydown', onKey);
    pollTimer = setInterval(() => { tickMetrics(); }, 3000);
  });
  onDestroy(() => {
    window.removeEventListener('keydown', onKey);
    if (pollTimer) clearInterval(pollTimer);
  });

  $: draftList = Object.values(drafts).sort((a, b) => a.id.localeCompare(b.id));
</script>

<!-- ============ HEADER ============ -->
<header class="phead">
  <nav class="crumbs mono" aria-label="breadcrumb">
    <a href="#/">Pipeline</a>
    <span class="sep">/</span>
    <span class="dim">S{family.stage} {stageMeta?.label ?? ''}</span>
    <span class="sep">/</span>
    <span>{family.id}</span>
  </nav>
  <div class="title-row">
    <div class="title-main">
      <span class="dot {famStatus}" aria-hidden="true"></span>
      <h1>{family.label}</h1>
      <span class="badge {famStatus}">{famStatus}</span>
      {#if rate > 0}<span class="badge hot mono">+{fmt(rate)}/s</span>{/if}
    </div>
    <div class="actions">
      <span class="pill" class:ok={proxyUp} class:err={!proxyUp} title={metricsErr ?? ''}>
        {proxyUp ? 'proxy up' : 'proxy down'}
      </span>
      <button on:click={loadFamily} disabled={loading} title="Recharger depuis le control plane">↻</button>
      <button on:click={newRule}>+ règle</button>
      <button class="primary" on:click={reloadDataPlane} disabled={reloadBusy}>
        {reloadBusy ? '…' : 'Recharger data plane'}
      </button>
    </div>
  </div>
  <p class="desc">{family.desc} <span class="mono dim">· {family.metric}_*</span></p>

  <div class="kpis">
    <div class="kpi">
      <span class="k-lbl">rev</span>
      <span class="k-val mono">{rev ?? '—'}</span>
    </div>
    <div class="kpi">
      <span class="k-lbl">règles</span>
      <span class="k-val mono">{enabledCount}<span class="dim">/{totalCount}</span></span>
    </div>
    <div class="kpi">
      <span class="k-lbl">évalués</span>
      <span class="k-val mono">{fmt(evaluatedTotal)}</span>
    </div>
    <div class="kpi">
      <span class="k-lbl">bloqués</span>
      <span class="k-val mono" class:hot={blockedTotal > 0}>{fmt(blockedTotal)}</span>
    </div>
    <div class="kpi">
      <span class="k-lbl">Δ/s</span>
      <span class="k-val mono" class:hot={rate > 0}>{fmt(rate)}</span>
    </div>
    <div class="kpi spark-kpi">
      <span class="k-lbl">trend</span>
      <span class="spark-wrap" style="color: var(--warn)">
        <Sparkline values={$history[family.metric] ?? []} width={120} height={18} fill />
      </span>
    </div>
    <div class="kpi">
      <span class="k-lbl">pass</span>
      <span class="k-val mono">{passRate.toFixed(1)}%</span>
    </div>
    <div class="kpi grow">
      <span class="k-lbl">endpoint</span>
      <span class="k-val mono small">/v1/mitigations/{family.id}</span>
    </div>
    {#if anyDirty()}
      <button class="primary save-all" on:click={saveAllDirty} title="Ctrl+S">
        Enregistrer tout
      </button>
    {/if}
  </div>
</header>

<!-- ============ ALERTS ============ -->
<!-- alerts now via global Toasts -->

<!-- ============ BODY ============ -->
{#if loading}
  <p class="dim">Chargement…</p>
{:else if draftList.length === 0}
  <div class="empty">
    <h3>Aucune règle pour <code>{family.id}</code></h3>
    <p>La mitigation est <em>dormante</em>. Crée une règle pour l'activer.</p>
    <p class="hint">Id canonique conseillé : <code>{family.rid}</code></p>
    <button class="primary" on:click={newRule}>+ règle</button>
  </div>
{:else}
  {#each draftList as r (r.id)}
    {@const dirty = isDirty(r.id)}
    {@const isNew = !originals[r.id]}
    <article class="rule" class:dirty class:disabled={!r.enabled}>
      <header class="r-head">
        <div class="r-id">
          <label class="switch" title={r.enabled ? 'Désactiver' : 'Activer'}>
            <input type="checkbox" bind:checked={r.enabled} on:change={() => (drafts = { ...drafts, [r.id]: r })} />
            <span class="slider" aria-hidden="true"></span>
          </label>
          <span class="mono id">{r.id}</span>
          {#if isNew}<span class="badge warn">non sauvegardé</span>
          {:else if dirty}<span class="badge warn">modifié</span>
          {:else}<span class="badge ok">à jour</span>{/if}
        </div>
        <div class="r-actions">
          <div class="segmented" role="radiogroup" aria-label="on_error">
            <button role="radio" aria-checked={r.on_error === 'allow'}
                    class:on={r.on_error === 'allow'}
                    on:click={() => { r.on_error = 'allow'; drafts = { ...drafts, [r.id]: r }; }}
                    title="fail-open : laisse passer si la règle plante">
              fail-open
            </button>
            <button role="radio" aria-checked={r.on_error === 'deny'}
                    class:on={r.on_error === 'deny'} class:danger={r.on_error === 'deny'}
                    on:click={() => { r.on_error = 'deny'; drafts = { ...drafts, [r.id]: r }; }}
                    title="fail-closed : bloque si la règle plante">
              fail-closed
            </button>
          </div>
          {#if dirty}
            <button class="ghost" on:click={() => revertRule(r.id)} title="Annuler les modifs locales">
              revert
            </button>
          {/if}
          <button class="primary" on:click={() => save(r)} disabled={busy[r.id] || !dirty}>
            {busy[r.id] ? '…' : 'Enregistrer'}
          </button>
        </div>
      </header>

      {#if !r.enabled}
        <label class="reason">
          <span class="r-lbl">reason <em class="hint">obligatoire si désactivée</em></span>
          <input type="text" bind:value={r.reason}
                 on:input={() => (drafts = { ...drafts, [r.id]: r })}
                 placeholder="ex: dormant — to be tuned"
                 class:invalid={!r.reason || r.reason.trim() === ''} />
        </label>
      {/if}

      <div class="params">
        {#each family.fields as f (f.name)}
          <div class="param">
            <div class="p-lbl">
              <code>{f.name}</code>
              <span class="hint">{f.label}{f.hint ? ` — ${f.hint}` : ''}</span>
            </div>
            <div class="p-val">
              {#if f.type.kind === 'bool'}
                <label class="switch sm">
                  <input type="checkbox" checked={!!r.params[f.name]}
                         on:change={(e) => setParam(r, f.name, e.currentTarget.checked)} />
                  <span class="slider" aria-hidden="true"></span>
                </label>
                <span class="dim mono sm">{r.params[f.name] ? 'true' : 'false'}</span>
              {:else if f.type.kind === 'int'}
                <input type="number" class="num"
                       min={f.type.min} max={f.type.max}
                       value={Number(r.params[f.name] ?? 0)}
                       on:input={(e) => setParam(r, f.name, Number(e.currentTarget.value))} />
                {#if f.type.min !== undefined && f.type.max !== undefined && (f.type.max - f.type.min) <= 100000}
                  <input type="range" class="slider-in"
                         min={f.type.min} max={f.type.max}
                         value={Number(r.params[f.name] ?? 0)}
                         on:input={(e) => setParam(r, f.name, Number(e.currentTarget.value))} />
                {/if}
              {:else if f.type.kind === 'duration'}
                <input type="text" class="dur" placeholder="ex: 5s, 250ms, 1m"
                       value={String(r.params[f.name] ?? '')}
                       on:input={(e) => setParam(r, f.name, e.currentTarget.value)} />
              {:else if f.type.kind === 'enum'}
                <div class="segmented sm">
                  {#each f.type.values as v (v)}
                    <button class:on={String(r.params[f.name] ?? '') === v}
                            class:danger={v === 'deny'}
                            on:click={() => setParam(r, f.name, v)}>
                      {v}
                    </button>
                  {/each}
                </div>
              {:else if f.type.kind === 'csv'}
                <div class="csv-wrap">
                  <input type="text" placeholder={f.type.placeholder ?? 'a,b,c'}
                         value={csvToString(r.params[f.name])}
                         on:input={(e) => setParam(r, f.name, stringToCsv(e.currentTarget.value))} />
                  {#if csvChips(r.params[f.name]).length > 0}
                    <div class="chips">
                      {#each csvChips(r.params[f.name]) as c (c)}
                        <span class="chip mono">{c}</span>
                      {/each}
                    </div>
                  {/if}
                </div>
              {:else}
                <input type="text" value={String(r.params[f.name] ?? '')}
                       on:input={(e) => setParam(r, f.name, e.currentTarget.value)} />
              {/if}
            </div>
          </div>
        {/each}
      </div>
    </article>
  {/each}
{/if}

<style>
  /* ============ HEADER ============ */
  .phead {
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-bottom: 12px;
  }
  .crumbs {
    display: flex;
    gap: 5px;
    align-items: baseline;
    font-size: 11px;
    color: var(--text-faint);
    margin-bottom: 6px;
  }
  .crumbs a { color: var(--text-dim); }
  .crumbs .sep { color: var(--text-faint); }
  .crumbs .dim { color: var(--text-faint); }

  .title-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    flex-wrap: wrap;
  }
  .title-main { display: flex; align-items: center; gap: 8px; }
  h1 { font-size: 17px; margin: 0; font-weight: 600; }
  .dot { width: 8px; height: 8px; border-radius: 50%; background: var(--text-faint); }
  .dot.active { background: var(--ok); }
  .dot.error { background: var(--err); }
  .dot.dormant { background: var(--text-faint); }

  .desc { margin: 6px 0 8px; color: var(--text-dim); font-size: 12px; }
  .desc .dim { color: var(--text-faint); }

  .actions { display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }

  .pill {
    font-size: 11px;
    padding: 1px 8px;
    border-radius: 10px;
    border: 1px solid var(--border-strong);
    color: var(--text-dim);
  }
  .pill.ok { color: var(--neon-green); border-color: var(--neon-green); }
  .pill.err { color: var(--neon-red); border-color: var(--neon-red); background: rgba(255,90,106,0.08); }

  /* KPI strip — façon barre d'outils compacte, accent néon orange. */
  .kpis {
    display: flex;
    gap: 18px;
    align-items: baseline;
    padding: 10px 14px;
    background: var(--neon-card-bg);
    border: 1px solid var(--neon-card-border);
    border-radius: 4px;
    flex-wrap: wrap;
    position: relative;
  }
  .kpi { display: inline-flex; flex-direction: column; gap: 0; }
  .kpi.grow { margin-left: auto; }
  .k-lbl {
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: var(--text-faint);
  }
  .k-val { font-size: 15px; font-weight: 600; color: var(--text); }
  .k-val.small { font-size: 12px; font-weight: 500; color: var(--text-dim); }
  .k-val.hot { color: var(--neon-orange); }
  .k-val .dim { color: var(--text-faint); font-weight: 400; }
  .spark-kpi { min-width: 130px; }
  .spark-wrap { display: inline-flex; align-items: center; height: 18px; color: var(--neon-orange); }
  .save-all { margin-left: auto; align-self: center; }

  /* Badges + dim helper. */
  .badge.hot { color: var(--neon-orange); border-color: var(--neon-orange); }
  .badge.active { color: var(--neon-green); border-color: var(--neon-green); }
  .badge.dormant { color: var(--text-faint); border-color: var(--neon-card-border); }
  .dim { color: var(--text-faint); }

  /* ============ ALERTS ============ */
  .alert {
    padding: 6px 10px;
    border-radius: 3px;
    margin-bottom: 10px;
    font-size: 12px;
    border: 1px solid;
  }
  .alert.err { color: var(--err); border-color: var(--err); background: var(--danger-bg); }
  .alert.ok { color: var(--ok); border-color: var(--ok); background: transparent; }

  /* ============ EMPTY STATE ============ */
  .empty {
    border: 1px dashed var(--border-strong);
    border-radius: 4px;
    padding: 18px 22px;
    background: var(--bg-elev);
  }
  .empty h3 { margin: 0 0 4px; font-size: 13px; font-weight: 600; }
  .empty p { margin: 4px 0; color: var(--text-dim); font-size: 12px; }
  .empty .hint { color: var(--text-faint); }
  .empty button { margin-top: 8px; }

  /* ============ RULE CARDS ============ */
  article.rule {
    border: 1px solid var(--border);
    border-left-width: 3px;
    background: var(--bg-elev);
    border-radius: 3px;
    padding: 10px 12px;
    margin-bottom: 10px;
    transition: border-color 120ms ease;
  }
  article.rule.disabled { border-left-color: var(--text-faint); opacity: 0.92; }
  article.rule:not(.disabled) { border-left-color: var(--ok); }
  article.rule.dirty { border-left-color: var(--warn); }

  .r-head {
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 12px;
    padding-bottom: 8px;
    margin-bottom: 8px;
    border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
  }
  .r-id { display: flex; align-items: center; gap: 8px; }
  .id { color: var(--text); font-size: 13px; }
  .r-actions { display: flex; align-items: center; gap: 6px; }

  /* Switch (toggle). */
  .switch {
    position: relative;
    display: inline-block;
    width: 32px;
    height: 18px;
    flex-shrink: 0;
  }
  .switch input { opacity: 0; width: 0; height: 0; }
  .switch .slider {
    position: absolute; inset: 0;
    background: var(--border-strong);
    border-radius: 18px;
    transition: background 120ms ease;
    cursor: pointer;
  }
  .switch .slider::before {
    content: '';
    position: absolute;
    height: 12px; width: 12px;
    left: 3px; top: 3px;
    background: var(--bg);
    border-radius: 50%;
    transition: transform 120ms ease;
  }
  .switch input:checked + .slider { background: var(--ok); }
  .switch input:checked + .slider::before { transform: translateX(14px); background: #fff; }
  .switch.sm { width: 26px; height: 14px; }
  .switch.sm .slider::before { height: 10px; width: 10px; left: 2px; top: 2px; }
  .switch.sm input:checked + .slider::before { transform: translateX(12px); }

  /* Segmented control. */
  .segmented {
    display: inline-flex;
    border: 1px solid var(--border-strong);
    border-radius: 3px;
    overflow: hidden;
  }
  .segmented button {
    border: none;
    border-radius: 0;
    background: var(--bg);
    color: var(--text-dim);
    padding: 3px 10px;
    font-size: 11px;
    border-right: 1px solid var(--border-strong);
  }
  .segmented button:last-child { border-right: none; }
  .segmented button:hover { background: var(--bg-row); color: var(--text); }
  .segmented button.on { background: var(--accent-dim); color: #fff; }
  .segmented button.on.danger { background: var(--danger-bg); color: var(--err); border-color: var(--err); }
  .segmented.sm button { padding: 2px 8px; font-size: 10px; }

  button.ghost {
    background: transparent;
    color: var(--text-dim);
    border-color: var(--border);
  }
  button.ghost:hover { color: var(--text); border-color: var(--accent); }

  /* Reason field. */
  .reason {
    display: flex;
    flex-direction: column;
    gap: 4px;
    margin-bottom: 10px;
  }
  .r-lbl { font-size: 11px; color: var(--text-dim); }
  .r-lbl .hint { color: var(--text-faint); font-style: normal; margin-left: 4px; }
  .reason input { width: 100%; }
  input.invalid { border-color: var(--err); background: var(--danger-bg); }

  /* Params grid : 2 colonnes confortables, 1 colonne en mobile. */
  .params {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
    gap: 10px 18px;
  }
  .param {
    display: flex;
    flex-direction: column;
    gap: 3px;
    padding: 4px 6px;
    border-radius: 3px;
    background: var(--bg);
    border: 1px solid var(--border);
  }
  .p-lbl { display: flex; flex-direction: column; }
  .p-lbl code { font-size: 12px; color: var(--text); }
  .p-lbl .hint { font-size: 10px; color: var(--text-faint); }
  .p-val { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
  .p-val input.num { width: 110px; }
  .p-val input.dur { width: 110px; }
  .p-val input[type=text]:not(.dur) { flex: 1 1 180px; }
  .p-val .slider-in { flex: 1 1 80px; min-width: 80px; }
  .sm { font-size: 11px; }

  /* CSV chips. */
  .csv-wrap { display: flex; flex-direction: column; gap: 4px; width: 100%; }
  .chips { display: flex; flex-wrap: wrap; gap: 3px; }
  .chip {
    font-size: 10px;
    padding: 1px 6px;
    border-radius: 8px;
    background: var(--bg-row);
    border: 1px solid var(--border);
    color: var(--text-dim);
  }
</style>
