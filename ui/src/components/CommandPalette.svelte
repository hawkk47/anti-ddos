<script lang="ts">
  // Command palette — fuzzy search sur familles + actions globales.
  // Ouvre via Ctrl/Cmd+K, ferme via Esc.
  import { onMount, onDestroy } from 'svelte';
  import { FAMILIES, PIPELINE_STAGES } from '../lib/families';
  import { api, ApiCallError } from '../lib/api';
  import { pushToast } from '../lib/stores';
  import { cycleTheme } from '../lib/theme';

  interface Item {
    kind: 'nav' | 'action';
    label: string;
    sub?: string;
    href?: string;
    run?: () => void | Promise<void>;
    keys: string; // texte fuzzy match
  }

  let open = false;
  let q = '';
  let cursor = 0;
  let inputEl: HTMLInputElement | null = null;

  function fmtErr(e: unknown): string {
    if (e instanceof ApiCallError) return `${e.status} ${e.message}`;
    return (e as Error).message;
  }

  async function reloadDataPlane(): Promise<void> {
    try {
      const r = await api.reload();
      pushToast('ok', `Data plane rechargé — ${r.pushed} règles.`);
    } catch (e) {
      pushToast('err', `Reload échoué : ${fmtErr(e)}`);
    }
  }

  $: items = buildItems();
  $: filtered = filter(items, q);
  $: if (cursor >= filtered.length) cursor = Math.max(0, filtered.length - 1);

  function buildItems(): Item[] {
    const fams: Item[] = FAMILIES.map((f) => {
      const stage = PIPELINE_STAGES.find((s) => s.id === f.stage);
      return {
        kind: 'nav',
        label: f.label,
        sub: `S${f.stage} ${stage?.label ?? ''} · /v1/mitigations/${f.id}`,
        href: `#/m/${f.id}`,
        keys: `${f.label} ${f.id} ${f.rid} ${f.metric} ${stage?.label ?? ''}`.toLowerCase(),
      };
    });
    const actions: Item[] = [
      { kind: 'nav', label: 'Overview', sub: 'KPI · débit · activité', href: '#/', keys: 'overview accueil home kpi' },
      { kind: 'nav', label: 'Pipeline', sub: 'diagramme par étages', href: '#/pipeline', keys: 'pipeline diagramme etages' },
      { kind: 'action', label: 'Recharger le data plane', sub: 'POST /v1/reload', run: reloadDataPlane, keys: 'reload data plane push deploy' },
      { kind: 'action', label: 'Cycle thème (auto → dark → light)', sub: 'apparence', run: cycleTheme, keys: 'theme dark light mode apparence' },
    ];
    return [...actions, ...fams];
  }

  function filter(list: Item[], query: string): Item[] {
    const q2 = query.trim().toLowerCase();
    if (q2 === '') return list;
    // Fuzzy : chaque caractère doit apparaître dans l'ordre.
    return list.filter((it) => {
      let i = 0;
      for (const ch of it.keys) {
        if (ch === q2[i]) i++;
        if (i >= q2.length) return true;
      }
      return false;
    });
  }

  function show(): void {
    open = true;
    q = '';
    cursor = 0;
    setTimeout(() => inputEl?.focus(), 0);
  }
  function hide(): void {
    open = false;
  }
  async function activate(it: Item): Promise<void> {
    hide();
    if (it.href) {
      location.hash = it.href;
    } else if (it.run) {
      await it.run();
    }
  }

  function onKey(e: KeyboardEvent): void {
    const meta = e.ctrlKey || e.metaKey;
    if (meta && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      open ? hide() : show();
      return;
    }
    if (!open) return;
    if (e.key === 'Escape') { e.preventDefault(); hide(); return; }
    if (e.key === 'ArrowDown') { e.preventDefault(); cursor = Math.min(cursor + 1, filtered.length - 1); return; }
    if (e.key === 'ArrowUp') { e.preventDefault(); cursor = Math.max(cursor - 1, 0); return; }
    if (e.key === 'Enter') {
      e.preventDefault();
      const it = filtered[cursor];
      if (it) activate(it);
    }
  }

  onMount(() => { window.addEventListener('keydown', onKey); });
  onDestroy(() => { window.removeEventListener('keydown', onKey); });
</script>

{#if open}
  <div
    class="overlay"
    on:click={hide}
    on:keydown={(e) => { if (e.key === 'Escape') hide(); }}
    role="dialog"
    aria-modal="true"
    tabindex="-1"
  >
    <div class="palette" on:click|stopPropagation role="presentation">
      <input
        bind:this={inputEl}
        bind:value={q}
        on:input={() => (cursor = 0)}
        placeholder="Tape une famille, une action…  (↑↓ pour naviguer, ⏎ pour valider, Esc pour fermer)"
        aria-label="Recherche"
        autocomplete="off"
      />
      <ul role="listbox">
        {#each filtered as it, i (it.label + (it.href ?? ''))}
          <li
            class:active={i === cursor}
            role="option"
            aria-selected={i === cursor}
            on:click={() => activate(it)}
            on:mouseenter={() => (cursor = i)}
          >
            <span class="kind mono">{it.kind === 'nav' ? '→' : '⚡'}</span>
            <span class="lbl">{it.label}</span>
            {#if it.sub}<span class="sub mono">{it.sub}</span>{/if}
          </li>
        {/each}
        {#if filtered.length === 0}
          <li class="empty">Aucun résultat.</li>
        {/if}
      </ul>
      <footer class="mono">
        <kbd>↑↓</kbd> naviguer · <kbd>⏎</kbd> ouvrir · <kbd>Esc</kbd> fermer · <kbd>Ctrl</kbd>+<kbd>K</kbd> toggle
      </footer>
    </div>
  </div>
{/if}

<style>
  .overlay {
    position: fixed; inset: 0;
    background: rgba(0, 0, 0, 0.45);
    display: flex;
    justify-content: center;
    align-items: flex-start;
    padding-top: 12vh;
    z-index: 900;
  }
  .palette {
    width: min(600px, 92vw);
    max-height: 70vh;
    display: flex;
    flex-direction: column;
    background: var(--bg-elev);
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    box-shadow: 0 10px 40px rgba(0, 0, 0, 0.4);
    overflow: hidden;
    animation: pop 140ms ease-out;
  }
  input {
    border: none;
    border-bottom: 1px solid var(--border);
    background: transparent;
    color: var(--text);
    font-size: 13px;
    padding: 10px 12px;
    border-radius: 0;
  }
  input:focus { outline: none; border-bottom-color: var(--accent); }
  ul {
    list-style: none;
    margin: 0;
    padding: 4px;
    overflow-y: auto;
    flex: 1;
  }
  li {
    display: flex;
    align-items: baseline;
    gap: 8px;
    padding: 5px 8px;
    border-radius: 3px;
    cursor: pointer;
    color: var(--text);
  }
  li.active { background: var(--bg-row); }
  li.empty { color: var(--text-faint); justify-content: center; cursor: default; }
  .kind { color: var(--text-faint); font-size: 11px; width: 14px; }
  .lbl { font-size: 13px; flex: 1; }
  .sub { color: var(--text-faint); font-size: 11px; }
  footer {
    padding: 6px 10px;
    border-top: 1px solid var(--border);
    font-size: 10px;
    color: var(--text-faint);
    background: var(--bg);
  }
  kbd {
    font-family: ui-monospace, Menlo, monospace;
    background: var(--bg-elev);
    border: 1px solid var(--border-strong);
    border-radius: 2px;
    padding: 0 4px;
    font-size: 10px;
    color: var(--text-dim);
  }
  @keyframes pop {
    from { transform: translateY(-6px); opacity: 0; }
    to   { transform: translateY(0); opacity: 1; }
  }
  @media (prefers-reduced-motion: reduce) {
    .palette { animation: none; }
  }
</style>
