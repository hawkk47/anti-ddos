<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { FAMILIES, familyById } from './lib/families';
  import Sidebar from './components/Sidebar.svelte';
  import Overview from './components/Overview.svelte';
  import Pipeline from './components/Pipeline.svelte';
  import Dashboard from './components/Dashboard.svelte';
  import FamilyPanel from './components/FamilyPanel.svelte';
  import Toasts from './components/Toasts.svelte';
  import CommandPalette from './components/CommandPalette.svelte';
  import { initTheme } from './lib/theme';
  import { pushToast } from './lib/stores';
  import { api, ApiCallError } from './lib/api';

  type Route =
    | { view: 'overview' }
    | { view: 'pipeline' }
    | { view: 'dashboard' }
    | { view: 'family'; id: string };

  function parseHash(h: string): Route {
    if (h.startsWith('#/m/')) {
      const id = h.slice(4);
      if (familyById(id)) return { view: 'family', id };
    }
    if (h === '#/dashboard') return { view: 'dashboard' };
    if (h === '#/pipeline')  return { view: 'pipeline' };
    return { view: 'overview' };
  }

  let route: Route = parseHash(location.hash);
  function onHash() { route = parseHash(location.hash); }

  // Séquences vim-style : g p / g d / g m, plus quelques raccourcis simples.
  let pendingG = false;
  let pendingTimer: ReturnType<typeof setTimeout> | null = null;
  function resetG() {
    pendingG = false;
    if (pendingTimer) { clearTimeout(pendingTimer); pendingTimer = null; }
  }
  function showHelp() {
    pushToast(
      'info',
      'Raccourcis : Ctrl+K palette · g o overview · g p pipeline · g d dashboard · r reload · ? aide',
      6000,
    );
  }
  async function reloadDataPlane() {
    try {
      const r = await api.reload();
      pushToast('ok', `Data plane rechargé — ${r.pushed} règles.`);
    } catch (e) {
      const msg = e instanceof ApiCallError ? `${e.status} ${e.message}` : (e as Error).message;
      pushToast('err', `Reload échoué : ${msg}`);
    }
  }
  function onKey(e: KeyboardEvent) {
    // On ignore quand l'utilisateur tape dans un champ.
    const t = e.target as HTMLElement | null;
    const inField = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
    if (inField) return;
    if (e.ctrlKey || e.metaKey || e.altKey) return;

    if (e.key === '?') { e.preventDefault(); showHelp(); return; }
    if (e.key === 'r') { e.preventDefault(); reloadDataPlane(); return; }
    if (e.key === 'g') {
      pendingG = true;
      if (pendingTimer) clearTimeout(pendingTimer);
      pendingTimer = setTimeout(resetG, 1200);
      return;
    }
    if (pendingG) {
      if (e.key === 'o')      { e.preventDefault(); location.hash = '#/'; }
      else if (e.key === 'p') { e.preventDefault(); location.hash = '#/pipeline'; }
      else if (e.key === 'd') { e.preventDefault(); location.hash = '#/dashboard'; }
      resetG();
    }
  }

  onMount(() => {
    initTheme();
    window.addEventListener('hashchange', onHash);
    window.addEventListener('keydown', onKey);
  });
  onDestroy(() => {
    window.removeEventListener('hashchange', onHash);
    window.removeEventListener('keydown', onKey);
  });

  $: currentId = route.view === 'family' ? route.id : null;
  $: currentView = route.view;
  $: fam = route.view === 'family' ? familyById(route.id) : undefined;
</script>

<div class="layout">
  <Sidebar families={FAMILIES} {currentId} {currentView} />
  <main>
    {#if route.view === 'overview'}
      <Overview />
    {:else if route.view === 'pipeline'}
      <Pipeline />
    {:else if route.view === 'dashboard'}
      <Dashboard families={FAMILIES} />
    {:else if fam}
      <FamilyPanel family={fam} />
    {:else}
      <p>Famille inconnue.</p>
    {/if}
  </main>
</div>

<Toasts />
<CommandPalette />

<style>
  .layout {
    display: grid;
    grid-template-columns: 230px 1fr;
    min-height: 100vh;
  }
  main {
    padding: 24px 32px 40px;
    overflow-x: auto;
  }
</style>
