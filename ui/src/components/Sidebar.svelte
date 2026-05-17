<script lang="ts">
  import type { FamilyDef } from '../lib/families';
  import { theme, cycleTheme } from '../lib/theme';

  export let families: FamilyDef[];
  export let currentId: string | null;
  export let currentView: 'pipeline' | 'dashboard' | 'family' = 'pipeline';

  function themeIcon(t: typeof $theme): string {
    return t === 'dark' ? '◐' : t === 'light' ? '◑' : '◓';
  }
</script>

<aside>
  <header>
    <div class="brand">
      <span class="logo" aria-hidden="true"></span>
      <span class="title">anti-ddos</span>
      <span class="sub">admin</span>
    </div>
    <button class="theme" on:click={cycleTheme} title="Cycle thème (auto/dark/light)">
      {themeIcon($theme)}
    </button>
  </header>

  <nav>
    <a class:active={currentView === 'pipeline'} href="#/">
      <span class="lbl">Pipeline</span>
    </a>
    <a class:active={currentView === 'dashboard'} href="#/dashboard">
      <span class="lbl">Dashboard</span>
    </a>
    <div class="group">Mitigations</div>
    {#each families as f (f.id)}
      <a class:active={currentId === f.id} href="#/m/{f.id}" title={f.desc}>
        <span class="id mono">{f.id}</span>
        <span class="lbl">{f.label}</span>
      </a>
    {/each}
  </nav>
  <footer>
    <span class="ft-count">{families.length} familles</span>
    <span class="ft-kbd"><kbd>Ctrl</kbd><kbd>K</kbd></span>
  </footer>
</aside>

<style>
  aside {
    background: var(--bg-elev);
    border-right: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    min-height: 100vh;
  }
  header {
    padding: 16px 18px 14px;
    border-bottom: 1px solid var(--border);
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .brand {
    display: flex;
    align-items: baseline;
    gap: 8px;
    flex: 1;
  }
  .logo {
    width: 10px;
    height: 10px;
    background: var(--accent);
    border-radius: 2px;
    align-self: center;
    box-shadow: 0 0 0 3px var(--accent-tint);
  }
  .title {
    font-weight: 600;
    font-size: 14px;
    color: var(--text);
    letter-spacing: -0.2px;
  }
  .sub {
    color: var(--text-faint);
    font-size: 11px;
    font-weight: 400;
  }
  .theme {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-faint);
    width: 26px; height: 26px;
    padding: 0;
    font-size: 13px;
    line-height: 1;
    border-radius: 6px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }
  .theme:hover { color: var(--text); border-color: var(--text-faint); }

  nav { padding: 10px 8px; flex: 1; display: flex; flex-direction: column; gap: 1px; }
  nav a {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 7px 12px;
    color: var(--text-dim);
    border-radius: 6px;
    font-size: 12.5px;
    transition: background 120ms ease, color 120ms ease;
  }
  nav a:hover { background: var(--bg-row); color: var(--text); }
  nav a.active {
    background: var(--accent-tint);
    color: var(--text);
  }
  nav a.active .lbl { font-weight: 500; }
  nav a.active .id  { color: var(--accent); }

  .id {
    font-size: 10.5px;
    color: var(--text-faint);
    letter-spacing: 0.4px;
  }
  .lbl { font-size: 12.5px; }

  .group {
    padding: 16px 12px 6px;
    font-size: 10px;
    text-transform: uppercase;
    color: var(--text-faint);
    letter-spacing: 0.8px;
    font-weight: 600;
  }

  footer {
    padding: 12px 18px;
    border-top: 1px solid var(--border);
    font-size: 11px;
    color: var(--text-faint);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .ft-kbd { display: inline-flex; gap: 3px; }
  kbd {
    background: var(--bg);
    border: 1px solid var(--border-strong);
    border-bottom-width: 2px;
    border-radius: 4px;
    padding: 0 5px;
    font-size: 10px;
    color: var(--text-dim);
    font-family: var(--font-mono);
  }
</style>
