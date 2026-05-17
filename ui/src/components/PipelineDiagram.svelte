<script lang="ts">
  /**
   * Diagramme architecture style Cloudflare :
   *   Clients ─dashed─▶ [Étage 0..4 du pipeline] ─dashed─▶ Upstream
   *
   * Chaque étage est une "neon-card" qui contient ses familles. Les
   * lignes deviennent "hot" (orange vif) quand au moins une famille de
   * l'étage a un débit > 0.
   */
  import { PIPELINE_STAGES, type FamilyDef } from '../lib/families';

  export let families: FamilyDef[] = [];
  /** Map metric → débit Δ/s pour colorer les flux. */
  export let rates: Record<string, number> = {};
  /** Map metric → blocked total (affiché en pied de card). */
  export let blocked: Record<string, number> = {};
  /** Statut visuel (active/dormant/error/unknown) par family.id. */
  export let statusOf: (f: FamilyDef) => 'active' | 'dormant' | 'error' | 'unknown' =
    () => 'unknown';

  // Layout calcul "à la main" — SVG overlay les cards positionnées en CSS grid.
  // On utilise des id de noeud pour ancrer les lignes via getBoundingClientRect.
  let host: HTMLDivElement;
  let lines: { x1: number; y1: number; x2: number; y2: number; hot: boolean; id: string }[] = [];

  const STAGE_TINTS: Record<number, 'orange' | 'blue' | 'purple' | 'red'> = {
    0: 'orange', // TLS / handshake
    1: 'blue',   // Connexion
    2: 'purple', // Hygiène
    3: 'orange', // Limites applicatives
    4: 'red',    // Comportemental (visuellement rouge mais on map à orange)
  };

  function stageTintClass(stage: number): string {
    const t = STAGE_TINTS[stage] ?? 'orange';
    if (t === 'blue') return 'blue';
    if (t === 'purple') return 'purple';
    return ''; // orange default
  }
  function stageLabelClass(stage: number): string {
    const t = STAGE_TINTS[stage] ?? 'orange';
    if (t === 'blue') return 'blue';
    if (t === 'purple') return 'purple';
    return '';
  }

  function stageFamilies(stageId: number): FamilyDef[] {
    return families.filter((f) => f.stage === stageId);
  }
  function stageHot(stageId: number): boolean {
    return stageFamilies(stageId).some((f) => (rates[f.metric] ?? 0) > 0);
  }
  function fmt(n: number): string {
    if (!Number.isFinite(n) || n <= 0) return '0';
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
    if (n < 1) return n.toFixed(2);
    return n.toFixed(0);
  }

  // Recalcule les coordonnées des flèches en fonction du layout DOM.
  function recompute() {
    if (!host) return;
    const hostBox = host.getBoundingClientRect();
    const nodes = host.querySelectorAll<HTMLElement>('[data-node]');
    const byId: Record<string, DOMRect> = {};
    nodes.forEach((n) => {
      const id = n.getAttribute('data-node');
      if (id) byId[id] = n.getBoundingClientRect();
    });

    const order = ['clients', 's0', 's1', 's2', 's3', 's4', 'upstream'];
    const next: typeof lines = [];
    for (let i = 0; i < order.length - 1; i++) {
      const a = byId[order[i]];
      const b = byId[order[i + 1]];
      if (!a || !b) continue;
      const x1 = a.right - hostBox.left;
      const y1 = a.top + a.height / 2 - hostBox.top;
      const x2 = b.left - hostBox.left;
      const y2 = b.top + b.height / 2 - hostBox.top;
      // hot = étage cible chaud (ou source)
      const targetStage = order[i + 1].startsWith('s')
        ? Number(order[i + 1].slice(1))
        : -1;
      const sourceStage = order[i].startsWith('s')
        ? Number(order[i].slice(1))
        : -1;
      const hot = (targetStage >= 0 && stageHot(targetStage)) || (sourceStage >= 0 && stageHot(sourceStage));
      next.push({ x1, y1, x2, y2, hot, id: `${order[i]}-${order[i + 1]}` });
    }
    lines = next;
  }

  $: void rates, void blocked, void families, queueMicrotask(recompute);

  let ro: ResizeObserver | null = null;
  $: if (host && typeof ResizeObserver !== 'undefined' && !ro) {
    ro = new ResizeObserver(recompute);
    ro.observe(host);
    recompute();
  }
</script>

<div class="diagram neon-grid-bg" bind:this={host}>
  <!-- SVG overlay pour les lignes de flux animées. -->
  <svg class="flow-overlay" preserveAspectRatio="none">
    {#each lines as l (l.id)}
      <path
        class="flow-line {l.hot ? 'hot' : 'cold'}"
        d={`M ${l.x1} ${l.y1} C ${(l.x1 + l.x2) / 2} ${l.y1}, ${(l.x1 + l.x2) / 2} ${l.y2}, ${l.x2} ${l.y2}`}
      />
    {/each}
  </svg>

  <!-- Clients -->
  <div class="col clients">
    <div class="neon-card dim" data-node="clients">
      <i class="corners"><i></i></i>
      <div class="node-head">
        <span class="neon-label dim">clients</span>
      </div>
      <div class="node-body mono">
        <div>HTTP / HTTPS</div>
        <div class="dim-text">internet</div>
      </div>
    </div>
  </div>

  <!-- 5 étages du pipeline -->
  {#each PIPELINE_STAGES as s (s.id)}
    {@const fams = stageFamilies(s.id)}
    {@const hot = stageHot(s.id)}
    <div class="col stage">
      <div class="neon-card {stageTintClass(s.id)}" class:hot data-node="s{s.id}">
        <i class="corners"><i></i></i>
        <div class="node-head">
          <span class="neon-label {stageLabelClass(s.id)}">stage {s.id}</span>
          <span class="stage-name">{s.label}</span>
        </div>
        <ul class="fam-list">
          {#each fams as f (f.id)}
            {@const r = rates[f.metric] ?? 0}
            {@const status = statusOf(f)}
            <li class="fam" class:hot={r > 0}>
              <a href="#/m/{f.id}" title={f.desc}>
                <span class="fam-dot {status}"></span>
                <span class="fam-name">{f.label}</span>
                <span class="fam-rate mono">
                  {#if r > 0}+{fmt(r)}/s{:else}{fmt(blocked[f.metric] ?? 0)}{/if}
                </span>
              </a>
            </li>
          {/each}
        </ul>
      </div>
    </div>
  {/each}

  <!-- Upstream -->
  <div class="col upstream">
    <div class="neon-card" data-node="upstream">
      <i class="corners"><i></i></i>
      <div class="node-head">
        <span class="neon-label">upstream</span>
      </div>
      <div class="node-body mono">
        <div>app backend</div>
        <div class="dim-text">protected</div>
      </div>
    </div>
  </div>
</div>

<style>
  .diagram {
    position: relative;
    display: grid;
    grid-template-columns: 130px repeat(5, 1fr) 130px;
    gap: 28px;
    padding: 20px 16px;
    border: 1px solid var(--neon-card-border);
    border-radius: 4px;
    align-items: stretch;
  }
  .flow-overlay {
    position: absolute;
    inset: 0;
    width: 100%;
    height: 100%;
    pointer-events: none;
    overflow: visible;
  }
  .col {
    display: flex;
    flex-direction: column;
    justify-content: center;
    min-width: 0;
    z-index: 1;
  }
  .node-head {
    display: flex;
    align-items: baseline;
    gap: 8px;
    padding: 8px 10px 6px;
    border-bottom: 1px solid var(--neon-card-border);
  }
  .stage-name {
    color: var(--text);
    font-size: 12px;
    font-weight: 500;
  }
  .node-body {
    padding: 10px;
    color: var(--text-dim);
    font-size: 11px;
  }
  .dim-text { color: var(--text-faint); font-size: 10px; margin-top: 2px; }

  .fam-list {
    list-style: none;
    margin: 0;
    padding: 4px 0;
  }
  .fam a {
    display: grid;
    grid-template-columns: 8px 1fr auto;
    align-items: center;
    gap: 8px;
    padding: 4px 10px;
    color: var(--text-dim);
    font-size: 11px;
    border-left: 2px solid transparent;
  }
  .fam a:hover {
    background: rgba(255,255,255,0.02);
    color: var(--text);
    text-decoration: none;
  }
  .fam.hot a {
    color: var(--text);
    border-left-color: var(--neon-orange);
  }
  .fam-dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--text-faint);
  }
  .fam-dot.active  { background: var(--neon-green); box-shadow: 0 0 4px var(--neon-green); }
  .fam-dot.error   { background: var(--neon-red);   box-shadow: 0 0 4px var(--neon-red); }
  .fam-dot.dormant { background: var(--text-faint); }
  .fam-name { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .fam-rate { color: var(--text-faint); font-size: 10px; }
  .fam.hot .fam-rate { color: var(--neon-orange); }
</style>
