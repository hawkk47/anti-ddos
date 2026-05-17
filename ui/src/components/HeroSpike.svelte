<script lang="ts">
  /**
   * HeroSpike — KPI hero compact.
   *
   * Layout : à gauche un gros chiffre tabulaire (req/s) + delta, à droite
   * une sparkline pleine largeur. Pas de glow, pas de HUD, pas de placeholder
   * dramatique : un état "—" propre quand vide.
   */
  import { onMount, onDestroy } from 'svelte';

  export let values: number[] = [];
  export let label = 'req/s';
  export let title = 'Trafic data plane';
  export let subtitle = 'Δ/s evaluated · live';
  export let height = 96;

  let host: HTMLDivElement;
  let width = 600;
  let ro: ResizeObserver | null = null;

  onMount(() => {
    if (typeof ResizeObserver !== 'undefined' && host) {
      ro = new ResizeObserver(() => {
        if (host) width = Math.max(240, host.clientWidth);
      });
      ro.observe(host);
      width = Math.max(240, host.clientWidth);
    }
  });
  onDestroy(() => ro?.disconnect());

  const padX = 4, padY = 6;
  $: innerW = Math.max(20, width - padX * 2);
  $: innerH = Math.max(20, height - padY * 2);

  $: data = values && values.length > 0 ? values : ([] as number[]);
  $: rawMax = data.length > 0 ? Math.max(0, ...data) : 0;
  $: maxV = rawMax > 0 ? rawMax * 1.2 : 1;
  $: last = data[data.length - 1] ?? 0;
  $: prev = data[data.length - 2] ?? 0;
  $: avg = data.length > 0 ? data.reduce((a, b) => a + b, 0) / data.length : 0;
  $: hasTraffic = rawMax > 0;
  $: trend = last - prev;

  function pointsStr(vs: number[]): string {
    if (vs.length === 0) return '';
    if (vs.length === 1) {
      const y = padY + innerH - (vs[0] / maxV) * innerH;
      return `${padX},${y} ${padX + innerW},${y}`;
    }
    return vs
      .map((v, i) => {
        const x = padX + (i / (vs.length - 1)) * innerW;
        const y = padY + innerH - (v / maxV) * innerH;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');
  }
  function areaPath(vs: number[]): string {
    if (vs.length < 2) return '';
    const pts = pointsStr(vs).split(' ');
    const baseY = padY + innerH;
    const x0 = pts[0].split(',')[0];
    const xN = pts[pts.length - 1].split(',')[0];
    return `M ${x0},${baseY} L ${pts.join(' L ')} L ${xN},${baseY} Z`;
  }

  function fmt(n: number): string {
    if (!Number.isFinite(n) || n <= 0) return '0';
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(2)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
    if (n >= 10) return n.toFixed(0);
    return n.toFixed(1);
  }
  function fmtSigned(n: number): string {
    if (!Number.isFinite(n) || n === 0) return '±0';
    const s = n > 0 ? '+' : '−';
    return `${s}${fmt(Math.abs(n))}`;
  }
</script>

<section class="hero">
  <i class="corners"><i></i></i>
  <header class="head">
    <div>
      <h2>{title}</h2>
      <p class="sub">{subtitle}</p>
    </div>
    <span class="status" class:live={hasTraffic}>
      <span class="dot" class:cold={!hasTraffic}></span>
      {hasTraffic ? 'LIVE' : 'IDLE'}
    </span>
  </header>

  <div class="body">
    <div class="kpi">
      <div class="big mono">{fmt(last)}</div>
      <div class="unit">{label}</div>
      {#if hasTraffic}
        <div class="meta mono">
          <span class="delta" class:up={trend > 0} class:down={trend < 0}>
            {fmtSigned(trend)}
          </span>
          <span class="avg">avg {fmt(avg)}</span>
          <span class="peak">peak {fmt(rawMax)}</span>
        </div>
      {:else}
        <div class="meta mono empty">en attente de trafic</div>
      {/if}
    </div>

    <div class="chart" bind:this={host}>
      <svg viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" style="height: {height}px;">
        <defs>
          <linearGradient id="hero-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"  stop-color="var(--accent)" stop-opacity="0.28" />
            <stop offset="100%" stop-color="var(--accent)" stop-opacity="0.0" />
          </linearGradient>
        </defs>

        <!-- Ligne baseline médiane -->
        <line
          x1={padX} x2={padX + innerW}
          y1={padY + innerH * 0.5} y2={padY + innerH * 0.5}
          stroke="var(--border)" stroke-dasharray="2 4" stroke-width="1"
        />

        {#if hasTraffic}
          <path d={areaPath(data)} fill="url(#hero-fill)" />
          <polyline
            points={pointsStr(data)}
            fill="none"
            stroke="var(--accent)"
            stroke-width="1.5"
            stroke-linejoin="round"
            stroke-linecap="round"
          />
        {:else}
          <line
            x1={padX} x2={padX + innerW}
            y1={padY + innerH * 0.5} y2={padY + innerH * 0.5}
            stroke="var(--border-strong)" stroke-width="1.5"
          />
        {/if}
      </svg>
    </div>
  </div>
</section>

<style>
  .hero {
    position: relative;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 16px 18px;
    display: flex;
    flex-direction: column;
    gap: 14px;
  }
  .head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
  }
  .head h2 {
    margin: 0;
    font-size: 14px;
    font-weight: 600;
    color: var(--text);
    letter-spacing: -0.1px;
  }
  .head .sub {
    margin: 2px 0 0;
    font-size: 11.5px;
    color: var(--text-faint);
  }
  .status {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    font-family: var(--font-mono);
    font-size: 10.5px;
    letter-spacing: 0.6px;
    color: var(--text-faint);
    text-transform: uppercase;
  }
  .status.live { color: var(--accent); }
  .dot {
    width: 6px; height: 6px; border-radius: 50%;
    background: var(--accent);
    animation: soft-pulse 1.8s ease-in-out infinite;
  }
  .dot.cold { background: var(--text-faint); animation: none; }

  .body {
    display: grid;
    grid-template-columns: minmax(140px, 200px) 1fr;
    gap: 18px;
    align-items: center;
  }
  @media (max-width: 720px) {
    .body { grid-template-columns: 1fr; }
  }

  .kpi { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .big {
    font-size: 38px;
    font-weight: 600;
    line-height: 1;
    color: var(--text);
    font-variant-numeric: tabular-nums;
    letter-spacing: -1px;
  }
  .unit {
    font-size: 11px;
    color: var(--text-faint);
    text-transform: uppercase;
    letter-spacing: 0.6px;
  }
  .meta {
    margin-top: 6px;
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    font-size: 11px;
    color: var(--text-faint);
  }
  .meta.empty { color: var(--text-faint); font-style: italic; }
  .delta { color: var(--text-dim); }
  .delta.up { color: var(--accent); }
  .delta.down { color: var(--ok); }
  .avg, .peak { color: var(--text-faint); }

  .chart {
    width: 100%;
    min-width: 0;
  }
  .chart svg {
    width: 100%;
    display: block;
  }
</style>
