<script lang="ts">
  // Sparkline SVG — pure, sans lib externe.
  // - Garde une hauteur fixe pour ne pas casser les layouts.
  // - Pas de tooltip (sobre, compact).
  export let values: number[] = [];
  export let width = 60;
  export let height = 14;
  export let color = 'currentColor';
  export let strokeWidth = 1;
  export let fill = false;

  $: max = values.length > 0 ? Math.max(...values, 0.0001) : 1;
  $: pts = computePoints(values, width, height, max);
  $: areaPts = pts ? `${pts} ${width},${height} 0,${height}` : '';

  function computePoints(vs: number[], w: number, h: number, m: number): string {
    if (vs.length === 0) return '';
    if (vs.length === 1) {
      const y = h - (vs[0]! / m) * (h - 1);
      return `0,${y} ${w},${y}`;
    }
    const step = w / (vs.length - 1);
    const out: string[] = [];
    for (let i = 0; i < vs.length; i++) {
      const x = i * step;
      const y = h - (vs[i]! / m) * (h - 1);
      out.push(`${x.toFixed(1)},${y.toFixed(1)}`);
    }
    return out.join(' ');
  }
</script>

{#if values.length > 0}
  <svg class="sparkline" width={width} height={height} viewBox="0 0 {width} {height}" role="img" aria-label="sparkline">
    {#if fill}
      <polygon points={areaPts} fill={color} opacity="0.18" />
    {/if}
    <polyline points={pts} fill="none" stroke={color} stroke-width={strokeWidth} stroke-linejoin="round" stroke-linecap="round" />
  </svg>
{:else}
  <svg class="sparkline empty" width={width} height={height} viewBox="0 0 {width} {height}" aria-hidden="true">
    <line x1="0" y1={height - 0.5} x2={width} y2={height - 0.5} stroke="currentColor" stroke-width="1" opacity="0.2" />
  </svg>
{/if}

<style>
  .sparkline { display: inline-block; vertical-align: middle; }
  .sparkline.empty { color: var(--text-faint); }
</style>
