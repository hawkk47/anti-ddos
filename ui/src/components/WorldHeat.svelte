<script lang="ts">
  /**
   * WorldHeat — synthèse de l'activité par pays.
   *
   * Lit les compteurs `proxy_requests_by_country_XX_total` exposés par
   * la data plane (cf. proxy/internal/geoip) et affiche :
   *   - top 8 pays sous forme de bar chart horizontal néon ;
   *   - une mini carte du monde stylisée avec hot-dots positionnés
   *     selon le centroïde approximatif de chaque pays.
   */
  import type { MetricFamily } from '../lib/prom';

  export let metrics: Record<string, MetricFamily> = {};

  const COUNTRY_NAMES: Record<string, string> = {
    LO: 'Local / loopback',
    ZZ: 'Inconnu',
    FR: 'France', US: 'United States', DE: 'Germany', GB: 'United Kingdom',
    CN: 'China', RU: 'Russia', BR: 'Brazil', IN: 'India', JP: 'Japan',
    CA: 'Canada', AU: 'Australia', ES: 'Spain', IT: 'Italy', NL: 'Netherlands',
    SE: 'Sweden', PL: 'Poland', UA: 'Ukraine', TR: 'Turkey', MX: 'Mexico',
    KR: 'South Korea', ZA: 'South Africa', SG: 'Singapore', HK: 'Hong Kong',
    AE: 'UAE', SA: 'Saudi Arabia', IR: 'Iran', VN: 'Vietnam', ID: 'Indonesia',
    PK: 'Pakistan', NG: 'Nigeria', EG: 'Egypt', AR: 'Argentina', CL: 'Chile',
    CO: 'Colombia', BE: 'Belgium', CH: 'Switzerland', AT: 'Austria',
    PT: 'Portugal', IE: 'Ireland', FI: 'Finland', NO: 'Norway', DK: 'Denmark',
    CZ: 'Czechia', GR: 'Greece', RO: 'Romania', HU: 'Hungary', IL: 'Israel',
    TH: 'Thailand', PH: 'Philippines', MY: 'Malaysia', NZ: 'New Zealand',
  };

  // Centroïdes (lon, lat) en projection equirectangulaire — assez pour
  // une carte décorative. Pas de prétention cartographique.
  const COUNTRY_LL: Record<string, [number, number]> = {
    FR: [2, 47], US: [-98, 40], DE: [10, 51], GB: [-2, 54], CN: [104, 36],
    RU: [100, 60], BR: [-54, -10], IN: [78, 22], JP: [138, 36], CA: [-100, 60],
    AU: [134, -25], ES: [-3, 40], IT: [12, 43], NL: [5, 52], SE: [15, 62],
    PL: [19, 52], UA: [31, 49], TR: [35, 39], MX: [-102, 23], KR: [127, 36],
    ZA: [24, -29], SG: [104, 1], HK: [114, 22], AE: [54, 24], SA: [45, 24],
    IR: [53, 32], VN: [108, 16], ID: [120, -5], PK: [70, 30], NG: [8, 9],
    EG: [30, 26], AR: [-64, -34], CL: [-71, -35], CO: [-74, 4], BE: [4, 50],
    CH: [8, 47], AT: [14, 47], PT: [-8, 39], IE: [-8, 53], FI: [25, 62],
    NO: [9, 62], DK: [10, 56], CZ: [15, 50], GR: [22, 39], RO: [25, 46],
    HU: [19, 47], IL: [35, 31], TH: [101, 15], PH: [122, 13], MY: [102, 4],
    NZ: [173, -41],
  };

  interface Row { code: string; name: string; value: number }

  const RE = /^proxy_requests_by_country_([A-Z]{2})_total$/;

  $: rows = (() => {
    const out: Row[] = [];
    for (const name of Object.keys(metrics)) {
      const m = RE.exec(name);
      if (!m) continue;
      const code = m[1];
      const sum = metrics[name].samples.reduce((a, s) => a + (Number.isFinite(s.value) ? s.value : 0), 0);
      if (sum <= 0) continue;
      out.push({ code, name: COUNTRY_NAMES[code] ?? code, value: sum });
    }
    out.sort((a, b) => b.value - a.value);
    return out;
  })();

  $: total = rows.reduce((a, r) => a + r.value, 0);
  $: top = rows.slice(0, 8);
  $: maxV = top.length > 0 ? top[0].value : 1;

  function fmt(n: number): string {
    if (!Number.isFinite(n) || n <= 0) return '0';
    if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
    if (n >= 1_000) return `${(n / 1_000).toFixed(1)}k`;
    return n.toFixed(0);
  }

  // Projection equirectangulaire vers SVG 360×180 (viewBox).
  function project(ll: [number, number]): { x: number; y: number } {
    const [lon, lat] = ll;
    return { x: (lon + 180) * (360 / 360), y: (90 - lat) * (180 / 180) };
  }

  $: dots = rows
    .filter((r) => COUNTRY_LL[r.code])
    .map((r) => ({
      ...r,
      ...project(COUNTRY_LL[r.code]),
      radius: 1.2 + 4 * Math.sqrt(r.value / Math.max(1, maxV)),
    }));
</script>

<section class="panel">
  <i class="corners purple"><i></i></i>
  <header class="panel-head">
    <div>
      <h2>Trafic par pays</h2>
      <p>Distribution g\u00e9ographique des requ\u00eates observ\u00e9es par la data plane.</p>
    </div>
    <span class="head-total mono">{fmt(total)} <span class="head-unit">req</span></span>
  </header>

  <!-- Mini-carte d\u00e9corative. -->
  <div class="map-wrap">
    <svg viewBox="0 0 360 180" preserveAspectRatio="xMidYMid meet" class="map" aria-hidden="true">
      <!-- Quadrillage discret -->
      <g class="grid">
        {#each [30, 60, 90, 120, 150] as y}
          <line x1="0" x2="360" y1={y} y2={y} />
        {/each}
        {#each [45, 90, 135, 180, 225, 270, 315] as x}
          <line x1={x} x2={x} y1="0" y2="180" />
        {/each}
      </g>
      <!-- \u00c9quateur + m\u00e9ridien -->
      <line x1="0" x2="360" y1="90" y2="90" class="axis" />
      <line x1="180" x2="180" y1="0" y2="180" class="axis" />

      {#each dots as d (d.code)}
        <circle cx={d.x} cy={d.y} r={d.radius} class="hot">
          <title>{d.name} \u2014 {fmt(d.value)}</title>
        </circle>
      {/each}
    </svg>
    {#if dots.length === 0}
      <div class="map-empty">aucune donn\u00e9e g\u00e9o</div>
    {/if}
  </div>

  <!-- Top pays. -->
  <ul class="bars">
    {#if top.length === 0}
      <li class="empty">en attente du premier hit</li>
    {:else}
      {#each top as r (r.code)}
        {@const pct = (r.value / maxV) * 100}
        {@const share = total > 0 ? (r.value / total) * 100 : 0}
        <li class="bar">
          <span class="bar-code mono">{r.code}</span>
          <span class="bar-name">{r.name}</span>
          <span class="bar-track" aria-hidden="true">
            <span class="bar-fill" style="width: {pct}%"></span>
          </span>
          <span class="bar-val mono">{fmt(r.value)}</span>
          <span class="bar-pct mono">{share.toFixed(1)}%</span>
        </li>
      {/each}
    {/if}
  </ul>
</section>

<style>
  .panel {
    position: relative;
    background: var(--bg-elev);
    border: 1px solid var(--border);
    border-radius: 10px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }
  .panel-head {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 12px;
    padding: 14px 18px;
    border-bottom: 1px solid var(--border);
  }
  .panel-head h2 {
    margin: 0;
    font-size: 13.5px;
    font-weight: 600;
    color: var(--text);
  }
  .panel-head p {
    margin: 3px 0 0;
    font-size: 12px;
    color: var(--text-faint);
  }
  .head-total {
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
    font-variant-numeric: tabular-nums;
    white-space: nowrap;
  }
  .head-unit {
    color: var(--text-faint);
    font-weight: 400;
    font-size: 11px;
    margin-left: 2px;
  }

  .map-wrap {
    position: relative;
    padding: 12px 18px;
    border-bottom: 1px solid var(--border);
    background: var(--bg);
  }
  .map {
    display: block;
    width: 100%;
    height: auto;
    max-height: 160px;
    aspect-ratio: 2 / 1;
  }
  .grid line { stroke: var(--border); stroke-width: 0.4; }
  .axis     { stroke: var(--border-strong); stroke-width: 0.5; stroke-dasharray: 2 4; }
  circle.hot {
    fill: var(--neon-orange);
    fill-opacity: 0.75;
    stroke: var(--neon-orange);
    stroke-width: 0.5;
    filter: drop-shadow(0 0 3px var(--neon-orange-glow));
  }
  .map-empty {
    position: absolute;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--text-faint);
    font-size: 11.5px;
    pointer-events: none;
  }

  .bars {
    list-style: none;
    padding: 12px 18px;
    margin: 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .empty {
    color: var(--text-faint);
    font-size: 12px;
    padding: 16px 0;
    text-align: center;
    font-style: italic;
  }
  .bar {
    display: grid;
    grid-template-columns: 30px minmax(0, 1fr) 1.4fr 56px 46px;
    align-items: center;
    gap: 10px;
    font-size: 12px;
    color: var(--text-dim);
  }
  .bar-code {
    color: var(--text-faint);
    font-weight: 600;
    font-size: 10.5px;
    letter-spacing: 0.4px;
  }
  .bar-name {
    color: var(--text);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
    font-size: 12.5px;
  }
  .bar-val {
    text-align: right;
    color: var(--text);
    font-variant-numeric: tabular-nums;
  }
  .bar-pct {
    text-align: right;
    color: var(--text-faint);
    font-variant-numeric: tabular-nums;
  }
  .bar-track {
    position: relative;
    height: 4px;
    background: var(--bg);
    border-radius: 2px;
    overflow: hidden;
  }
  .bar-fill {
    display: block;
    height: 100%;
    background: linear-gradient(90deg, var(--neon-orange) 0%, var(--neon-orange-soft) 100%);
    border-radius: 2px;
    box-shadow: 0 0 8px var(--neon-orange-glow);
    transition: width 240ms ease-out;
  }
</style>
