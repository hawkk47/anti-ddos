// Mini-parseur Prometheus text format → entries plates.
// Suffisant pour notre dashboard (counters + gauges, pas d'histogrammes).

export interface MetricSample {
  name: string;
  labels: Record<string, string>;
  value: number;
}

export interface MetricFamily {
  name: string;
  help: string;
  type: string;
  samples: MetricSample[];
}

export function parsePromText(text: string): MetricFamily[] {
  const families = new Map<string, MetricFamily>();
  const ensure = (name: string): MetricFamily => {
    let f = families.get(name);
    if (!f) {
      f = { name, help: '', type: 'untyped', samples: [] };
      families.set(name, f);
    }
    return f;
  };

  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim();
    if (line === '') continue;
    if (line.startsWith('# HELP ')) {
      const rest = line.slice(7);
      const sp = rest.indexOf(' ');
      if (sp > 0) ensure(rest.slice(0, sp)).help = rest.slice(sp + 1);
      continue;
    }
    if (line.startsWith('# TYPE ')) {
      const rest = line.slice(7);
      const sp = rest.indexOf(' ');
      if (sp > 0) ensure(rest.slice(0, sp)).type = rest.slice(sp + 1);
      continue;
    }
    if (line.startsWith('#')) continue;
    const sample = parseSampleLine(line);
    if (sample) ensure(sample.name).samples.push(sample);
  }
  return [...families.values()].sort((a, b) => a.name.localeCompare(b.name));
}

function parseSampleLine(line: string): MetricSample | null {
  let name = '';
  let i = 0;
  while (i < line.length && /[a-zA-Z0-9_:]/.test(line[i]!)) {
    name += line[i];
    i++;
  }
  if (!name) return null;
  const labels: Record<string, string> = {};
  if (line[i] === '{') {
    i++;
    const end = line.indexOf('}', i);
    if (end < 0) return null;
    const block = line.slice(i, end);
    for (const part of splitLabels(block)) {
      const eq = part.indexOf('=');
      if (eq < 0) continue;
      const k = part.slice(0, eq).trim();
      let v = part.slice(eq + 1).trim();
      if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      labels[k] = v.replace(/\\"/g, '"').replace(/\\\\/g, '\\');
    }
    i = end + 1;
  }
  const valueStr = line.slice(i).trim().split(/\s+/, 1)[0] ?? '';
  const value = Number(valueStr);
  if (!Number.isFinite(value)) return null;
  return { name, labels, value };
}

function splitLabels(block: string): string[] {
  // Sépare sur `,` en respectant les chaînes "...".
  const out: string[] = [];
  let cur = '';
  let inStr = false;
  let esc = false;
  for (const ch of block) {
    if (esc) { cur += ch; esc = false; continue; }
    if (ch === '\\') { cur += ch; esc = true; continue; }
    if (ch === '"') { inStr = !inStr; cur += ch; continue; }
    if (ch === ',' && !inStr) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim() !== '') out.push(cur);
  return out;
}