// Gestion du thème — appliqué via data-theme="dark"|"light" sur <html>.
// Persisté dans localStorage('antiddos.theme'). Default = 'auto' (suit OS).

import { writable, type Writable } from 'svelte/store';

export type Theme = 'auto' | 'dark' | 'light';
const KEY = 'antiddos.theme';

function readStored(): Theme {
  try {
    const v = localStorage.getItem(KEY);
    if (v === 'dark' || v === 'light' || v === 'auto') return v;
  } catch { /* ignore */ }
  return 'auto';
}

export const theme: Writable<Theme> = writable(readStored());

export function applyTheme(t: Theme): void {
  const root = document.documentElement;
  if (t === 'auto') {
    root.removeAttribute('data-theme');
  } else {
    root.setAttribute('data-theme', t);
  }
  try { localStorage.setItem(KEY, t); } catch { /* ignore */ }
  theme.set(t);
}

export function cycleTheme(): void {
  const order: Theme[] = ['auto', 'dark', 'light'];
  let cur: Theme = 'auto';
  const unsub = theme.subscribe((v) => { cur = v; });
  unsub();
  const idx = order.indexOf(cur);
  applyTheme(order[(idx + 1) % order.length] ?? 'auto');
}

export function initTheme(): void {
  applyTheme(readStored());
}
