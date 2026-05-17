// Stores partagés à l'échelle de l'app.
// - toasts     : queue de notifications éphémères (remplace les bandeaux .alert).
// - connectivity : santé control plane + data plane (alimenté par Pipeline/FamilyPanel).
// - history    : séries glissantes Δ/s par préfixe de métrique, pour les sparklines.

import { writable, type Writable } from 'svelte/store';

// ---------------- Toasts ----------------
export type ToastKind = 'ok' | 'err' | 'info' | 'warn';
export interface Toast {
  id: number;
  kind: ToastKind;
  text: string;
  /** ms avant auto-dismiss, 0 = sticky */
  ttl: number;
  at: number;
}
let toastSeq = 1;
export const toasts: Writable<Toast[]> = writable([]);
export function pushToast(kind: ToastKind, text: string, ttl = 4000): void {
  const t: Toast = { id: toastSeq++, kind, text, ttl, at: Date.now() };
  toasts.update((list) => [...list, t]);
  if (ttl > 0) {
    setTimeout(() => dismissToast(t.id), ttl);
  }
}
export function dismissToast(id: number): void {
  toasts.update((list) => list.filter((t) => t.id !== id));
}

// ---------------- Connectivity ----------------
export interface Connectivity {
  controlUp: boolean | null; // null = inconnu (pas encore tenté)
  proxyUp: boolean | null;
  lastTick: number | null;
}
export const connectivity: Writable<Connectivity> = writable({
  controlUp: null,
  proxyUp: null,
  lastTick: null,
});
export function setControlUp(up: boolean): void {
  connectivity.update((c) => ({ ...c, controlUp: up, lastTick: Date.now() }));
}
export function setProxyUp(up: boolean): void {
  connectivity.update((c) => ({ ...c, proxyUp: up, lastTick: Date.now() }));
}

// ---------------- History (sparklines) ----------------
// On stocke un buffer circulaire de N derniers Δ/s par clé (préfixe métrique).
// Tous les écrans qui poussent partagent ce store → cohérence visuelle.
const HISTORY_CAP = 60;
type HistoryMap = Record<string, number[]>;
export const history: Writable<HistoryMap> = writable({});
export function pushHistory(key: string, value: number): void {
  history.update((m) => {
    const cur = m[key] ?? [];
    const next = cur.length >= HISTORY_CAP ? [...cur.slice(1), value] : [...cur, value];
    return { ...m, [key]: next };
  });
}
export function historyOf(map: HistoryMap, key: string): number[] {
  return map[key] ?? [];
}
