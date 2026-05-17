// Typed fetch client vers le control plane.
// Base URL relative — l'UI est servie sous le même origine que `/v1/...`
// quand bundlée par @fastify/static, ou via le proxy Vite en dev.
//
// Auth Bearer : stockée en sessionStorage (clé `antiddos.token`). Sur
// un 401, on demande un nouveau token via prompt(). Aucun secret n'est
// jamais loggé en console ni persisté en localStorage.

const TOKEN_KEY = 'antiddos.token';

function getToken(): string | null {
  try { return sessionStorage.getItem(TOKEN_KEY); } catch { return null; }
}

export function setToken(t: string | null): void {
  try {
    if (t && t.length > 0) sessionStorage.setItem(TOKEN_KEY, t);
    else sessionStorage.removeItem(TOKEN_KEY);
  } catch { /* sessionStorage indisponible — degrade silencieusement */ }
}

function promptForToken(reason: string): string | null {
  // eslint-disable-next-line no-alert
  const t = window.prompt(
    `Token admin requis (${reason}).\nDéfini par ANTIDDOS_CTRL_API_TOKEN sur le control plane.`,
    '',
  );
  if (t && t.trim().length >= 16) {
    setToken(t.trim());
    return t.trim();
  }
  return null;
}

export interface Rule {
  id: string;
  enabled: boolean;
  on_error: 'allow' | 'deny';
  reason?: string;
  notes?: string;
  params: Record<string, unknown>;
}

export interface FamilyPayload {
  rev: number;
  rules: Rule[];
}

export interface ApiError {
  code: string;
  message: string;
}

export class ApiCallError extends Error {
  constructor(public readonly status: number, public readonly body: unknown) {
    super(typeof body === 'object' && body !== null && 'message' in body
      ? String((body as ApiError).message)
      : `HTTP ${status}`);
  }
}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res = await doFetch(method, path, body);
  if (res.status === 401) {
    const t = promptForToken('non authentifié');
    if (t) res = await doFetch(method, path, body);
  }
  const text = await res.text();
  const parsed: unknown = text ? safeJson(text) : null;
  if (!res.ok) throw new ApiCallError(res.status, parsed);
  return parsed as T;
}

async function doFetch(method: string, path: string, body?: unknown): Promise<Response> {
  const headers: Record<string, string> = { accept: 'application/json' };
  if (body !== undefined) headers['content-type'] = 'application/json';
  const tok = getToken();
  if (tok) headers['authorization'] = `Bearer ${tok}`;
  return fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
  });
}

function safeJson(text: string): unknown {
  try { return JSON.parse(text); } catch { return text; }
}

export const api = {
  listFamily(family: string) {
    return call<FamilyPayload>('GET', `/v1/mitigations/${family}`);
  },
  upsertRule(family: string, rule: Rule) {
    return call<{ rev: number; rule: Rule }>(
      'PUT',
      `/v1/mitigations/${family}/${encodeURIComponent(rule.id)}`,
      rule,
    );
  },
  reload() {
    return call<{ status: 'accepted'; at: number; pushed: number }>('POST', '/v1/reload', {});
  },
  async metrics(): Promise<string> {
    // Relay control plane → data plane /_admin/v1/metrics. Auth Bearer
    // ajouté automatiquement par doFetch.
    let res = await doFetch('GET', '/v1/proxy/metrics');
    if (res.status === 401) {
      const t = promptForToken('non authentifié');
      if (t) res = await doFetch('GET', '/v1/proxy/metrics');
    }
    if (!res.ok) throw new ApiCallError(res.status, null);
    return res.text();
  },
};
