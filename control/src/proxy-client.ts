/**
 * Client HTTP minimal vers les endpoints admin du data plane.
 *
 * Loopback only en pratique (le proxy refuse toute requête non-loopback
 * sur /_admin/*), mais le client n'impose pas de check côté URL : la
 * politique réseau est appliquée côté proxy. Le control plane peut
 * tourner sur le même host que le proxy ou sur un host pair via une
 * boucle réseau privée — ce sera couvert par mTLS plus tard.
 *
 * Pas de retry automatique : un POST /v1/reload qui échoue doit
 * remonter à l'opérateur. Idempotence : tout l'état est envoyé à
 * chaque appel (snapshot complet, pas de diff).
 */
import type { ConnectionsRule } from './mitigations/connections.js';

export interface ProxyClient {
  applyConnections(snapshot: { version: number; rules: ConnectionsRule[] }): Promise<void>;
}

export class ProxyApplyError extends Error {
  constructor(
    public readonly status: number,
    public readonly detail: string,
  ) {
    super(`proxy apply failed: ${status} ${detail}`);
    this.name = 'ProxyApplyError';
  }
}

export interface HttpProxyClientOptions {
  baseUrl: string;
  /** Timeout réseau total (ms). Défaut : 5000. */
  timeoutMs?: number;
  /** Surcharge fetch (tests). */
  fetchImpl?: typeof fetch;
}

/**
 * createHttpProxyClient construit un client basé sur fetch (Node 20+).
 *
 * Le timeout est appliqué via AbortController. Aucune retry : un échec
 * de POST signifie que le state du proxy est resté l'ancien — le
 * control plane peut renvoyer ultérieurement le même snapshot sans
 * effet de bord.
 */
export function createHttpProxyClient(opts: HttpProxyClientOptions): ProxyClient {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 5000;
  const base = opts.baseUrl.replace(/\/+$/, '');

  return {
    async applyConnections(snapshot) {
      const url = `${base}/_admin/v1/mitigations/connections`;
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      try {
        const res = await fetchImpl(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(snapshot),
          signal: ctrl.signal,
        });
        if (!res.ok) {
          let detail = `${res.status} ${res.statusText}`;
          try {
            const body = (await res.json()) as { detail?: string; error?: string };
            if (body.detail) detail = body.detail;
            else if (body.error) detail = body.error;
          } catch {
            /* body non-JSON, on garde le statut texte */
          }
          throw new ProxyApplyError(res.status, detail);
        }
      } finally {
        clearTimeout(timer);
      }
    },
  };
}
