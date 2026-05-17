import { Type, type Static } from '@sinclair/typebox';

/**
 * Schéma de configuration runtime du control plane.
 *
 * Tout champ sensible (clé, certificat) doit venir d'env, pas du JSON.
 * Cf. .github/instructions/control-plane.instructions.md.
 */
export const ConfigSchema = Type.Object(
  {
    listenHost: Type.String({ default: '127.0.0.1', minLength: 1 }),
    listenPort: Type.Integer({ default: 9090, minimum: 0, maximum: 65535 }),
    logLevel: Type.Union(
      [
        Type.Literal('fatal'),
        Type.Literal('error'),
        Type.Literal('warn'),
        Type.Literal('info'),
        Type.Literal('debug'),
        Type.Literal('trace'),
      ],
      { default: 'info' },
    ),
    /** URL du data plane à notifier sur reload (admin API du proxy). */
    proxyAdminUrl: Type.String({ default: 'http://127.0.0.1:8081' }),
    /**
     * Token Bearer envoyé au data plane sur les routes admin
     * mutantes (`/_admin/v1/...`). 16–512 chars. `null` ⇒ pas de
     * header (le proxy doit alors tourner sans token — dev only).
     */
    proxyAdminToken: Type.Union([Type.String({ minLength: 16, maxLength: 512 }), Type.Null()], {
      default: null,
    }),
    /**
     * Token Bearer requis sur toutes les routes hors /v1/health et
     * /metrics. `null` autorisé UNIQUEMENT en bind loopback (dev) :
     * le boot échoue si le bind n'est pas loopback et que le token
     * n'est pas fourni. Le secret ne doit JAMAIS être logé.
     */
    apiToken: Type.Union([Type.String({ minLength: 16, maxLength: 512 }), Type.Null()], {
      default: null,
    }),
    /**
     * Répertoire où sont persistés les snapshots des stores
     * (`<stateDir>/<family>.json`). Défaut `./state` relatif au CWD.
     */
    stateDir: Type.String({ default: './state', minLength: 1 }),
  },
  { additionalProperties: false },
);

export type Config = Static<typeof ConfigSchema>;

/**
 * Construit une Config à partir des variables d'environnement.
 * Aucun défaut prod ; tous les défauts pointent loopback.
 */
export function loadConfigFromEnv(env: NodeJS.ProcessEnv = process.env): Config {
  const port = env['ANTIDDOS_CTRL_PORT'];
  const parsedPort = port === undefined || port === '' ? 9090 : Number.parseInt(port, 10);
  if (!Number.isInteger(parsedPort) || parsedPort < 0 || parsedPort > 65535) {
    throw new Error(`ANTIDDOS_CTRL_PORT invalid: ${String(port)}`);
  }

  const level = env['ANTIDDOS_CTRL_LOG_LEVEL'] ?? 'info';
  const allowed = ['fatal', 'error', 'warn', 'info', 'debug', 'trace'] as const;
  if (!(allowed as readonly string[]).includes(level)) {
    throw new Error(`ANTIDDOS_CTRL_LOG_LEVEL invalid: ${level}`);
  }

  const host = env['ANTIDDOS_CTRL_HOST'] ?? '127.0.0.1';
  const token = env['ANTIDDOS_CTRL_API_TOKEN'];
  let apiToken: string | null = null;
  if (token !== undefined && token !== '') {
    if (token.length < 16) {
      throw new Error('ANTIDDOS_CTRL_API_TOKEN must be at least 16 chars');
    }
    if (token.length > 512) {
      throw new Error('ANTIDDOS_CTRL_API_TOKEN too long (> 512 chars)');
    }
    apiToken = token;
  } else if (!isLoopbackHost(host)) {
    // Fail-fast : refuser de booter ouvert sur le réseau sans token.
    throw new Error(
      `ANTIDDOS_CTRL_API_TOKEN is required when ANTIDDOS_CTRL_HOST is not loopback (got ${host})`,
    );
  }

  const proxyToken = env['ANTIDDOS_PROXY_ADMIN_TOKEN'];
  let proxyAdminToken: string | null = null;
  if (proxyToken !== undefined && proxyToken !== '') {
    if (proxyToken.length < 16) {
      throw new Error('ANTIDDOS_PROXY_ADMIN_TOKEN must be at least 16 chars');
    }
    if (proxyToken.length > 512) {
      throw new Error('ANTIDDOS_PROXY_ADMIN_TOKEN too long (> 512 chars)');
    }
    proxyAdminToken = proxyToken;
  }

  return {
    listenHost: host,
    listenPort: parsedPort,
    logLevel: level as Config['logLevel'],
    proxyAdminUrl: env['ANTIDDOS_PROXY_ADMIN_URL'] ?? 'http://127.0.0.1:8081',
    proxyAdminToken,
    apiToken,
    stateDir: env['ANTIDDOS_CTRL_STATE_DIR'] ?? './state',
  };
}

/**
 * isLoopbackHost : approximation pragmatique. Couvre les cas usuels
 * 127.0.0.1 / ::1 / localhost. N'essaie pas de résoudre un hostname
 * arbitraire — si l'opérateur met une IP publique, on considère que
 * c'est non-loopback et on exige un token.
 */
export function isLoopbackHost(host: string): boolean {
  const h = host.toLowerCase();
  return (
    h === '127.0.0.1' ||
    h === '::1' ||
    h === 'localhost' ||
    h === '[::1]' ||
    h.startsWith('127.')
  );
}
