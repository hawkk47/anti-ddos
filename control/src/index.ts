import { buildApp } from './app.js';
import { loadConfigFromEnv } from './config.js';

async function main(): Promise<void> {
  const config = loadConfigFromEnv();
  const app = buildApp({ config });

  const shutdown = async (signal: string): Promise<void> => {
    app.log.info({ signal }, 'shutdown requested');
    try {
      await app.close();
      process.exit(0);
    } catch (err) {
      app.log.error({ err }, 'shutdown failed');
      process.exit(1);
    }
  };

  process.on('SIGINT', () => {
    void shutdown('SIGINT');
  });
  process.on('SIGTERM', () => {
    void shutdown('SIGTERM');
  });

  try {
    const addr = await app.listen({ host: config.listenHost, port: config.listenPort });
    app.log.info({ addr }, 'control plane listening');
  } catch (err) {
    app.log.error({ err }, 'listen failed');
    process.exit(2);
  }
}

void main();
