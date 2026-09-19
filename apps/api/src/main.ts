import { createLogger, PRODUCT_NAME, PRODUCT_TAGLINE } from '@adminsecops/core';
import { loadConfig } from './config.js';
import { buildServer } from './server.js';

const log = createLogger({ bindings: { component: 'api' } });

async function main(): Promise<void> {
  const config = loadConfig();
  // The Vite dev server proxies to this API and forwards its own Host header.
  const devHosts = process.env.ADMINSECOPS_DEV === '1' ? ['localhost:5173', '127.0.0.1:5173'] : [];
  const app = await buildServer({ config, logger: log, extraHosts: devHosts });
  await app.listen({ host: config.host, port: config.port });
  log.info('started', { url: `http://${config.host === '::1' ? '[::1]' : config.host}:${config.port}`, dataDir: config.dataDir });
  process.stdout.write(`\n${PRODUCT_NAME} - ${PRODUCT_TAGLINE}\nOpen http://localhost:${config.port} in your browser. Press Ctrl+C to stop.\n\n`);

  const shutdown = (): void => {
    void app.close().then(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

main().catch((error: unknown) => {
  log.error('failed to start', { error: error instanceof Error ? error.message : 'unknown error' });
  process.exit(1);
});
