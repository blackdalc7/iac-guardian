'use strict';

const { loadConfig } = require('./config');
const { createRuntime } = require('./bootstrap');

async function main() {
  const config = loadConfig();
  const { app, engine, ledger, github } = await createRuntime(config);

  const server = app.listen(config.port, config.host, () => {
    console.log(`[guardian] listening on http://${config.host}:${config.port}`);
    console.log(`[guardian] policy sha256:${engine.digest}`);
    console.log(`[guardian] github mode: ${github.mode}${config.demo ? ' | demo scenarios enabled' : ''}`);
    if (ledger.signer.ephemeral) {
      console.log(`[guardian] using an ephemeral attestation key (${ledger.signer.keyId}); set ATTESTATION_PRIVATE_KEY to persist it`);
    }
  });

  // Slow-request limits: a client cannot hold sockets open indefinitely.
  server.headersTimeout = 10_000;
  server.requestTimeout = 15_000;

  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

main().catch((err) => {
  console.error(`[guardian] failed to start: ${err.message}`);
  process.exit(1);
});
