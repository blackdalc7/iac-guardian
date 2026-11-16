'use strict';

const { defineConfig, devices } = require('@playwright/test');

const PORT = 8799;

module.exports = defineConfig({
  testDir: './e2e',
  timeout: 30_000,
  fullyParallel: false,
  workers: 1,
  reporter: [['list']],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'off',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], viewport: { width: 1440, height: 900 } } }],
  // Demo mode: random webhook secret, dry-run GitHub client, fixture scenarios.
  webServer: {
    command: 'node src/server.js',
    url: `http://127.0.0.1:${PORT}/healthz`,
    env: { GUARDIAN_DEMO: '1', PORT: String(PORT) },
    reuseExistingServer: false,
  },
});
