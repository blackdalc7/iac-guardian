#!/usr/bin/env node
'use strict';

// Sends a signed `pull_request` webhook to a running agent, exactly as GitHub
// would. Usage: WEBHOOK_SECRET=... node scripts/simulate.js payments [url]

const crypto = require('node:crypto');
const { sign } = require('../src/security/webhook');
const { scenarios, buildEvent } = require('../fixtures/scenarios');

async function main() {
  const [id = 'payments', url = 'http://127.0.0.1:8787/webhook'] = process.argv.slice(2);
  const scenario = scenarios.find((s) => s.id === id);
  if (!scenario) throw new Error(`unknown scenario "${id}". Available: ${scenarios.map((s) => s.id).join(', ')}`);

  const secret = process.env.WEBHOOK_SECRET;
  if (!secret) throw new Error('set WEBHOOK_SECRET to the value the agent was started with');

  const body = Buffer.from(JSON.stringify(buildEvent(scenario)));
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'x-github-event': 'pull_request',
      'x-github-delivery': crypto.randomUUID(),
      'x-hub-signature-256': sign(secret, body),
    },
    body,
  });
  console.log(res.status, await res.text());
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
