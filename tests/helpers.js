'use strict';

const crypto = require('node:crypto');
const { loadConfig } = require('../src/config');
const { createRuntime } = require('../src/bootstrap');
const { sign } = require('../src/security/webhook');
const { scenarios, buildEvent } = require('../fixtures/scenarios');

const SECRET = crypto.randomBytes(32).toString('hex');

const runtime = (overrides = {}, env = {}) =>
  createRuntime(loadConfig({ WEBHOOK_SECRET: SECRET, LLM_PROFILE: 'realistic', ...env }), overrides);

const event = (id) => buildEvent(scenarios.find((s) => s.id === id));

// Minimal event around arbitrary files, for the adversarial pipeline tests.
function eventWith(files) {
  const base = event('clean');
  return { ...base, guardian: { files } };
}

function signed(body, { secret = SECRET, delivery = crypto.randomUUID(), eventName = 'pull_request' } = {}) {
  const raw = typeof body === 'string' ? body : JSON.stringify(body);
  return {
    raw,
    headers: {
      'content-type': 'application/json',
      'x-github-event': eventName,
      'x-github-delivery': delivery,
      'x-hub-signature-256': sign(secret, Buffer.from(raw)),
    },
  };
}

/** LLM stub that replays scripted replies, one per attempt. */
const scriptedLlm = (...replies) => {
  let call = 0;
  return {
    model: 'scripted',
    calls: [],
    async review(request) {
      this.calls.push(request);
      const reply = replies[Math.min(call, replies.length - 1)];
      call += 1;
      return typeof reply === 'function' ? reply(request) : reply;
    },
  };
};

const reply = (patches, findings = []) => ({ model: 'scripted', findings, patches, summary: 'scripted reply' });

module.exports = { SECRET, runtime, event, eventWith, signed, scriptedLlm, reply };
