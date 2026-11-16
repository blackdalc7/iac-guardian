'use strict';

const { PolicyEngine } = require('./policy/engine');
const { MockLlm } = require('./llm/mock');
const { DryRunGitHub, RestGitHub } = require('./github/client');
const { Signer, Ledger } = require('./attest/ledger');
const { Guardian } = require('./pipeline/guardian');
const { createApp } = require('./app');

// Wires the object graph in one place so tests can swap any collaborator.
async function createRuntime(config, overrides = {}) {
  const engine = overrides.engine || (await PolicyEngine.load());
  const ledger = overrides.ledger || new Ledger(Signer.fromEnv(config.attestationPrivateKey));
  const llm = overrides.llm || new MockLlm({ profile: config.llmProfile });
  // Demo scenarios reference repositories that do not exist, so demo mode
  // never talks to GitHub even if a token happens to be in the environment.
  const live = config.githubToken && !config.demo;
  const github =
    overrides.github || (live ? new RestGitHub({ token: config.githubToken, apiUrl: config.githubApiUrl }) : new DryRunGitHub());
  const guardian = new Guardian({ engine, llm, github, ledger, maxAttempts: config.maxAttempts });
  const app = createApp({ config, guardian, engine, ledger });
  return { app, guardian, engine, ledger, github, llm };
}

module.exports = { createRuntime };
