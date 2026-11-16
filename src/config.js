'use strict';

const crypto = require('node:crypto');
const { z } = require('zod');

// Every knob comes from the environment so nothing sensitive lives in git.
const schema = z.object({
  PORT: z.coerce.number().int().min(1).max(65535).default(8787),
  HOST: z.string().default('127.0.0.1'),
  GUARDIAN_DEMO: z.enum(['0', '1']).default('0'),
  WEBHOOK_SECRET: z.string().min(32, 'WEBHOOK_SECRET must be at least 32 characters').optional(),
  GITHUB_TOKEN: z.string().min(1).optional(),
  GITHUB_API_URL: z.string().url().default('https://api.github.com'),
  ATTESTATION_PRIVATE_KEY: z.string().min(1).optional(),
  MAX_REPAIR_ATTEMPTS: z.coerce.number().int().min(1).max(5).default(3),
  LLM_PROFILE: z.enum(['realistic', 'ideal']).default('realistic'),
});

function loadConfig(env = process.env) {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ');
    throw new Error(`Invalid configuration - ${problems}`);
  }
  const cfg = parsed.data;
  const demo = cfg.GUARDIAN_DEMO === '1';

  // Fail closed: outside demo mode an unsigned webhook endpoint is never
  // acceptable, so a missing secret stops the process instead of warning.
  if (!cfg.WEBHOOK_SECRET && !demo) {
    throw new Error('WEBHOOK_SECRET is required (set GUARDIAN_DEMO=1 for a local demo with a random secret)');
  }

  return {
    port: cfg.PORT,
    host: cfg.HOST,
    demo,
    webhookSecret: cfg.WEBHOOK_SECRET || crypto.randomBytes(32).toString('hex'),
    githubToken: cfg.GITHUB_TOKEN,
    githubApiUrl: cfg.GITHUB_API_URL,
    attestationPrivateKey: cfg.ATTESTATION_PRIVATE_KEY,
    maxAttempts: cfg.MAX_REPAIR_ATTEMPTS,
    llmProfile: cfg.LLM_PROFILE,
  };
}

module.exports = { loadConfig };
