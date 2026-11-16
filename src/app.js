'use strict';

const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const { verifySignature, ReplayCache } = require('./security/webhook');
const { pullRequestEvent, HANDLED_ACTIONS } = require('./security/payload');
const { scenarios, buildEvent } = require('../fixtures/scenarios');

const WEB_DIST = path.join(__dirname, '..', 'web', 'dist');
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const summary = (a) => ({
  id: a.id,
  createdAt: a.createdAt,
  status: a.status,
  verdict: a.verdict,
  repo: a.repo,
  pr: a.pr,
  violations: a.baseline.length,
  attempts: a.attempts.length,
});

function createApp({ config, guardian, engine, ledger }) {
  const app = express();
  const replay = new ReplayCache();

  app.disable('x-powered-by');
  app.use(
    helmet({
      // No inline script or style, no third-party origins: an XSS bug in the
      // report UI would have nowhere to load a payload from.
      contentSecurityPolicy: {
        useDefaults: false,
        directives: {
          defaultSrc: ["'none'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'"],
          fontSrc: ["'self'"],
          imgSrc: ["'self'", 'data:'],
          connectSrc: ["'self'"],
          baseUri: ["'none'"],
          formAction: ["'none'"],
          frameAncestors: ["'none'"],
        },
      },
      crossOriginResourcePolicy: { policy: 'same-origin' },
      referrerPolicy: { policy: 'no-referrer' },
    }),
  );
  app.use((req, res, next) => {
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), interest-cohort=()');
    next();
  });

  const limiter = (limit) => rateLimit({ windowMs: 60_000, limit, standardHeaders: 'draft-7', legacyHeaders: false });

  // ------------------------------------------------------------ webhook
  // express.raw keeps the exact bytes: the HMAC must be checked before the
  // body is parsed, and against what was sent rather than a re-encoding.
  app.post('/webhook', limiter(60), express.raw({ type: 'application/json', limit: '1mb' }), (req, res) => {
    if (!Buffer.isBuffer(req.body) || !verifySignature(config.webhookSecret, req.body, req.get('x-hub-signature-256'))) {
      return res.status(401).json({ error: 'invalid signature' });
    }

    const delivery = req.get('x-github-delivery');
    if (!delivery || !UUID.test(delivery)) return res.status(400).json({ error: 'missing delivery id' });
    if (!replay.claim(delivery)) return res.status(409).json({ error: 'duplicate delivery' });

    const event = req.get('x-github-event');
    if (event === 'ping') return res.json({ ok: true });
    if (event !== 'pull_request') return res.status(202).json({ ignored: `event ${String(event).slice(0, 40)}` });

    let body;
    try {
      body = JSON.parse(req.body.toString('utf8'));
    } catch {
      return res.status(400).json({ error: 'malformed JSON' });
    }
    const parsed = pullRequestEvent.safeParse(body);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      return res.status(422).json({ error: 'invalid payload', field: issue.path.join('.'), reason: issue.message });
    }
    if (!HANDLED_ACTIONS.has(parsed.data.action)) return res.status(202).json({ ignored: `action ${parsed.data.action}` });

    // Acknowledge straight away (GitHub times out after 10s) and analyse
    // in the background.
    const audit = guardian.submit(parsed.data);
    return res.status(202).json({ auditId: audit.id });
  });

  // -------------------------------------------------------- read-only API
  const api = express.Router();
  api.use(limiter(600));
  api.use((req, res, next) => {
    res.setHeader('Cache-Control', 'no-store');
    next();
  });

  api.get('/meta', (req, res) => {
    res.json({
      demo: config.demo,
      githubMode: guardian.github.mode,
      llm: guardian.llm.model,
      maxAttempts: guardian.maxAttempts,
      policy: engine.manifest,
      attestation: { keyId: ledger.signer.keyId, ephemeral: ledger.signer.ephemeral, publicKey: ledger.signer.publicKeyPem() },
      scenarios: config.demo ? scenarios.map(({ id, label, description }) => ({ id, label, description })) : [],
    });
  });

  api.get('/audits', (req, res) => res.json(guardian.list().map(summary)));

  api.get('/audits/:id', (req, res) => {
    const audit = UUID.test(req.params.id) && guardian.get(req.params.id);
    if (!audit) return res.status(404).json({ error: 'not found' });
    return res.json(audit);
  });

  // Re-computes the hash and signature server-side for one entry and walks
  // the whole chain, so the badge in the UI reflects a fresh check.
  api.get('/audits/:id/verify', (req, res) => {
    const audit = UUID.test(req.params.id) && guardian.get(req.params.id);
    if (!audit?.attestation) return res.status(404).json({ error: 'not found' });
    return res.json({ entry: ledger.verifyEntry(audit.attestation), chain: ledger.verifyChain() });
  });

  api.get('/ledger', (req, res) => {
    res.json({ chain: ledger.verifyChain(), entries: ledger.entries.map(({ index, hash, prevHash, keyId }) => ({ index, hash, prevHash, keyId })) });
  });

  if (config.demo) {
    // Demo-only trigger. The custom header cannot be sent cross-origin
    // without a CORS preflight (which is never granted), so another site
    // open in the same browser cannot fire it.
    api.post('/demo/:scenario', limiter(30), (req, res) => {
      if (req.get('x-guardian-demo') !== '1') return res.status(403).json({ error: 'forbidden' });
      const scenario = scenarios.find((s) => s.id === req.params.scenario);
      if (!scenario) return res.status(404).json({ error: 'unknown scenario' });
      // Same validation path as a real delivery: fixtures get no shortcut.
      const audit = guardian.submit(pullRequestEvent.parse(buildEvent(scenario)));
      return res.status(202).json({ auditId: audit.id });
    });
  }

  api.use((req, res) => res.status(404).json({ error: 'not found' }));
  app.use('/api', api);
  app.get('/healthz', (req, res) => res.json({ ok: true }));

  // ------------------------------------------------------------- web UI
  if (fs.existsSync(WEB_DIST)) {
    app.use(express.static(WEB_DIST, { index: 'index.html', maxAge: '1h' }));
  } else {
    app.get('/', (req, res) => res.type('text/plain').send('UI not built yet. Run: npm run build'));
  }

  app.use((req, res) => res.status(404).json({ error: 'not found' }));

  // Errors are logged server-side; clients only ever get a generic message.
  // eslint-disable-next-line no-unused-vars
  app.use((err, req, res, next) => {
    const status = err.status && err.status < 500 ? err.status : 500;
    if (status === 500) console.error('[guardian] unhandled error:', err.message);
    res.status(status).json({ error: status === 413 ? 'payload too large' : status === 500 ? 'internal error' : 'bad request' });
  });

  return app;
}

module.exports = { createApp };
