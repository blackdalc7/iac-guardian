'use strict';

const request = require('supertest');
const { runtime, event, signed, SECRET } = require('./helpers');
const { verifySignature, sign, ReplayCache } = require('../src/security/webhook');
const { loadConfig } = require('../src/config');

const post = (app, { raw, headers }) => request(app).post('/webhook').set(headers).send(raw);

describe('webhook authentication', () => {
  let rt;
  beforeAll(async () => {
    rt = await runtime();
  });

  test('accepts a correctly signed pull_request event', async () => {
    const res = await post(rt.app, signed(event('clean')));
    expect(res.status).toBe(202);
    await rt.guardian.idle();
    expect(rt.guardian.get(res.body.auditId).verdict).toBe('CLEAN');
  });

  test('rejects a missing signature', async () => {
    const req = signed(event('clean'));
    delete req.headers['x-hub-signature-256'];
    expect((await post(rt.app, req)).status).toBe(401);
  });

  test('rejects a signature made with the wrong secret', async () => {
    const res = await post(rt.app, signed(event('clean'), { secret: 'not-the-secret'.repeat(4) }));
    expect(res.status).toBe(401);
  });

  test('rejects a body modified after signing', async () => {
    const req = signed(event('clean'));
    req.raw = req.raw.replace('"opened"', '"reopened"');
    expect((await post(rt.app, req)).status).toBe(401);
  });

  test('rejects a replayed delivery', async () => {
    const req = signed(event('clean'));
    expect((await post(rt.app, req)).status).toBe(202);
    expect((await post(rt.app, req)).status).toBe(409);
  });

  test('requires a well-formed delivery id', async () => {
    const res = await post(rt.app, signed(event('clean'), { delivery: 'abc' }));
    expect(res.status).toBe(400);
  });

  test('answers ping and ignores unrelated events and actions', async () => {
    expect((await post(rt.app, signed({ zen: 'ok' }, { eventName: 'ping' }))).body).toEqual({ ok: true });
    expect((await post(rt.app, signed({}, { eventName: 'push' }))).body.ignored).toMatch(/push/);
    const closed = await post(rt.app, signed({ ...event('clean'), action: 'closed' }));
    expect(closed.body.ignored).toMatch(/closed/);
  });

  test('rejects malformed JSON even when it is correctly signed', async () => {
    expect((await post(rt.app, signed('{"action":'))).status).toBe(400);
  });

  test('rejects oversized bodies before doing any work', async () => {
    const res = await post(rt.app, signed(JSON.stringify({ pad: 'x'.repeat(1_100_000) })));
    expect(res.status).toBe(413);
  });
});

describe('payload validation', () => {
  let rt;
  beforeAll(async () => {
    rt = await runtime();
  });

  const withFile = (path) => ({ ...event('clean'), guardian: { files: [{ path, content: '' }] } });

  test.each([['../../etc/passwd.tf'], ['/abs/main.tf'], ['infra//main.tf'], ['infra/main.tf.sh'], ['infra/ma in.tf']])(
    'rejects unsafe file path %s',
    async (path) => {
      const res = await post(rt.app, signed(withFile(path)));
      expect(res.status).toBe(422);
    },
  );

  test('rejects repository names that could alter an API path', async () => {
    const body = event('clean');
    body.repository.name = '../../user';
    const res = await post(rt.app, signed(body));
    expect(res.status).toBe(422);
    expect(res.body.field).toBe('repository.name');
  });

  test('rejects a head sha that is not a full commit id', async () => {
    const body = event('clean');
    body.pull_request.head.sha = 'main';
    expect((await post(rt.app, signed(body))).status).toBe(422);
  });

  test('rejects duplicate paths and too many files', async () => {
    const dup = { ...event('clean'), guardian: { files: [{ path: 'a.tf', content: '' }, { path: 'a.tf', content: '' }] } };
    expect((await post(rt.app, signed(dup))).status).toBe(422);
    const many = { ...event('clean'), guardian: { files: Array.from({ length: 21 }, (_, i) => ({ path: `f${i}.tf`, content: '' })) } };
    expect((await post(rt.app, signed(many))).status).toBe(422);
  });
});

describe('signature primitives', () => {
  const body = Buffer.from('{"a":1}');

  test('verifies only the exact signature', () => {
    const good = sign(SECRET, body);
    expect(verifySignature(SECRET, body, good)).toBe(true);
    expect(verifySignature(SECRET, body, good.replace(/.$/, (c) => (c === '0' ? '1' : '0')))).toBe(false);
    expect(verifySignature(SECRET, body, good.toUpperCase())).toBe(false);
    expect(verifySignature(SECRET, body, 'sha1=abcdef')).toBe(false);
    expect(verifySignature(SECRET, body, undefined)).toBe(false);
  });

  test('replay cache expires entries and stays bounded', () => {
    const cache = new ReplayCache({ ttlMs: 1000, maxEntries: 3 });
    expect(cache.claim('a', 0)).toBe(true);
    expect(cache.claim('a', 500)).toBe(false);
    expect(cache.claim('a', 1500)).toBe(true);
    ['b', 'c', 'd', 'e', 'f'].forEach((id) => cache.claim(id, 1600));
    expect(cache.seen.size).toBeLessThanOrEqual(4);
  });
});

describe('configuration', () => {
  test('refuses to start without a webhook secret outside demo mode', () => {
    expect(() => loadConfig({})).toThrow(/WEBHOOK_SECRET is required/);
  });

  test('refuses a short webhook secret', () => {
    expect(() => loadConfig({ WEBHOOK_SECRET: 'short' })).toThrow(/at least 32/);
  });

  test('demo mode generates a random secret per process', () => {
    const a = loadConfig({ GUARDIAN_DEMO: '1' });
    const b = loadConfig({ GUARDIAN_DEMO: '1' });
    expect(a.webhookSecret).toHaveLength(64);
    expect(a.webhookSecret).not.toBe(b.webhookSecret);
  });
});

describe('http surface', () => {
  let rt;
  beforeAll(async () => {
    rt = await runtime();
  });

  test('sends a strict CSP and hardening headers', async () => {
    const res = await request(rt.app).get('/healthz');
    const csp = res.headers['content-security-policy'];
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain('unsafe-inline');
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
    expect(res.headers['x-powered-by']).toBeUndefined();
  });

  test('demo trigger does not exist outside demo mode', async () => {
    const res = await request(rt.app).post('/api/demo/payments').set('x-guardian-demo', '1');
    expect(res.status).toBe(404);
  });

  test('demo trigger needs the custom header in demo mode', async () => {
    const demo = await runtime({}, { GUARDIAN_DEMO: '1' });
    expect((await request(demo.app).post('/api/demo/payments')).status).toBe(403);
    const ok = await request(demo.app).post('/api/demo/payments').set('x-guardian-demo', '1');
    expect(ok.status).toBe(202);
    await demo.guardian.idle();
  });

  test('audit lookup validates the id and never echoes it', async () => {
    const res = await request(rt.app).get('/api/audits/<script>alert(1)</script>');
    expect(res.status).toBe(404);
    expect(res.text).not.toContain('script');
  });
});
