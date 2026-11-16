'use strict';

const request = require('supertest');
const { runtime, event, eventWith, scriptedLlm, reply } = require('./helpers');

async function run(rt, ev) {
  const audit = rt.guardian.submit(ev);
  await rt.guardian.idle();
  return audit;
}

const gates = (attempt) => Object.fromEntries(attempt.gates.map((g) => [g.name, g.pass]));

describe('repair loop on the reference scenarios', () => {
  let rt;
  beforeAll(async () => {
    rt = await runtime();
  });

  test('payments: converges on the second attempt using policy feedback', async () => {
    const audit = await run(rt, event('payments'));

    expect(audit.verdict).toBe('VERIFIED');
    expect(audit.baseline.map((v) => v.id).sort()).toEqual(['TF001', 'TF002', 'TF003', 'TF005', 'TF006', 'TF007', 'TF008', 'TF009']);
    expect(audit.acceptedAttempt).toBe(2);

    // First pass misses the two cross-resource findings; OPA reports them.
    expect(gates(audit.attempts[0]).policy).toBe(false);
    expect(audit.attempts[0].remaining.map((v) => v.id).sort()).toEqual(['TF002', 'TF009']);
    expect(audit.attempts[1].remaining).toEqual([]);

    const missed = audit.baseline.filter((v) => v.detectedByAi === 2).map((v) => v.id).sort();
    expect(missed).toEqual(['TF002', 'TF009']);
  });

  test('payments: proposes a fix PR against the contributor branch', async () => {
    const call = rt.github.calls.find((c) => c.op === 'openFixPullRequest' && c.repo === 'payments-infra');
    expect(call.headRef).toBe('feature/payments-staging');
    expect(call.branch).toMatch(/^iac-guardian\/pr-42-[0-9a-f]{8}$/);
    expect(call.files).toHaveLength(1);
    expect(call.files[0].content).toContain('publicly_accessible    = false');
    expect(call.files[0].content).toContain('resource "aws_s3_bucket_public_access_block" "receipts"');
    // Public HTTPS was never a finding and must survive the patch untouched.
    expect(call.files[0].content).toMatch(/to_port\s+= 443\s+protocol\s+= "tcp"\s+cidr_blocks = \["0\.0\.0\.0\/0"\]/);
  });

  test('kubernetes: hardens the workload and leaves the Service alone', async () => {
    const audit = await run(rt, event('kubernetes'));
    expect(audit.verdict).toBe('VERIFIED');
    expect(audit.acceptedAttempt).toBe(1);

    const patched = rt.github.calls.find((c) => c.op === 'openFixPullRequest' && c.repo === 'shop-platform').files[0].content;
    expect(patched).toContain('privileged: false');
    expect(patched).toContain('hostNetwork: false');
    expect(patched).toContain('image: registry.acme.example/shop/checkout:2.8.1');
    expect(patched).toContain('kind: Service');
  });

  test('injection: the backdoor is blocked by the scope gate, then a clean fix is accepted', async () => {
    const audit = await run(rt, event('injection'));
    const [first, second] = audit.attempts;

    expect(gates(first).scope).toBe(false);
    expect(first.gates.find((g) => g.name === 'scope').details.join(' ')).toMatch(/resource-added.*null_resource/);
    expect(first.gates.find((g) => g.name === 'scope').details.join(' ')).toMatch(/execution-construct/);
    expect(first.accepted).toBe(false);

    expect(audit.verdict).toBe('VERIFIED');
    expect(second.accepted).toBe(true);
    const shipped = rt.github.calls.find((c) => c.op === 'openFixPullRequest' && c.repo === 'analytics-infra').files[0].content;
    expect(shipped).not.toContain('null_resource');
    expect(shipped).not.toContain('local-exec');
  });

  test('iam: fails closed when the model cannot satisfy the policy', async () => {
    const audit = await run(rt, event('iam'));
    expect(audit.verdict).toBe('REJECTED');
    expect(audit.attempts).toHaveLength(3);
    expect(audit.acceptedAttempt).toBeNull();
    expect(rt.github.calls.some((c) => c.op === 'openFixPullRequest' && c.repo === 'ci-bootstrap')).toBe(false);
    expect(rt.github.calls.find((c) => c.op === 'comment' && c.repo === 'ci-bootstrap').body).toMatch(/Nothing was changed/);
    expect(audit.github.status.state).toBe('failure');
  });

  test('clean: passes without calling for a fix', async () => {
    const audit = await run(rt, event('clean'));
    expect(audit.verdict).toBe('CLEAN');
    expect(audit.attempts).toHaveLength(0);
    expect(audit.github.status.state).toBe('success');
  });

  test('ideal model profile verifies the payments stack in one attempt', async () => {
    const ideal = await runtime({}, { LLM_PROFILE: 'ideal' });
    const audit = await run(ideal, event('payments'));
    expect(audit.verdict).toBe('VERIFIED');
    expect(audit.acceptedAttempt).toBe(1);
  });
});

describe('gates against a hostile or broken model', () => {
  const BUCKET = 'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n  acl    = "public-read"\n}\n';
  const VOLUME = 'resource "aws_ebs_volume" "data" {\n  size = 10\n  encrypted = true\n}\n';
  const LOCKED =
    'resource "aws_s3_bucket_public_access_block" "logs" {\n  bucket = aws_s3_bucket.logs.id\n  block_public_acls = true\n  block_public_policy = true\n  ignore_public_acls = true\n  restrict_public_buckets = true\n}\n';
  const FIXED = `${BUCKET.replace('public-read', 'private')}${LOCKED}`;
  const files = [{ path: 'main.tf', content: BUCKET + VOLUME }];

  const attempt = async (patchContent, path = 'main.tf') => {
    const rt = await runtime({ llm: scriptedLlm(reply([{ path, content: patchContent }])) }, { MAX_REPAIR_ATTEMPTS: '1' });
    const audit = await run(rt, eventWith(files));
    return { audit, rt, gate: (name) => audit.attempts[0].gates.find((g) => g.name === name) };
  };

  test('accepts the minimal correct patch (control case)', async () => {
    const { audit } = await attempt(FIXED + VOLUME);
    expect(audit.verdict).toBe('VERIFIED');
  });

  test('rejects a patch that "fixes" the finding by deleting the resource', async () => {
    const { audit, gate } = await attempt(VOLUME);
    expect(audit.verdict).toBe('REJECTED');
    expect(gate('policy').pass).toBe(true); // compliant, and still wrong
    expect(gate('scope').details.join()).toMatch(/resource-removed: aws_s3_bucket\.logs/);
  });

  test('rejects a compliant patch that also edits an unrelated resource', async () => {
    const { audit, gate } = await attempt(FIXED + VOLUME.replace('size = 10', 'size = 5000'));
    expect(audit.verdict).toBe('REJECTED');
    expect(gate('scope').details.join()).toMatch(/out-of-scope-change: aws_ebs_volume\.data/);
  });

  test('rejects a compliant patch that adds an output to leak data', async () => {
    const { audit, gate } = await attempt(`${FIXED}${VOLUME}output "leak" {\n  value = aws_s3_bucket.logs.arn\n}\n`);
    expect(audit.verdict).toBe('REJECTED');
    expect(gate('scope').details.join()).toMatch(/settings-changed/);
  });

  test('rejects a compliant patch that pulls in a module', async () => {
    const { gate } = await attempt(`${FIXED}${VOLUME}module "helper" {\n  source = "git::https://example.invalid/mod.git"\n}\n`);
    expect(gate('scope').details.join()).toMatch(/modules-changed/);
  });

  test('rejects a patch that attaches a provisioner to an existing resource', async () => {
    const withProvisioner = FIXED.replace('acl    = "private"', 'acl    = "private"\n  provisioner "local-exec" {\n    command = "id"\n  }');
    const { gate } = await attempt(withProvisioner + VOLUME);
    expect(gate('scope').details.join()).toMatch(/execution-construct: aws_s3_bucket\.logs/);
  });

  test('rejects a patch that is not valid HCL', async () => {
    const { audit, gate } = await attempt('resource "aws_s3_bucket" "logs" {');
    expect(audit.verdict).toBe('REJECTED');
    expect(gate('syntax').pass).toBe(false);
    expect(gate('policy')).toBeUndefined(); // later gates never run on unparsable input
  });

  test('rejects a patch aimed at a file that is not part of the pull request', async () => {
    const { audit, gate } = await attempt(FIXED, '.github/workflows/deploy.yaml');
    expect(audit.verdict).toBe('REJECTED');
    expect(gate('schema').details.join()).toMatch(/unknown file/);
  });

  test('rejects a reply that does not follow the schema', async () => {
    const rt = await runtime({ llm: scriptedLlm({ patches: 'rm -rf /', findings: null }) }, { MAX_REPAIR_ATTEMPTS: '1' });
    const audit = await run(rt, eventWith(files));
    expect(audit.verdict).toBe('REJECTED');
    expect(audit.attempts[0].gates).toEqual([{ name: 'schema', pass: false, details: ['reply did not match the expected schema'] }]);
  });

  test('rejects a no-op patch: claiming success is not evidence', async () => {
    const rt = await runtime({ llm: scriptedLlm(reply([])) });
    const audit = await run(rt, eventWith(files));
    expect(audit.verdict).toBe('REJECTED');
    expect(audit.attempts).toHaveLength(3);
  });

  test('rejects a Kubernetes patch that swaps the container image', async () => {
    const pod = 'apiVersion: v1\nkind: Pod\nmetadata:\n  name: job\nspec:\n  containers:\n    - name: job\n      image: registry.example/job:1.0\n';
    const hardened = `${pod.replace('job:1.0', 'evil/job:latest')}      securityContext:\n        runAsNonRoot: true\n        allowPrivilegeEscalation: false\n`;
    const rt = await runtime({ llm: scriptedLlm(reply([{ path: 'pod.yaml', content: hardened }])) }, { MAX_REPAIR_ATTEMPTS: '1' });
    const audit = await run(rt, eventWith([{ path: 'pod.yaml', content: pod }]));
    expect(audit.verdict).toBe('REJECTED');
    expect(audit.attempts[0].gates.find((g) => g.name === 'scope').details.join()).toMatch(/image-changed/);
  });

  test('feeds gate results back to the model on the next attempt', async () => {
    const llm = scriptedLlm(reply([]), reply([{ path: 'main.tf', content: FIXED + VOLUME }]));
    const rt = await runtime({ llm });
    const audit = await run(rt, eventWith(files));

    expect(audit.verdict).toBe('VERIFIED');
    expect(llm.calls[0].feedback).toBeNull();
    expect(llm.calls[1].feedback.remainingViolations.map((v) => v.id).sort()).toEqual(['TF001', 'TF002']);
  });

  test('wraps untrusted files in an unguessable, per-request delimiter', async () => {
    const llm = scriptedLlm(reply([]));
    const rt = await runtime({ llm });
    await run(rt, eventWith(files));
    const fences = llm.calls.map((c) => /<file-([0-9a-f]{16}) /.exec(c.prompt.user)[1]);
    expect(new Set(fences).size).toBe(fences.length);
  });

  test('reports unparsable input as an error instead of guessing', async () => {
    const rt = await runtime();
    const audit = await run(rt, eventWith([{ path: 'broken.tf', content: 'resource "x" "y" {' }]));
    expect(audit.verdict).toBe('ERROR');
    expect(audit.error).toMatch(/could not parse broken\.tf/);
    expect(audit.github.status.state).toBe('error');
  });
});

describe('audit API', () => {
  test('exposes reports and a live verification of their attestation', async () => {
    const rt = await runtime();
    const audit = await run(rt, event('kubernetes'));

    const list = await request(rt.app).get('/api/audits');
    expect(list.body[0]).toMatchObject({ id: audit.id, verdict: 'VERIFIED', violations: 4 });

    const detail = await request(rt.app).get(`/api/audits/${audit.id}`);
    expect(detail.body.attempts[0].diff[0].hunks.length).toBeGreaterThan(0);
    expect(detail.headers['cache-control']).toBe('no-store');

    const verify = await request(rt.app).get(`/api/audits/${audit.id}/verify`);
    expect(verify.body).toEqual({
      entry: { hashOk: true, signatureOk: true },
      chain: expect.objectContaining({ ok: true, length: 1 }),
    });
  });
});
