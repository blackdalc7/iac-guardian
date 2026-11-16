'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { PolicyEngine } = require('../src/policy/engine');
const { buildDocument } = require('../src/iac/parse');
const { sha256 } = require('../src/util');

const DIST = path.join(__dirname, '..', 'policy', 'dist');
const REGO = path.join(__dirname, '..', 'policy', 'rego');

describe('policy engine', () => {
  test('refuses to load a policy module that does not match its manifest', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-policy-test-'));
    const wasm = fs.readFileSync(path.join(DIST, 'policy.wasm'));
    wasm[wasm.length - 1] ^= 0xff;
    fs.writeFileSync(path.join(dir, 'policy.wasm'), wasm);
    fs.copyFileSync(path.join(DIST, 'policy.manifest.json'), path.join(dir, 'policy.manifest.json'));

    await expect(PolicyEngine.load(dir)).rejects.toThrow(/digest mismatch/);
  });

  // Catches the easy mistake of editing a .rego file and forgetting to
  // rebuild: the wasm would silently enforce the old rules.
  test('committed wasm was built from the committed Rego sources', () => {
    const manifest = JSON.parse(fs.readFileSync(path.join(DIST, 'policy.manifest.json'), 'utf8'));
    for (const [file, digest] of Object.entries(manifest.sources)) {
      const source = fs.readFileSync(path.join(REGO, file), 'utf8').replace(/\r\n/g, '\n');
      expect([file, sha256(source)]).toEqual([file, digest]);
    }
  });

  test('evaluates parsed Terraform through the wasm entrypoint', async () => {
    const engine = await PolicyEngine.load();
    const { doc } = await buildDocument([
      {
        path: 'db.tf',
        content: `
resource "aws_security_group" "db" {
  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  engine                 = "mysql"
  storage_encrypted      = true
  vpc_security_group_ids = [aws_security_group.db.id]
}
`,
      },
    ]);

    const violations = engine.evaluate(doc);
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ id: 'TF009', severity: 'critical', resource: 'aws_db_instance.main', related: ['aws_security_group.db'] });
  });

  test('returns violations in a stable, severity-first order', async () => {
    const engine = await PolicyEngine.load();
    const { doc } = await buildDocument([
      { path: 'a.tf', content: 'resource "aws_ebs_volume" "v" {\n  size = 1\n}\nresource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n' },
    ]);
    const first = engine.evaluate(doc);
    expect(first.map((v) => v.id)).toEqual(['TF001', 'TF002', 'TF008']);
    expect(engine.evaluate(doc)).toEqual(first);
  });
});
