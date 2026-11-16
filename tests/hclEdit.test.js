'use strict';

const hcl = require('../src/iac/hclEdit');

const SRC = `# header
resource "aws_s3_bucket" "a" {
  bucket = "\${var.prefix}-data" # trailing comment
  acl    = "public-read"
  tags = {
    note = "a } inside a string"
  }
  policy = <<EOF
{ "Statement": [ { "unbalanced": "{" } ] }
EOF

  lifecycle_rule {
    enabled = true
  }
}

resource "aws_s3_bucket" "b" { }
`;

describe('HCL text editor', () => {
  const block = (src, name) => hcl.findBlock(src, 'resource', ['aws_s3_bucket', name]);

  test('finds block boundaries despite braces in strings, comments and heredocs', () => {
    const a = block(SRC, 'a');
    expect(SRC.slice(a.start, a.end)).toMatch(/^resource "aws_s3_bucket" "a" \{[\s\S]*enabled = true\n  \}\n\}$/);
    const names = hcl.parseBody(SRC, a.bodyStart, a.bodyEnd).map((i) => `${i.kind}:${i.name}`);
    expect(names).toEqual(['attr:bucket', 'attr:acl', 'attr:tags', 'attr:policy', 'block:lifecycle_rule']);
  });

  test('replaces a value in place and keeps the rest byte-identical', () => {
    const out = hcl.setAttr(SRC, block(SRC, 'a'), 'acl', '"private"');
    expect(out).toBe(SRC.replace('"public-read"', '"private"'));
  });

  test('keeps a trailing comment when replacing a value', () => {
    const out = hcl.setAttr(SRC, block(SRC, 'a'), 'bucket', '"x"');
    expect(out).toContain('bucket = "x" # trailing comment');
  });

  test('appends a missing attribute inside the right block', () => {
    const out = hcl.setAttr(SRC, block(SRC, 'a'), 'force_destroy', 'false');
    expect(out).toContain('  }\n  force_destroy = false\n}\n\nresource "aws_s3_bucket" "b"');
  });

  test('expands a one-line block when adding to it', () => {
    const out = hcl.setAttr(SRC, block(SRC, 'b'), 'bucket', '"b"');
    expect(out.endsWith('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')).toBe(true);
  });

  test('edits nested blocks', () => {
    const [rule] = hcl.nestedBlocks(SRC, block(SRC, 'a'), 'lifecycle_rule');
    expect(hcl.setAttr(SRC, rule, 'enabled', 'false')).toContain('    enabled = false');
  });
});
