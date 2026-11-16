#!/usr/bin/env node
'use strict';

// Compiles policy/rego/*.rego into a single WebAssembly module and writes a
// manifest pinning its SHA-256. The agent refuses to boot if the module on
// disk does not match the manifest, so a swapped policy.wasm is detected.
//
// Requires the `opa` CLI (https://www.openpolicyagent.org/docs/#running-opa).
// Set OPA_BIN to use a binary that is not on PATH.

const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const ROOT = path.join(__dirname, '..', 'policy');
const REGO_DIR = path.join(ROOT, 'rego');
const DIST_DIR = path.join(ROOT, 'dist');
const ENTRYPOINT = 'guardian/deny';
const OPA = process.env.OPA_BIN || 'opa';

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// Minimal tar reader: an OPA bundle is a gzipped tar and we only need one
// entry out of it, which is not worth a dependency.
function extractFromTar(tar, wanted) {
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    const name = header.subarray(0, 100).toString('utf8').replace(/\0.*$/, '');
    if (!name) break;
    const size = parseInt(header.subarray(124, 136).toString('utf8').trim(), 8);
    const body = tar.subarray(offset + 512, offset + 512 + size);
    if (name.replace(/^\//, '') === wanted) return Buffer.from(body);
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  throw new Error(`${wanted} not found in bundle`);
}

function main() {
  const sources = fs
    .readdirSync(REGO_DIR)
    .filter((f) => f.endsWith('.rego') && !f.endsWith('_test.rego'))
    .sort();

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'guardian-policy-'));
  const bundle = path.join(tmp, 'bundle.tar.gz');

  execFileSync(OPA, ['check', '--strict', REGO_DIR], { stdio: 'inherit' });
  execFileSync(
    OPA,
    ['build', '-t', 'wasm', '-e', ENTRYPOINT, '-o', bundle, ...sources.map((f) => path.join(REGO_DIR, f))],
    { stdio: 'inherit' },
  );

  const wasm = extractFromTar(zlib.gunzipSync(fs.readFileSync(bundle)), 'policy.wasm');
  const opaVersion = execFileSync(OPA, ['version'], { encoding: 'utf8' }).match(/Version:\s*(\S+)/)[1];

  const manifest = {
    entrypoint: ENTRYPOINT,
    opaVersion,
    sha256: sha256(wasm),
    sources: Object.fromEntries(
      // Normalise line endings so the digest is identical on Windows checkouts.
      sources.map((f) => [f, sha256(fs.readFileSync(path.join(REGO_DIR, f), 'utf8').replace(/\r\n/g, '\n'))]),
    ),
  };

  fs.mkdirSync(DIST_DIR, { recursive: true });
  fs.writeFileSync(path.join(DIST_DIR, 'policy.wasm'), wasm);
  fs.writeFileSync(path.join(DIST_DIR, 'policy.manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  console.log(`policy.wasm  ${wasm.length} bytes  sha256:${manifest.sha256}`);
}

main();
