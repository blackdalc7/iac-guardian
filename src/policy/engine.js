'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { loadPolicy } = require('@open-policy-agent/opa-wasm');

const DIST = path.join(__dirname, '..', '..', 'policy', 'dist');
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };

class PolicyEngine {
  constructor(policy, manifest) {
    this.policy = policy;
    this.manifest = manifest;
  }

  static async load(dir = DIST) {
    const wasm = fs.readFileSync(path.join(dir, 'policy.wasm'));
    const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'policy.manifest.json'), 'utf8'));

    // The policy is the root of trust for every verdict, so it is pinned.
    // If the module on disk is not the one that was reviewed and built,
    // refuse to start instead of silently enforcing something else.
    const digest = crypto.createHash('sha256').update(wasm).digest('hex');
    if (digest !== manifest.sha256) {
      throw new Error(`policy.wasm digest mismatch: expected ${manifest.sha256}, found ${digest}`);
    }

    // Cap wasm memory (64 KiB pages) so a hostile input cannot balloon the heap.
    const policy = await loadPolicy(wasm, { initial: 16, maximum: 512 });
    return new PolicyEngine(policy, manifest);
  }

  get digest() {
    return this.manifest.sha256;
  }

  /** Evaluates the document and returns violations in a stable order. */
  evaluate(doc) {
    const result = this.policy.evaluate(doc, this.manifest.entrypoint);
    const violations = result?.[0]?.result ?? [];
    return [...violations].sort(
      (a, b) =>
        SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
        a.id.localeCompare(b.id) ||
        a.resource.localeCompare(b.resource) ||
        a.msg.localeCompare(b.msg),
    );
  }
}

module.exports = { PolicyEngine };
