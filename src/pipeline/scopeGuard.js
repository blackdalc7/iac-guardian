'use strict';

const { sameValue } = require('../util');

// Resource types a fix is allowed to introduce. Everything else must already
// exist in the pull request: the agent hardens infrastructure, it does not
// provision any.
const ADDABLE_TYPES = new Set(['aws_s3_bucket_public_access_block']);

// Constructs that execute code or open a remote session at apply time.
const EXECUTION_KEYS = ['provisioner', 'connection'];

const k8sKey = (o) => `${o.file}::${o.doc.kind}/${o.doc.metadata?.name ?? 'unnamed'}`;
const tfKey = (r) => `${r.file}::${r.address}`;

function images(value, out = []) {
  if (Array.isArray(value)) value.forEach((v) => images(v, out));
  else if (value && typeof value === 'object') {
    for (const [key, v] of Object.entries(value)) {
      if (key === 'image' && typeof v === 'string') out.push(v);
      else images(v, out);
    }
  }
  return out;
}

/**
 * Structural diff between the original and patched documents.
 *
 * OPA answers "is the result compliant?". This answers a different question:
 * "did the patch do anything it had no reason to do?". A model that has been
 * prompt-injected can produce a fully compliant file that also adds a
 * backdoor, so compliance alone is not a sufficient acceptance test.
 *
 * @returns {{rule: string, detail: string}[]} empty when the patch is in scope
 */
function checkScope({ before, after, baseline }) {
  const problems = [];
  const flag = (rule, detail) => problems.push({ rule, detail });

  // Resources a finding points at (directly or as a related resource) are
  // the only existing ones a fix has any business modifying.
  const allowed = new Set(baseline.flatMap((v) => [v.resource, ...(v.related || [])]));

  const beforeTf = new Map(before.terraform.resources.map((r) => [tfKey(r), r]));
  const afterTf = new Map(after.terraform.resources.map((r) => [tfKey(r), r]));

  for (const [key, r] of beforeTf) {
    const patched = afterTf.get(key);
    if (!patched) {
      flag('resource-removed', `${r.address} was deleted by the patch`);
    } else if (!sameValue(r.config, patched.config) && !allowed.has(r.address)) {
      flag('out-of-scope-change', `${r.address} was modified but no finding refers to it`);
    }
  }

  for (const [key, r] of afterTf) {
    if (!beforeTf.has(key) && !(r.kind === 'resource' && ADDABLE_TYPES.has(r.type))) {
      flag('resource-added', `${r.address} was introduced by the patch`);
    }
    const previous = beforeTf.get(key)?.config ?? {};
    for (const field of EXECUTION_KEYS) {
      if (r.config[field] !== undefined && !sameValue(r.config[field], previous[field])) {
        flag('execution-construct', `${r.address} gained or changed a '${field}' block`);
      }
    }
  }

  // Modules and providers pull in third-party code; settings include outputs
  // (a classic exfiltration channel) and the state backend.
  for (const section of ['modules', 'providers', 'settings']) {
    if (!sameValue(before.terraform[section], after.terraform[section])) {
      flag(`${section}-changed`, `the patch altered Terraform ${section}`);
    }
  }

  const beforeK8s = new Map(before.kubernetes.objects.map((o) => [k8sKey(o), o]));
  const afterK8s = new Map(after.kubernetes.objects.map((o) => [k8sKey(o), o]));

  for (const [key, o] of beforeK8s) {
    const patched = afterK8s.get(key);
    const address = `${o.doc.kind}/${o.doc.metadata?.name ?? 'unnamed'}`;
    if (!patched) {
      flag('object-removed', `${address} was deleted by the patch`);
      continue;
    }
    if (!sameValue(o.doc, patched.doc) && !allowed.has(address)) {
      flag('out-of-scope-change', `${address} was modified but no finding refers to it`);
    }
    // Swapping an image tag is a supply-chain change, never a hardening fix.
    if (!sameValue(images(o.doc), images(patched.doc))) {
      flag('image-changed', `${address} references different container images after the patch`);
    }
  }
  for (const [key, o] of afterK8s) {
    if (!beforeK8s.has(key)) flag('object-added', `${o.doc.kind}/${o.doc.metadata?.name ?? 'unnamed'} was introduced by the patch`);
  }

  return problems;
}

module.exports = { checkScope, ADDABLE_TYPES };
