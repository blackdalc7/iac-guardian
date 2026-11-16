'use strict';

const crypto = require('node:crypto');
const { structuredPatch } = require('diff');
const { buildDocument } = require('../iac/parse');
const { buildPrompt } = require('../llm/prompt');
const { reviewSchema } = require('../llm/provider');
const { checkScope } = require('./scopeGuard');
const { sha256 } = require('../util');

const findingKey = (f) => `${f.id}|${f.resource}`;

function diffFiles(original, patched) {
  const after = new Map(patched.map((f) => [f.path, f.content]));
  return original
    .filter((f) => after.get(f.path) !== f.content)
    .map((f) => {
      const patch = structuredPatch(f.path, f.path, f.content, after.get(f.path), '', '', { context: 3 });
      const lines = patch.hunks.flatMap((h) => h.lines);
      return {
        path: f.path,
        additions: lines.filter((l) => l.startsWith('+')).length,
        deletions: lines.filter((l) => l.startsWith('-')).length,
        hunks: patch.hunks.map(({ oldStart, oldLines, newStart, newLines, lines: body }) => ({ oldStart, oldLines, newStart, newLines, lines: body })),
      };
    });
}

/**
 * The remediation pipeline.
 *
 * Core idea: the model is an untrusted proposer and OPA is the verifier.
 * A patch is accepted only if four independent gates agree, and when one
 * does not, its findings go back to the model as counterexamples for the
 * next attempt (bounded, so a model that cannot converge fails closed).
 */
class Guardian {
  constructor({ engine, llm, github, ledger, maxAttempts = 3, maxAudits = 200 }) {
    this.engine = engine;
    this.llm = llm;
    this.github = github;
    this.ledger = ledger;
    this.maxAttempts = maxAttempts;
    this.maxAudits = maxAudits;
    this.audits = new Map();
    this.queue = Promise.resolve();
  }

  /** Registers an audit and returns immediately; work happens off-request. */
  submit(event) {
    const audit = {
      id: crypto.randomUUID(),
      createdAt: new Date().toISOString(),
      completedAt: null,
      status: 'queued',
      verdict: null,
      repo: `${event.repository.owner.login}/${event.repository.name}`,
      pr: {
        number: event.number,
        title: event.pull_request.title,
        author: event.pull_request.user.login,
        headRef: event.pull_request.head.ref,
        headSha: event.pull_request.head.sha,
        baseRef: event.pull_request.base.ref,
      },
      files: [],
      baseline: [],
      attempts: [],
      acceptedAttempt: null,
      github: { mode: this.github.mode, fixPullRequest: null, status: null, error: null },
      attestation: null,
      error: null,
    };

    this.audits.set(audit.id, audit);
    // Oldest reports are evicted so the in-memory store stays bounded.
    while (this.audits.size > this.maxAudits) this.audits.delete(this.audits.keys().next().value);

    // One job at a time: predictable ordering for the hash chain and no
    // unbounded parallel model calls triggered by a burst of webhooks.
    this.queue = this.queue.then(() => this.#process(audit, event));
    return audit;
  }

  idle() {
    return this.queue;
  }

  list() {
    return [...this.audits.values()].reverse();
  }

  get(id) {
    return this.audits.get(id);
  }

  async #process(audit, event) {
    audit.status = 'running';
    const target = { owner: event.repository.owner.login, repo: event.repository.name };
    let original = [];
    let accepted = null;

    try {
      original =
        event.guardian?.files ??
        (await this.github.getPullRequestFiles({ ...target, number: audit.pr.number, sha: audit.pr.headSha }));
      audit.files = original.map((f) => ({ path: f.path, sha256: sha256(f.content) }));

      const { doc: before, errors } = await buildDocument(original);
      if (errors.length) throw new Error(`could not parse ${errors[0].file}: ${errors[0].message}`);

      audit.baseline = this.engine.evaluate(before).map((v) => ({ ...v, detectedByAi: null }));

      if (original.length && audit.baseline.length) {
        accepted = await this.#repair(audit, original, before);
      }
      audit.verdict = !audit.baseline.length ? 'CLEAN' : accepted ? 'VERIFIED' : 'REJECTED';
    } catch (err) {
      audit.verdict = 'ERROR';
      audit.error = String(err.message || err).slice(0, 300);
    }

    audit.attestation = this.ledger.append(this.#statement(audit, original, accepted));
    await this.#report(audit, target, accepted);
    audit.status = 'done';
    audit.completedAt = new Date().toISOString();
  }

  async #repair(audit, original, before) {
    let feedback = null;

    for (let n = 1; n <= this.maxAttempts; n += 1) {
      const prompt = buildPrompt({ files: original, feedback, attempt: n }, crypto.randomBytes(8).toString('hex'));
      const attempt = { n, model: null, promptSha256: prompt.sha256, summary: '', findings: [], gates: [], remaining: [], diff: [], accepted: false };
      audit.attempts.push(attempt);
      const gate = (name, pass, details = []) => {
        attempt.gates.push({ name, pass, details });
        return pass;
      };

      // Gate 1 - schema. Model output is untrusted input like any other.
      const reply = reviewSchema.safeParse(await this.llm.review({ files: original, feedback, attempt: n, prompt }));
      const known = new Set(original.map((f) => f.path));
      const strays = reply.success ? reply.data.patches.filter((p) => !known.has(p.path)).map((p) => p.path) : [];
      if (!gate('schema', reply.success && strays.length === 0, reply.success ? strays.map((p) => `patch targets unknown file ${p}`) : ['reply did not match the expected schema'])) {
        feedback = { error: 'Reply must follow the JSON schema and only patch files from the request.' };
        continue;
      }

      const review = reply.data;
      attempt.model = review.model;
      attempt.summary = review.summary;
      attempt.findings = review.findings;
      const reported = new Set(review.findings.map(findingKey));
      for (const v of audit.baseline) {
        if (v.detectedByAi === null && reported.has(findingKey(v))) v.detectedByAi = n;
      }

      const patches = new Map(review.patches.map((p) => [p.path, p.content]));
      const patched = original.map((f) => ({ path: f.path, content: patches.get(f.path) ?? f.content }));
      attempt.diff = diffFiles(original, patched);

      // Gate 2 - syntax. The patch must still be valid HCL / YAML.
      const { doc: after, errors } = await buildDocument(patched);
      if (!gate('syntax', errors.length === 0, errors.map((e) => `${e.file}: ${e.message}`))) {
        feedback = { parseErrors: errors };
        continue;
      }

      // Gate 3 - scope. The patch may only touch what the findings justify.
      const scope = checkScope({ before, after, baseline: audit.baseline });
      const scopeOk = gate('scope', scope.length === 0, scope.map((s) => `${s.rule}: ${s.detail}`));

      // Gate 4 - policy. OPA must report zero violations on the result.
      attempt.remaining = this.engine.evaluate(after);
      const policyOk = gate('policy', attempt.remaining.length === 0, [...new Set(attempt.remaining.map((v) => `${v.id} ${v.resource}`))]);

      if (scopeOk && policyOk) {
        attempt.accepted = true;
        audit.acceptedAttempt = n;
        return patched;
      }
      feedback = {
        scopeViolations: scope,
        remainingViolations: attempt.remaining.map(({ id, resource, msg }) => ({ id, resource, msg })),
      };
    }
    return null;
  }

  // in-toto style statement: binds the verdict to the exact inputs, outputs
  // and policy build, so it cannot be replayed for different code.
  #statement(audit, original, accepted) {
    const patchedDigest = new Map((accepted || []).map((f) => [f.path, sha256(f.content)]));
    return {
      _type: 'https://in-toto.io/Statement/v1',
      subject: original.map((f) => ({ name: f.path, digest: { sha256: sha256(f.content) } })),
      predicateType: 'https://github.com/iac-guardian/attestations/policy-gate/v1',
      predicate: {
        auditId: audit.id,
        repository: audit.repo,
        pullRequest: audit.pr.number,
        headSha: audit.pr.headSha,
        verdict: audit.verdict,
        policy: { engine: 'opa-wasm', entrypoint: this.engine.manifest.entrypoint, sha256: this.engine.digest },
        violationsBefore: audit.baseline.map(findingKey),
        violationsAfter: accepted ? [] : audit.baseline.map(findingKey),
        attempts: audit.attempts.map((a) => ({ n: a.n, promptSha256: a.promptSha256, gates: Object.fromEntries(a.gates.map((g) => [g.name, g.pass])) })),
        patched: original
          .filter((f) => patchedDigest.has(f.path) && patchedDigest.get(f.path) !== sha256(f.content))
          .map((f) => ({ name: f.path, digest: { sha256: patchedDigest.get(f.path) } })),
        timestamp: audit.createdAt,
      },
    };
  }

  async #report(audit, target, accepted) {
    const count = audit.baseline.length;
    const sha = audit.pr.headSha;
    try {
      if (audit.verdict === 'VERIFIED') {
        const changed = accepted.filter((f) => audit.files.find((o) => o.path === f.path).sha256 !== sha256(f.content));
        audit.github.fixPullRequest = await this.github.openFixPullRequest({
          ...target,
          headRef: audit.pr.headRef,
          headSha: sha,
          branch: `iac-guardian/pr-${audit.pr.number}-${audit.attestation.hash.slice(0, 8)}`,
          files: changed,
          title: `fix(security): close ${count} policy violation${count === 1 ? '' : 's'} in #${audit.pr.number}`,
          body: fixBody(audit),
        });
        audit.github.status = { state: 'failure', description: `${count} violation(s) found - verified fix proposed` };
      } else if (audit.verdict === 'REJECTED') {
        audit.github.status = { state: 'failure', description: `${count} violation(s) found - no verified fix, human review required` };
        await this.github.comment({ ...target, number: audit.pr.number, body: rejectionBody(audit) });
      } else if (audit.verdict === 'CLEAN') {
        audit.github.status = { state: 'success', description: 'No policy violations' };
      } else {
        audit.github.status = { state: 'error', description: 'Analysis failed - see audit report' };
      }
      await this.github.setStatus({ ...target, sha, ...audit.github.status });
    } catch (err) {
      // Reporting problems must not rewrite the verdict that was just signed.
      audit.github.error = String(err.message || err).slice(0, 200);
    }
  }
}

const violationTable = (list) =>
  ['| Rule | Severity | Resource | Finding |', '| --- | --- | --- | --- |', ...list.map((v) => `| ${v.id} | ${v.severity} | \`${v.resource}\` | ${v.title} |`)].join('\n');

function fixBody(audit) {
  return [
    `Automated hardening for #${audit.pr.number}.`,
    '',
    violationTable(audit.baseline),
    '',
    `Every violation above is closed in this branch. The patch was accepted on attempt ${audit.acceptedAttempt} after passing the schema, syntax, scope and OPA policy gates.`,
    '',
    `- Policy build: \`sha256:${audit.attestation.statement.predicate.policy.sha256}\``,
    `- Ledger entry: \`${audit.attestation.hash}\` (key \`${audit.attestation.keyId}\`)`,
    '',
    'Review the diff before merging: the gates prove the policy is satisfied, not that the change matches your intent.',
  ].join('\n');
}

function rejectionBody(audit) {
  return [
    `IaC Guardian found ${audit.baseline.length} policy violation(s) and could not produce a fix that passes verification after ${audit.attempts.length} attempt(s). Nothing was changed.`,
    '',
    violationTable(audit.baseline),
    '',
    `Ledger entry: \`${audit.attestation.hash}\``,
  ].join('\n');
}

module.exports = { Guardian };
