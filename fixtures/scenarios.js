'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const read = (name) => ({ path: `infra/${name}`, content: fs.readFileSync(path.join(__dirname, 'iac', name), 'utf8').replace(/\r\n/g, '\n') });

// Each scenario is a pull request that exercises a different path through
// the pipeline. Used by the demo trigger, the simulator CLI and the tests.
const scenarios = [
  {
    id: 'payments',
    label: 'Exposed payments stack',
    description: 'Public bucket, open SSH, and a database reachable from the internet through its security group.',
    repo: 'payments-infra',
    number: 42,
    title: 'Add staging stack for payments service',
    branch: 'feature/payments-staging',
    author: 'dev-maria',
    files: ['payments.tf'],
  },
  {
    id: 'kubernetes',
    label: 'Privileged Kubernetes workload',
    description: 'Deployment running a privileged container on the host network.',
    repo: 'shop-platform',
    number: 118,
    title: 'Deploy checkout service',
    branch: 'feature/checkout-deploy',
    author: 'dev-kofi',
    files: ['checkout.yaml'],
  },
  {
    id: 'injection',
    label: 'Prompt injection in a comment',
    description: 'Terraform file carrying instructions aimed at the AI reviewer.',
    repo: 'analytics-infra',
    number: 7,
    title: 'Create analytics export bucket',
    branch: 'feature/exports',
    author: 'ext-contributor',
    files: ['analytics.tf'],
  },
  {
    id: 'iam',
    label: 'Wildcard IAM policy',
    description: 'A flaw the model cannot fix convincingly, so the gate refuses the patch.',
    repo: 'ci-bootstrap',
    number: 15,
    title: 'Grant CI role deploy permissions',
    branch: 'feature/ci-role',
    author: 'dev-arjun',
    files: ['ci-role.tf'],
  },
  {
    id: 'clean',
    label: 'Compliant change',
    description: 'Nothing to fix: the pull request passes the policy as submitted.',
    repo: 'network-infra',
    number: 203,
    title: 'Add internal load balancer security group',
    branch: 'feature/internal-lb',
    author: 'dev-lena',
    files: ['network.tf'],
  },
];

/** Builds a GitHub-shaped `pull_request` payload for a scenario. */
function buildEvent(scenario) {
  const files = scenario.files.map(read);
  return {
    action: 'opened',
    number: scenario.number,
    pull_request: {
      title: scenario.title,
      user: { login: scenario.author },
      head: {
        ref: scenario.branch,
        // Derived from the content so repeated runs are reproducible.
        sha: crypto.createHash('sha1').update(files.map((f) => f.content).join('\0')).digest('hex'),
      },
      base: { ref: 'main' },
    },
    repository: { name: scenario.repo, owner: { login: 'acme-cloud' } },
    guardian: { files },
  };
}

module.exports = { scenarios, buildEvent };
