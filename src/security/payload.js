'use strict';

const { z } = require('zod');

const MAX_FILES = 20;
const MAX_FILE_BYTES = 200 * 1024;

// GitHub's own naming rules. Validating them here means these values can be
// interpolated into API paths later without any risk of path traversal.
const login = z.string().regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/);
const repoName = z.string().regex(/^[A-Za-z0-9._-]{1,100}$/).refine((v) => v !== '.' && v !== '..');
const gitRef = z
  .string()
  .min(1)
  .max(200)
  .regex(/^[A-Za-z0-9._\/-]+$/)
  .refine((v) => !v.includes('..') && !v.startsWith('/') && !v.endsWith('/'));
const sha = z.string().regex(/^[0-9a-f]{40}$/);

const filePath = z
  .string()
  .min(1)
  .max(300)
  .regex(/^[A-Za-z0-9._\/-]+$/, 'unexpected characters in path')
  .refine((p) => !p.startsWith('/') && !p.split('/').some((seg) => seg === '..' || seg === ''), 'path must be relative')
  .refine((p) => /\.(tf|ya?ml)$/.test(p), 'only .tf, .yaml and .yml files are analysed');

const file = z.object({
  path: filePath,
  content: z.string().refine((c) => Buffer.byteLength(c, 'utf8') <= MAX_FILE_BYTES, 'file too large'),
});

// Only the fields the agent actually uses are declared; everything else in
// the (large) GitHub payload is stripped by zod rather than trusted.
const pullRequestEvent = z.object({
  action: z.string().max(40),
  number: z.number().int().positive(),
  pull_request: z.object({
    title: z.string().max(300),
    user: z.object({ login }),
    head: z.object({ ref: gitRef, sha }),
    base: z.object({ ref: gitRef }),
  }),
  repository: z.object({
    name: repoName,
    owner: z.object({ login }),
  }),
  // Simulation extension: lets a payload carry the changed files inline so the
  // agent can be exercised without network access to GitHub.
  guardian: z
    .object({
      files: z
        .array(file)
        .min(1)
        .max(MAX_FILES)
        .refine((files) => new Set(files.map((f) => f.path)).size === files.length, 'duplicate file paths'),
    })
    .optional(),
});

const HANDLED_ACTIONS = new Set(['opened', 'synchronize', 'reopened']);

module.exports = { pullRequestEvent, filePath, HANDLED_ACTIONS, MAX_FILES, MAX_FILE_BYTES };
