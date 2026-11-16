'use strict';

const { z } = require('zod');
const { filePath } = require('../security/payload');

// The model's reply is parsed against a strict schema before anything reads
// it. Model output is attacker-influenced (the prompt contains attacker-
// written code), so it gets the same treatment as any other untrusted input.
const reviewSchema = z.object({
  model: z.string().max(100),
  findings: z
    .array(
      z.object({
        id: z.string().regex(/^[A-Z0-9]{3,8}$/),
        severity: z.enum(['critical', 'high', 'medium', 'low']),
        resource: z.string().max(200),
        file: z.string().max(300),
        rationale: z.string().max(600),
      }),
    )
    .max(200),
  patches: z.array(z.object({ path: filePath, content: z.string().max(400 * 1024) })).max(20),
  summary: z.string().max(2000),
});

/**
 * Contract every model backend implements. Swapping the mock for a hosted
 * model means implementing review(); nothing downstream changes, because
 * nothing downstream trusts the answer.
 *
 * @typedef {object} LlmProvider
 * @property {(request: {files: {path: string, content: string}[], feedback?: object, attempt: number}) => Promise<object>} review
 */

module.exports = { reviewSchema };
