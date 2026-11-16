'use strict';

const crypto = require('node:crypto');

const SIGNATURE_RE = /^sha256=[0-9a-f]{64}$/;

function sign(secret, rawBody) {
  return `sha256=${crypto.createHmac('sha256', secret).update(rawBody).digest('hex')}`;
}

// The HMAC is computed over the raw bytes GitHub sent. Verifying a
// re-serialised JSON body would let whitespace differences break (or worse,
// forge) the check. Comparison is constant-time to avoid leaking how many
// leading characters of a guessed signature were right.
function verifySignature(secret, rawBody, header) {
  if (typeof header !== 'string' || !SIGNATURE_RE.test(header)) return false;
  const expected = Buffer.from(sign(secret, rawBody), 'utf8');
  const received = Buffer.from(header, 'utf8');
  return expected.length === received.length && crypto.timingSafeEqual(expected, received);
}

// A valid signature only proves the payload came from GitHub once. Remembering
// delivery IDs stops a captured request from being replayed to re-trigger the
// pipeline. The cache is bounded so it cannot be used to exhaust memory.
class ReplayCache {
  constructor({ ttlMs = 10 * 60 * 1000, maxEntries = 5000 } = {}) {
    this.ttlMs = ttlMs;
    this.maxEntries = maxEntries;
    this.seen = new Map();
  }

  /** Returns true the first time an id is seen, false on a replay. */
  claim(id, now = Date.now()) {
    for (const [key, expiry] of this.seen) {
      if (expiry > now && this.seen.size <= this.maxEntries) break;
      this.seen.delete(key);
    }
    if (this.seen.has(id)) return false;
    this.seen.set(id, now + this.ttlMs);
    return true;
  }
}

module.exports = { sign, verifySignature, ReplayCache };
