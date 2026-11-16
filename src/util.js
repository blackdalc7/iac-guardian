'use strict';

const crypto = require('node:crypto');

// Deterministic JSON: keys sorted at every level. Hashes and signatures are
// computed over this form so they do not depend on property insertion order.
function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .filter((k) => value[k] !== undefined)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

const sameValue = (a, b) => canonical(a) === canonical(b);

module.exports = { canonical, sha256, sameValue };
