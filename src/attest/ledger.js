'use strict';

const crypto = require('node:crypto');
const { canonical, sha256 } = require('../util');

const GENESIS = '0'.repeat(64);

class Signer {
  constructor(privateKey, ephemeral) {
    this.privateKey = privateKey;
    this.publicKey = crypto.createPublicKey(privateKey);
    this.ephemeral = ephemeral;
    const raw = this.publicKey.export({ type: 'spki', format: 'der' });
    this.keyId = sha256(raw).slice(0, 16);
  }

  // Ed25519: deterministic signatures, no per-signature nonce to get wrong.
  // Without a configured key a throwaway one is generated, which still makes
  // the ledger tamper-evident for the lifetime of the process.
  static fromEnv(pem) {
    if (pem) {
      const key = crypto.createPrivateKey(pem.replace(/\\n/g, '\n'));
      if (key.asymmetricKeyType !== 'ed25519') throw new Error('ATTESTATION_PRIVATE_KEY must be an Ed25519 key');
      return new Signer(key, false);
    }
    return new Signer(crypto.generateKeyPairSync('ed25519').privateKey, true);
  }

  sign(hexDigest) {
    return crypto.sign(null, Buffer.from(hexDigest, 'hex'), this.privateKey).toString('base64');
  }

  publicKeyPem() {
    return this.publicKey.export({ type: 'spki', format: 'pem' });
  }
}

function verifySignature(publicKeyPem, hexDigest, signature) {
  try {
    return crypto.verify(null, Buffer.from(hexDigest, 'hex'), publicKeyPem, Buffer.from(signature, 'base64'));
  } catch {
    return false;
  }
}

const entryHash = ({ index, prevHash, statement }) => sha256(canonical({ index, prevHash, statement }));

// Append-only log of signed verdicts. Each entry commits to the hash of the
// one before it, so rewriting or dropping a past verdict breaks every later
// link. This is the evidence an auditor checks instead of trusting the UI.
class Ledger {
  constructor(signer) {
    this.signer = signer;
    this.entries = [];
  }

  append(statement) {
    const index = this.entries.length;
    const prevHash = index ? this.entries[index - 1].hash : GENESIS;
    const hash = entryHash({ index, prevHash, statement });
    const entry = { index, prevHash, statement, hash, signature: this.signer.sign(hash), keyId: this.signer.keyId };
    this.entries.push(entry);
    return entry;
  }

  verifyEntry(entry, publicKeyPem = this.signer.publicKeyPem()) {
    const hashOk = entryHash(entry) === entry.hash;
    return { hashOk, signatureOk: hashOk && verifySignature(publicKeyPem, entry.hash, entry.signature) };
  }

  verifyChain() {
    let prev = GENESIS;
    for (const entry of this.entries) {
      const { hashOk, signatureOk } = this.verifyEntry(entry);
      if (!hashOk || !signatureOk || entry.prevHash !== prev) return { ok: false, brokenAt: entry.index, length: this.entries.length };
      prev = entry.hash;
    }
    return { ok: true, brokenAt: null, length: this.entries.length, head: prev };
  }
}

module.exports = { Signer, Ledger, verifySignature, GENESIS };
