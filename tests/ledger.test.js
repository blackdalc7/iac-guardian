'use strict';

const crypto = require('node:crypto');
const { Signer, Ledger } = require('../src/attest/ledger');
const { canonical } = require('../src/util');

describe('attestation ledger', () => {
  const build = () => {
    const ledger = new Ledger(Signer.fromEnv());
    ['a', 'b', 'c'].forEach((v) => ledger.append({ verdict: v }));
    return ledger;
  };

  test('a fresh chain verifies', () => {
    expect(build().verifyChain()).toMatchObject({ ok: true, length: 3 });
  });

  test('editing a past verdict is detected', () => {
    const ledger = build();
    ledger.entries[1].statement.verdict = 'VERIFIED';
    expect(ledger.verifyChain()).toMatchObject({ ok: false, brokenAt: 1 });
  });

  test('re-hashing a forged entry still fails without the signing key', () => {
    const ledger = build();
    const forged = ledger.entries[1];
    forged.statement.verdict = 'VERIFIED';
    forged.hash = crypto.createHash('sha256').update(canonical({ index: 1, prevHash: forged.prevHash, statement: forged.statement })).digest('hex');
    expect(ledger.verifyEntry(forged)).toEqual({ hashOk: true, signatureOk: false });
    expect(ledger.verifyChain().ok).toBe(false);
  });

  test('removing an entry breaks the links after it', () => {
    const ledger = build();
    ledger.entries.splice(1, 1);
    expect(ledger.verifyChain()).toMatchObject({ ok: false, brokenAt: 2 });
  });

  test('signatures verify against the exported public key only', () => {
    const ledger = build();
    const other = Signer.fromEnv();
    expect(ledger.verifyEntry(ledger.entries[0], ledger.signer.publicKeyPem()).signatureOk).toBe(true);
    expect(ledger.verifyEntry(ledger.entries[0], other.publicKeyPem()).signatureOk).toBe(false);
  });

  test('loads a persistent Ed25519 key and rejects other key types', () => {
    const ed = crypto.generateKeyPairSync('ed25519').privateKey.export({ type: 'pkcs8', format: 'pem' });
    const a = Signer.fromEnv(ed);
    expect(a.ephemeral).toBe(false);
    expect(Signer.fromEnv(ed).keyId).toBe(a.keyId);

    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
    expect(() => Signer.fromEnv(rsa)).toThrow(/Ed25519/);
  });

  test('canonical JSON ignores key order', () => {
    expect(canonical({ b: 1, a: [{ d: 1, c: 2 }] })).toBe(canonical({ a: [{ c: 2, d: 1 }], b: 1 }));
  });
});
