import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { Panel, Pill, short } from './ui.jsx';

function Check({ ok, children }) {
  return (
    <li className={`flex items-center gap-2 text-[12px] ${ok ? 'text-zinc-300' : 'text-crimson'}`}>
      <span className={`font-mono ${ok ? 'text-amethyst' : 'text-crimson'}`}>{ok ? '✓' : '✕'}</span>
      {children}
    </li>
  );
}

export default function Attestation({ audit, signer }) {
  const [result, setResult] = useState(null);
  const [failed, setFailed] = useState(false);
  const entry = audit.attestation;

  useEffect(() => {
    setResult(null);
    setFailed(false);
  }, [audit.id]);

  async function verify() {
    try {
      setResult(await api.verify(audit.id));
    } catch {
      setFailed(true);
    }
  }

  const verified = result && result.entry.hashOk && result.entry.signatureOk && result.chain.ok;

  return (
    <Panel
      title="Signed attestation"
      data-testid="attestation"
      aside={
        result ? (
          <Pill tone={verified ? 'amethyst' : 'crimson'} data-testid="attestation-result">
            {verified ? 'Signature valid' : 'Verification failed'}
          </Pill>
        ) : (
          <button
            type="button"
            onClick={verify}
            data-testid="verify-attestation"
            className="rounded-full border border-amethyst/40 px-3 py-1 text-[11px] font-medium text-amethyst transition hover:bg-amethyst/10"
          >
            Verify
          </button>
        )
      }
    >
      <dl className="space-y-3">
        <div>
          <dt className="label">Ledger entry #{entry.index}</dt>
          <dd className="hash mt-1 text-amethyst">{entry.hash}</dd>
        </div>
        <div>
          <dt className="label">Previous entry</dt>
          <dd className="hash mt-1 text-zinc-500">{short(entry.prevHash, 32)}</dd>
        </div>
        <div>
          <dt className="label">Ed25519 signature · key {entry.keyId}</dt>
          <dd className="hash mt-1 text-zinc-400">{short(entry.signature, 44)}</dd>
        </div>
      </dl>

      {result && (
        <ul className="mt-4 space-y-1.5 border-t border-white/[0.06] pt-4">
          <Check ok={result.entry.hashOk}>Statement hash matches its contents</Check>
          <Check ok={result.entry.signatureOk}>Signature verifies with the agent key</Check>
          <Check ok={result.chain.ok}>Hash chain intact across {result.chain.length} entries</Check>
        </ul>
      )}
      {failed && <p className="mt-3 text-[12px] text-crimson">Could not reach the verification endpoint.</p>}
      {signer.ephemeral && (
        <p className="mt-4 text-[11px] leading-relaxed text-zinc-600">
          Signed with a key generated at startup. Configure a persistent key to verify entries across restarts.
        </p>
      )}
    </Panel>
  );
}
