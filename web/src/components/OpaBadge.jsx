import React from 'react';
import { AlertIcon, ShieldIcon, short } from './ui.jsx';

const COPY = {
  VERIFIED: (a) => ({
    ok: true,
    heading: 'OPA verified',
    line: `${a.baseline.length} violation${a.baseline.length === 1 ? '' : 's'} before the patch, 0 after`,
  }),
  CLEAN: () => ({ ok: true, heading: 'OPA passed', line: 'No violations in the submitted code' }),
  REJECTED: (a) => ({
    ok: false,
    heading: 'OPA rejected',
    line: `No proposed patch passed all gates in ${a.attempts.length} attempt${a.attempts.length === 1 ? '' : 's'}`,
  }),
  ERROR: (a) => ({ ok: false, heading: 'Not evaluated', line: a.error || 'Analysis failed' }),
};

// The badge reports what the policy engine concluded, not what the model
// claimed. Its numbers come straight from the OPA evaluations in the audit.
export default function OpaBadge({ audit, policy }) {
  const { ok, heading, line } = COPY[audit.verdict](audit);
  const before = audit.baseline.length;
  const after = audit.verdict === 'VERIFIED' || audit.verdict === 'CLEAN' ? 0 : before;

  return (
    <section
      data-testid="opa-badge"
      data-verdict={audit.verdict}
      className={`glass relative overflow-hidden p-5 ${ok ? 'shadow-glow' : 'shadow-glow-crimson'}`}
    >
      <div className="flex items-start gap-4">
        <div className={`rounded-xl border p-2.5 ${ok ? 'border-cyan/30 bg-cyan/10 text-cyan' : 'border-crimson/40 bg-crimson/10 text-crimson'}`}>
          {ok ? <ShieldIcon className="h-7 w-7" /> : <AlertIcon className="h-7 w-7" />}
        </div>
        <div className="min-w-0 flex-1">
          <p className="label">Policy validation</p>
          <h2 className={`mt-1 text-xl font-semibold tracking-tight ${ok ? 'text-white' : 'text-crimson'}`}>{heading}</h2>
          <p className="mt-1 text-[13px] text-zinc-400">{line}</p>
        </div>
        <div className="text-right font-mono" aria-label={`${before} violations before, ${after} after`}>
          <span className={`text-3xl font-medium ${before ? 'text-crimson' : 'text-zinc-600'}`}>{before}</span>
          <span className="mx-2 text-zinc-600">→</span>
          <span className={`text-3xl font-medium ${after ? 'text-crimson' : 'text-cyan'}`} data-testid="violations-after">
            {after}
          </span>
        </div>
      </div>

      <dl className="mt-5 grid grid-cols-3 gap-4 border-t border-white/[0.06] pt-4">
        <div>
          <dt className="label">Engine</dt>
          <dd className="mt-1 font-mono text-[12px] text-zinc-300">opa-wasm · {policy.opaVersion}</dd>
        </div>
        <div>
          <dt className="label">Entrypoint</dt>
          <dd className="mt-1 font-mono text-[12px] text-zinc-300">{policy.entrypoint}</dd>
        </div>
        <div>
          <dt className="label">Policy digest</dt>
          <dd className="mt-1 font-mono text-[12px] text-amethyst" title={policy.sha256}>
            sha256:{short(policy.sha256, 16)}
          </dd>
        </div>
      </dl>
    </section>
  );
}
