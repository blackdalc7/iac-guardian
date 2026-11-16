import React from 'react';
import { Panel } from './ui.jsx';

const GATES = [
  ['schema', 'Schema'],
  ['syntax', 'Syntax'],
  ['scope', 'Scope'],
  ['policy', 'OPA policy'],
];

function Gate({ label, gate }) {
  const state = !gate ? 'skipped' : gate.pass ? 'pass' : 'fail';
  const styles = {
    pass: 'border-cyan/25 bg-cyan/[0.06] text-cyan',
    fail: 'border-crimson/40 bg-crimson/[0.1] text-crimson',
    skipped: 'border-white/[0.06] text-zinc-600',
  };
  return (
    <span data-gate-state={state} className={`rounded-md border px-2 py-1 font-mono text-[11px] ${styles[state]}`}>
      {state === 'pass' ? '✓' : state === 'fail' ? '✕' : '·'} {label}
    </span>
  );
}

// One row per model attempt. Shows which deterministic gate stopped a patch
// and why, which is also exactly what was fed back to the model.
export default function Pipeline({ audit, selected, onSelect }) {
  if (audit.attempts.length === 0) {
    return (
      <Panel title="Remediation loop">
        <p className="text-[13px] text-zinc-500">
          {audit.verdict === 'CLEAN' ? 'No violations, so no patch was requested from the model.' : 'The pipeline stopped before requesting a patch.'}
        </p>
      </Panel>
    );
  }

  return (
    <Panel title="Remediation loop" aside={<span className="font-mono text-[11px] text-zinc-600">{audit.attempts[0].model}</span>}>
      <ol className="space-y-2" data-testid="attempts">
        {audit.attempts.map((attempt) => {
          const byName = Object.fromEntries(attempt.gates.map((g) => [g.name, g]));
          const failures = attempt.gates.filter((g) => !g.pass);
          const active = attempt.n === selected;
          return (
            <li key={attempt.n}>
              <button
                type="button"
                onClick={() => onSelect(attempt.n)}
                data-testid={`attempt-${attempt.n}`}
                data-accepted={attempt.accepted}
                className={`w-full rounded-xl border p-3 text-left transition ${
                  active ? 'border-white/20 bg-white/[0.04]' : 'border-white/[0.06] hover:border-white/15'
                }`}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <span className="mr-2 text-[13px] font-medium text-zinc-200">Attempt {attempt.n}</span>
                  {GATES.map(([name, label]) => (
                    <Gate key={name} label={label} gate={byName[name]} />
                  ))}
                  <span className={`ml-auto text-[11px] font-medium ${attempt.accepted ? 'text-cyan' : 'text-crimson'}`}>
                    {attempt.accepted ? 'Accepted' : 'Rejected'}
                  </span>
                </div>
                {failures.length > 0 && (
                  <ul className="mt-3 space-y-1 border-l border-crimson/40 pl-3">
                    {failures.flatMap((g) =>
                      g.details.map((detail) => (
                        <li key={`${g.name}-${detail}`} className="font-mono text-[11px] leading-relaxed text-zinc-400">
                          <span className="text-crimson">{g.name}</span> {detail}
                        </li>
                      )),
                    )}
                  </ul>
                )}
              </button>
            </li>
          );
        })}
      </ol>
    </Panel>
  );
}
