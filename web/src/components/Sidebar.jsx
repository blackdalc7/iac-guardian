import React from 'react';
import { VerdictPill } from './ui.jsx';

function Scenarios({ scenarios, onSimulate, busy }) {
  return (
    <div className="glass p-4" data-testid="scenarios">
      <h2 className="label mb-3">Simulate a pull request</h2>
      <ul className="space-y-1.5">
        {scenarios.map((s) => (
          <li key={s.id}>
            <button
              type="button"
              disabled={busy}
              onClick={() => onSimulate(s.id)}
              title={s.description}
              data-testid={`simulate-${s.id}`}
              className="group flex w-full items-center justify-between rounded-lg border border-transparent px-3 py-2 text-left text-[13px] text-zinc-300 transition hover:border-cyan/30 hover:bg-cyan/[0.06] hover:text-white disabled:opacity-40"
            >
              {s.label}
              <span className="font-mono text-[11px] text-zinc-600 transition group-hover:text-cyan">run</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

export default function Sidebar({ meta, audits, selectedId, onSelect, onSimulate, busy }) {
  return (
    <aside className="flex flex-col gap-4">
      {meta?.demo && <Scenarios scenarios={meta.scenarios} onSimulate={onSimulate} busy={busy} />}

      <div className="glass flex min-h-0 flex-col p-2">
        <h2 className="label px-3 pb-2 pt-3">Audited pull requests</h2>
        {audits.length === 0 ? (
          <p className="px-3 pb-4 pt-1 text-[13px] leading-relaxed text-zinc-500">
            Nothing yet. Reports appear here as soon as a <span className="font-mono text-zinc-400">pull_request</span> webhook
            arrives.
          </p>
        ) : (
          <ul className="space-y-1" data-testid="audit-list">
            {audits.map((a) => (
              <li key={a.id}>
                <button
                  type="button"
                  onClick={() => onSelect(a.id)}
                  aria-current={a.id === selectedId}
                  data-testid="audit-item"
                  className={`w-full rounded-xl border px-3 py-3 text-left transition ${
                    a.id === selectedId ? 'border-cyan/30 bg-cyan/[0.05]' : 'border-transparent hover:bg-white/[0.04]'
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-[11px] text-zinc-500">
                      {a.repo} #{a.pr.number}
                    </span>
                    <VerdictPill audit={a} />
                  </div>
                  <p className="mt-1.5 truncate text-[13px] text-zinc-200">{a.pr.title}</p>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </aside>
  );
}
