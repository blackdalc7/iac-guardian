import React from 'react';
import { Panel, Severity } from './ui.jsx';

function Detection({ attempt }) {
  if (attempt === 1) return <span className="text-zinc-400">Model, first pass</span>;
  if (attempt) return <span className="text-amethyst">After policy feedback</span>;
  return <span className="text-crimson">Policy only</span>;
}

export default function Findings({ audit }) {
  if (audit.baseline.length === 0) return null;
  return (
    <Panel title={`Policy violations · ${audit.baseline.length}`}>
      <div className="overflow-x-auto">
        <table className="w-full text-left text-[13px]" data-testid="findings">
          <thead>
            <tr className="label border-b border-white/[0.06]">
              <th className="pb-2 pr-4 font-medium">Rule</th>
              <th className="pb-2 pr-4 font-medium">Severity</th>
              <th className="pb-2 pr-4 font-medium">Resource</th>
              <th className="pb-2 pr-4 font-medium">Finding</th>
              <th className="pb-2 font-medium">Detected by</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.04]">
            {audit.baseline.map((v) => (
              <tr key={`${v.id}-${v.resource}-${v.msg}`} className="align-top">
                <td className="py-2.5 pr-4 font-mono text-[12px] text-zinc-200">{v.id}</td>
                <td className="py-2.5 pr-4">
                  <Severity level={v.severity} />
                </td>
                <td className="py-2.5 pr-4 font-mono text-[12px] text-zinc-400">{v.resource}</td>
                <td className="py-2.5 pr-4 text-zinc-300" title={v.msg}>
                  {v.title}
                </td>
                <td className="whitespace-nowrap py-2.5 text-[12px]">
                  <Detection attempt={v.detectedByAi} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
