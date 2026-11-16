import React from 'react';
import { Panel, Pill } from './ui.jsx';

// Expands a hunk into rows carrying both line numbers, so the gutter can show
// where a line sat before and after the patch.
function rows(hunk) {
  let oldNo = hunk.oldStart;
  let newNo = hunk.newStart;
  return hunk.lines
    .filter((line) => !line.startsWith('\\'))
    .map((line) => {
      const sign = line[0];
      const row = { sign, text: line.slice(1), oldNo: sign === '+' ? '' : oldNo, newNo: sign === '-' ? '' : newNo };
      if (sign !== '+') oldNo += 1;
      if (sign !== '-') newNo += 1;
      return row;
    });
}

const ROW = {
  '+': 'bg-cyan/[0.07] text-cyan',
  '-': 'bg-crimson/[0.09] text-crimson',
  ' ': 'text-zinc-400',
};

function FileDiff({ file }) {
  return (
    <div className="overflow-hidden rounded-xl border border-white/[0.08] bg-charcoal/80" data-testid="diff-file">
      <div className="flex items-center justify-between border-b border-white/[0.08] px-4 py-2.5">
        <span className="font-mono text-[12px] text-zinc-200">{file.path}</span>
        <span className="font-mono text-[11px]">
          <span className="text-cyan">+{file.additions}</span> <span className="text-crimson">−{file.deletions}</span>
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse font-mono text-[12px] leading-[1.65]">
          <tbody>
            {file.hunks.map((hunk) => (
              <React.Fragment key={`${hunk.oldStart}-${hunk.newStart}`}>
                <tr className="bg-white/[0.03] text-zinc-600">
                  <td colSpan={4} className="px-4 py-1">
                    @@ −{hunk.oldStart},{hunk.oldLines} +{hunk.newStart},{hunk.newLines} @@
                  </td>
                </tr>
                {rows(hunk).map((row, i) => (
                  // eslint-disable-next-line react/no-array-index-key
                  <tr key={i} className={ROW[row.sign]} data-diff-sign={row.sign}>
                    <td className="w-12 select-none px-2 text-right text-zinc-600">{row.oldNo}</td>
                    <td className="w-12 select-none px-2 text-right text-zinc-600">{row.newNo}</td>
                    <td className="w-5 select-none text-center">{row.sign === ' ' ? '' : row.sign === '-' ? '−' : '+'}</td>
                    <td className="whitespace-pre pr-6">{row.text || ' '}</td>
                  </tr>
                ))}
              </React.Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function DiffView({ attempt }) {
  if (!attempt) return null;
  return (
    <Panel
      title={`Unified diff · attempt ${attempt.n}`}
      data-testid="diff"
      aside={
        <Pill tone={attempt.accepted ? 'cyan' : 'crimson'} data-testid="diff-status">
          {attempt.accepted ? 'Accepted patch' : 'Rejected proposal, not applied'}
        </Pill>
      }
    >
      {attempt.diff.length === 0 ? (
        <p className="text-[13px] text-zinc-500">The model returned no changes on this attempt.</p>
      ) : (
        <div className="space-y-4">
          {attempt.diff.map((file) => (
            <FileDiff key={file.path} file={file} />
          ))}
        </div>
      )}
    </Panel>
  );
}
