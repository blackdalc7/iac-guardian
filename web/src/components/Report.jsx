import React, { useEffect, useState } from 'react';
import Attestation from './Attestation.jsx';
import DiffView from './DiffView.jsx';
import Findings from './Findings.jsx';
import OpaBadge from './OpaBadge.jsx';
import Pipeline from './Pipeline.jsx';
import { Panel, Pill, short } from './ui.jsx';

function GitHubOutcome({ audit }) {
  const { github } = audit;
  return (
    <Panel title="Reported to GitHub" aside={<Pill>{github.mode === 'live' ? 'Live' : 'Dry run'}</Pill>}>
      <dl className="space-y-3 text-[13px]">
        <div>
          <dt className="label">Commit status</dt>
          <dd className="mt-1 text-zinc-300">
            <span className={`font-mono text-[12px] ${github.status?.state === 'success' ? 'text-cyan' : 'text-crimson'}`}>
              {github.status?.state}
            </span>{' '}
            · {github.status?.description}
          </dd>
        </div>
        {github.fixPullRequest && (
          <div>
            <dt className="label">Fix branch</dt>
            <dd className="mt-1 break-all font-mono text-[12px] text-zinc-300" data-testid="fix-branch">
              {github.fixPullRequest.branch} → {audit.pr.headRef}
            </dd>
          </div>
        )}
        {github.error && <p className="text-[12px] text-crimson">{github.error}</p>}
      </dl>
    </Panel>
  );
}

export default function Report({ audit, meta }) {
  const [attemptNo, setAttemptNo] = useState(null);

  // Default to the accepted attempt, or the last one tried.
  useEffect(() => {
    setAttemptNo(audit.acceptedAttempt ?? audit.attempts.at(-1)?.n ?? null);
  }, [audit.id, audit.status]);

  if (audit.status !== 'done') {
    return (
      <div className="glass flex h-64 items-center justify-center text-[13px] text-zinc-500" data-testid="report-pending">
        <span className="mr-3 h-2 w-2 animate-pulse rounded-full bg-cyan" />
        Running the remediation loop…
      </div>
    );
  }

  const attempt = audit.attempts.find((a) => a.n === attemptNo);

  return (
    <article className="space-y-4" data-testid="report" data-audit-id={audit.id}>
      <header className="px-1">
        <p className="font-mono text-[12px] text-zinc-500">
          {audit.repo} #{audit.pr.number} · {audit.pr.headRef} → {audit.pr.baseRef} · {short(audit.pr.headSha, 7)} · @{audit.pr.author}
        </p>
        <h1 className="mt-1.5 text-2xl font-semibold tracking-tight text-white">{audit.pr.title}</h1>
      </header>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <OpaBadge audit={audit} policy={meta.policy} />
        <Attestation audit={audit} signer={meta.attestation} />
      </div>

      <div className="grid gap-4 xl:grid-cols-[minmax(0,1.5fr)_minmax(0,1fr)]">
        <Pipeline audit={audit} selected={attemptNo} onSelect={setAttemptNo} />
        <GitHubOutcome audit={audit} />
      </div>

      <Findings audit={audit} />
      <DiffView attempt={attempt} />
    </article>
  );
}
