import React, { useCallback, useEffect, useState } from 'react';
import { api } from './api.js';
import Report from './components/Report.jsx';
import Sidebar from './components/Sidebar.jsx';
import { Pill, ShieldIcon, short } from './components/ui.jsx';

const POLL_MS = 1500;

function Header({ meta }) {
  return (
    <header className="flex flex-wrap items-center justify-between gap-4">
      <div className="flex items-center gap-3">
        <div className="rounded-xl border border-cyan/30 bg-cyan/10 p-2 text-cyan">
          <ShieldIcon className="h-5 w-5" />
        </div>
        <div>
          <p className="text-[15px] font-semibold tracking-tight text-white">IaC Guardian</p>
          <p className="text-[12px] text-zinc-500">CI/CD Security Audit</p>
        </div>
      </div>
      {meta && (
        <div className="flex flex-wrap items-center gap-2">
          <Pill tone="amethyst" title={meta.policy.sha256} data-testid="policy-digest">
            <span className="font-mono">policy {short(meta.policy.sha256, 10)}</span>
          </Pill>
          <Pill>
            <span className="font-mono">key {meta.attestation.keyId}</span>
          </Pill>
          <Pill>{meta.githubMode === 'live' ? 'GitHub live' : 'GitHub dry run'}</Pill>
        </div>
      )}
    </header>
  );
}

function EmptyState({ demo }) {
  return (
    <div className="glass flex h-72 flex-col items-center justify-center px-6 text-center" data-testid="empty-state">
      <ShieldIcon className="h-9 w-9 text-zinc-700" />
      <p className="mt-4 text-[15px] font-medium text-zinc-200">No pull request selected</p>
      <p className="mt-1.5 max-w-sm text-[13px] leading-relaxed text-zinc-500">
        {demo
          ? 'Pick a scenario on the left to send a simulated pull request through the pipeline.'
          : 'Point a GitHub pull_request webhook at /webhook to start auditing changes.'}
      </p>
    </div>
  );
}

export default function App() {
  const [meta, setMeta] = useState(null);
  const [audits, setAudits] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [audit, setAudit] = useState(null);
  const [busy, setBusy] = useState(false);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    api.meta().then(setMeta).catch(() => setOffline(true));
  }, []);

  // Poll the list; the server is the single source of truth for verdicts.
  useEffect(() => {
    let cancelled = false;
    const tick = async () => {
      try {
        const next = await api.audits();
        if (!cancelled) {
          setAudits(next);
          setOffline(false);
        }
      } catch {
        if (!cancelled) setOffline(true);
      }
    };
    tick();
    const timer = setInterval(tick, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, []);

  // Load the selected report, re-fetching until its analysis has finished.
  const selectedStatus = audits.find((a) => a.id === selectedId)?.status;
  useEffect(() => {
    if (!selectedId) return undefined;
    let cancelled = false;
    api
      .audit(selectedId)
      .then((next) => !cancelled && setAudit(next))
      .catch(() => !cancelled && setAudit(null));
    return () => {
      cancelled = true;
    };
  }, [selectedId, selectedStatus]);

  const simulate = useCallback(async (scenario) => {
    setBusy(true);
    try {
      const { auditId } = await api.simulate(scenario);
      setAudits(await api.audits());
      setSelectedId(auditId);
    } catch {
      setOffline(true);
    } finally {
      setBusy(false);
    }
  }, []);

  const current = audit && audit.id === selectedId ? audit : null;

  return (
    <div className="mx-auto max-w-[1500px] px-6 py-6">
      <Header meta={meta} />
      {offline && (
        <p className="mt-4 rounded-xl border border-crimson/40 bg-crimson/10 px-4 py-2 text-[13px] text-crimson" role="alert">
          Cannot reach the Guardian API. Retrying…
        </p>
      )}
      <div className="mt-6 grid gap-5 lg:grid-cols-[300px_minmax(0,1fr)]">
        <Sidebar meta={meta} audits={audits} selectedId={selectedId} onSelect={setSelectedId} onSimulate={simulate} busy={busy} />
        <main>{current && meta ? <Report audit={current} meta={meta} /> : <EmptyState demo={meta?.demo} />}</main>
      </div>
    </div>
  );
}
