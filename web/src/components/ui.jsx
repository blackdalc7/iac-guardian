import React from 'react';

export const VERDICTS = {
  VERIFIED: { label: 'Verified fix', tone: 'cyan' },
  CLEAN: { label: 'Compliant', tone: 'cyan' },
  REJECTED: { label: 'Fix rejected', tone: 'crimson' },
  ERROR: { label: 'Error', tone: 'crimson' },
};

const TONES = {
  cyan: 'border-cyan/30 bg-cyan/[0.08] text-cyan',
  amethyst: 'border-amethyst/30 bg-amethyst/[0.08] text-amethyst',
  crimson: 'border-crimson/40 bg-crimson/[0.1] text-crimson',
  neutral: 'border-white/10 bg-white/[0.04] text-zinc-400',
};

export function Pill({ tone = 'neutral', children, ...rest }) {
  return (
    <span
      className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${TONES[tone]}`}
      {...rest}
    >
      {children}
    </span>
  );
}

export function VerdictPill({ audit }) {
  if (audit.status !== 'done') {
    return (
      <Pill>
        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-cyan" />
        Analysing
      </Pill>
    );
  }
  const v = VERDICTS[audit.verdict];
  return <Pill tone={v.tone}>{v.label}</Pill>;
}

const SEVERITY = {
  critical: 'text-crimson',
  high: 'text-orange-300',
  medium: 'text-amber-200',
  low: 'text-zinc-400',
};

export function Severity({ level }) {
  return (
    <span className={`inline-flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-wider ${SEVERITY[level]}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {level}
    </span>
  );
}

export function Panel({ title, aside, children, className = '', ...rest }) {
  return (
    <section className={`glass p-5 ${className}`} {...rest}>
      {(title || aside) && (
        <header className="mb-4 flex items-center justify-between gap-4">
          <h2 className="label">{title}</h2>
          {aside}
        </header>
      )}
      {children}
    </section>
  );
}

export const short = (hex, n = 12) => (hex ? `${hex.slice(0, n)}…` : '');

export function ShieldIcon({ className = '' }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={className} aria-hidden="true">
      <path d="M12 3l7 2.8v5.4c0 4.3-2.9 8.2-7 9.8-4.1-1.6-7-5.5-7-9.8V5.800z" strokeLinejoin="round" />
      <path d="M8.800 12.200l2.300 2.300 4.300-4.600" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

export function AlertIcon({ className = '' }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className={className} aria-hidden="true">
      <path d="M12 3l7 2.8v5.4c0 4.3-2.9 8.2-7 9.8-4.1-1.6-7-5.5-7-9.8V5.800z" strokeLinejoin="round" />
      <path d="M12 8.500v4.200M12 15.600v.1" strokeLinecap="round" />
    </svg>
  );
}
