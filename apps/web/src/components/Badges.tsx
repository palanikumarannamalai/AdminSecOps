import type { CollectionStatus, Confidence, ControlStatus, Severity } from '@adminsecops/core';
import type { PriorityTier } from '@adminsecops/schemas';
import {
  COLLECTION_STATUS_LABELS,
  CONFIDENCE_LABELS,
  EFFORT_LABELS,
  SEVERITY_LABELS,
  STATUS_DESCRIPTIONS,
  STATUS_LABELS,
  TIER_LABELS,
} from '../lib/labels';

function statusClass(status: string): string {
  return status.toLowerCase().replace(/_/g, '-');
}

export function StatusBadge({ status }: { status: ControlStatus }) {
  return (
    <span className={`badge badge--status badge--status-${statusClass(status)}`} title={STATUS_DESCRIPTIONS[status]}>
      {STATUS_LABELS[status]}
    </span>
  );
}

/** Severity is always shown as text; the colour and marker only reinforce it. */
export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span className={`badge badge--severity badge--severity-${severity}`}>
      <span className="badge__marker" aria-hidden="true" />
      {SEVERITY_LABELS[severity]}
    </span>
  );
}

export function ConfidenceBadge({ confidence }: { confidence: Confidence }) {
  return <span className={`badge badge--neutral badge--confidence-${confidence}`}>{CONFIDENCE_LABELS[confidence]}</span>;
}

export function TierBadge({ tier }: { tier: PriorityTier }) {
  return <span className={`badge badge--tier badge--tier-${tier}`}>{TIER_LABELS[tier]}</span>;
}

export function EffortBadge({ effort }: { effort: 'low' | 'medium' | 'high' }) {
  return <span className="badge badge--neutral">{EFFORT_LABELS[effort]}</span>;
}

export function IntegrityBadge({ verified }: { verified: boolean }) {
  return verified ? (
    <span className="badge badge--integrity-ok">Integrity verified</span>
  ) : (
    <span className="badge badge--integrity-failed">Integrity not verified</span>
  );
}

const COLLECTION_TONE: Record<CollectionStatus, string> = {
  Success: 'ok',
  Partial: 'warn',
  Failed: 'bad',
  Unauthorized: 'bad',
  NotCollected: 'muted',
  NotApplicable: 'muted',
};

export function CollectionStatusBadge({ status }: { status: CollectionStatus | null }) {
  if (status === null) return <span className="badge badge--tone-muted">Unknown</span>;
  return <span className={`badge badge--tone-${COLLECTION_TONE[status]}`}>{COLLECTION_STATUS_LABELS[status]}</span>;
}

export type Tone = 'ok' | 'warn' | 'bad' | 'muted' | 'info';

export function ToneBadge({ tone, children }: { tone: Tone; children: string }) {
  return <span className={`badge badge--tone-${tone}`}>{children}</span>;
}
