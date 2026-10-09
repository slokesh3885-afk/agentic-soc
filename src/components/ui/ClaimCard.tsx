import React from 'react';
import type { ClaimStatus } from '../../types/soc';
import {
  FileCheck2,
  AlertTriangle,
  Link2,
  ExternalLink,
} from 'lucide-react';
import { StatusBadge } from './StatusBadge';
import { cn } from '../../lib/utils';

export interface ClaimData {
  id?: string;
  claim_id?: string;
  claim: string;
  status: ClaimStatus | string;
  evidence_ids?: string[];
  evidenceIds?: string[];
  valid_evidence_ids?: string[];
  reason?: string;
  confidence?: number;
  critic_notes?: string;
}

export interface ClaimCardProps {
  claim: ClaimData;
  onEvidenceClick?: (evidenceId: string) => void;
  compact?: boolean;
  className?: string;
}

export const ClaimCard: React.FC<ClaimCardProps> = ({
  claim,
  onEvidenceClick,
  compact = false,
  className,
}) => {
  const claimId = claim.claim_id || claim.id || 'CLM-000';
  const claimText = claim.claim || 'Unspecified assertion';
  const statusStr = claim.status || 'UNCERTAIN';
  const evidenceIds = claim.evidence_ids || claim.evidenceIds || [];
  const reasonText = claim.reason || claim.critic_notes;

  const getBorderColor = () => {
    switch (statusStr.toUpperCase()) {
      case 'SUPPORTED':
        return 'border-emerald-900/60 hover:border-emerald-700/80 bg-emerald-950/10';
      case 'CONTRADICTED':
        return 'border-rose-900/70 hover:border-rose-700/80 bg-rose-950/15';
      case 'UNSUPPORTED':
        return 'border-amber-900/60 hover:border-amber-700/80 bg-amber-950/10';
      case 'UNCERTAIN':
      default:
        return 'border-slate-800 hover:border-slate-700 bg-slate-900/30';
    }
  };

  if (compact) {
    return (
      <div
        className={cn(
          'p-2.5 rounded-lg border font-mono text-xs flex items-center justify-between gap-3 transition-all',
          getBorderColor(),
          className
        )}
      >
        <div className="flex items-center gap-2 truncate">
          <span className="font-bold text-cyan-400 text-[11px] shrink-0">{claimId}</span>
          <span className="text-slate-200 truncate">{claimText}</span>
        </div>
        <StatusBadge status={statusStr} size="xs" />
      </div>
    );
  }

  return (
    <div
      className={cn(
        'rounded-xl border p-4 font-mono text-xs shadow-md transition-all flex flex-col justify-between gap-3',
        getBorderColor(),
        className
      )}
    >
      {/* Header Bar */}
      <div className="flex items-center justify-between gap-2 pb-2.5 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <div className="p-1 rounded bg-slate-900 border border-slate-800 text-cyan-400">
            <FileCheck2 className="w-3.5 h-3.5" />
          </div>
          <span className="font-bold text-cyan-400 text-xs tracking-wide">
            {claimId}
          </span>
          <span className="text-[10px] text-slate-500">Hypothesis Assertion</span>
        </div>

        <StatusBadge status={statusStr} size="sm" />
      </div>

      {/* Claim Assertion Statement */}
      <div className="space-y-1">
        <p className="text-slate-200 font-medium text-xs leading-relaxed">
          {claimText}
        </p>
      </div>

      {/* Linked Evidence Citations */}
      {evidenceIds.length > 0 ? (
        <div className="pt-2 border-t border-slate-800/70 space-y-1.5">
          <div className="flex items-center justify-between text-[10px] text-slate-400">
            <span className="flex items-center gap-1 font-semibold text-slate-300">
              <Link2 className="w-3 h-3 text-cyan-400" />
              Evidence Citations ({evidenceIds.length})
            </span>
            <span className="text-slate-500">Verified Telemetry</span>
          </div>

          <div className="flex flex-wrap gap-1.5">
            {evidenceIds.map((evId) => (
              <button
                key={evId}
                onClick={() => onEvidenceClick && onEvidenceClick(evId)}
                className={cn(
                  'px-2 py-0.5 rounded text-[10px] font-mono border transition-all flex items-center gap-1',
                  onEvidenceClick
                    ? 'bg-cyan-950/60 border-cyan-800/60 text-cyan-300 hover:bg-cyan-900/80 hover:border-cyan-600 cursor-pointer'
                    : 'bg-slate-900 border-slate-800 text-slate-300'
                )}
                title={`Citation: ${evId}`}
              >
                <span>{evId}</span>
                {onEvidenceClick && <ExternalLink className="w-2.5 h-2.5 opacity-60" />}
              </button>
            ))}
          </div>
        </div>
      ) : (
        <div className="pt-1 text-[10px] text-amber-400/90 flex items-center gap-1.5">
          <AlertTriangle className="w-3 h-3 text-amber-400 shrink-0" />
          <span>No evidence citations linked (Uncorroborated Assertion).</span>
        </div>
      )}

      {/* Critic Review Reason or Notes */}
      {reasonText && (
        <div className="p-2 rounded bg-slate-950/80 border border-slate-800/80 text-[11px] text-slate-400 space-y-0.5">
          <span className="text-[10px] font-bold text-slate-300 block uppercase tracking-wider">
            Evaluation Note:
          </span>
          <p className="leading-snug">{reasonText}</p>
        </div>
      )}
    </div>
  );
};
