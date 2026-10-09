import React, { useState } from 'react';
import type { ApprovalRequest, ApprovalActionType, ApprovalRiskLevel, ApprovalStatus } from '../../types/soc';
import {
  ShieldCheck,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Lock,
  Server,
} from 'lucide-react';
import { StatusBadge } from './StatusBadge';
import { Button } from './Button';
import { cn } from '../../lib/utils';

export interface ApprovalCardData {
  id: string;
  action_type: ApprovalActionType | string;
  actionType?: ApprovalActionType | string;
  recommended_action?: string;
  recommendedAction?: string;
  risk_level: ApprovalRiskLevel | string;
  riskLevel?: ApprovalRiskLevel | string;
  target_host?: string;
  targetHost?: string;
  target?: string;
  justification?: string;
  trust_score?: number;
  trustScore?: number;
  trust_verdict?: string;
  trustVerdict?: string;
  status: ApprovalStatus | string;
  requires_override?: boolean;
  requiresOverride?: boolean;
  requested_by?: string;
  requestedBy?: string;
  requested_at?: string;
  requestedAt?: string;
}

export interface ApprovalCardProps {
  approval: ApprovalCardData | ApprovalRequest | any;
  onApprove?: (id: string, notes?: string) => void;
  onReject?: (id: string, reason?: string) => void;
  isSubmitting?: boolean;
  compact?: boolean;
  className?: string;
}

export const ApprovalCard: React.FC<ApprovalCardProps> = ({
  approval,
  onApprove,
  onReject,
  isSubmitting = false,
  compact = false,
  className,
}) => {
  const [decisionNotes, setDecisionNotes] = useState<string>('');
  const [showNotesInput, setShowNotesInput] = useState<boolean>(false);

  const id = approval.id || 'REQ-000';
  const actionType = approval.action_type || approval.actionType || 'CONTAINMENT_ACTION';
  const recommendedAction = approval.recommended_action || approval.recommendedAction || actionType.replace(/_/g, ' ');
  const riskLevel = (approval.risk_level || approval.riskLevel || 'MEDIUM').toUpperCase();
  const status = (approval.status || 'PENDING').toUpperCase();
  const targetHost = approval.target_host || approval.targetHost || approval.target;
  const justification = approval.justification || 'High-risk containment action requested by autonomous multi-agent pipeline.';
  const trustScore = approval.trust_score ?? approval.trustScore ?? 85;
  const requiresOverride = approval.requires_override ?? approval.requiresOverride ?? (trustScore < 85);
  const requestedBy = approval.requested_by || approval.requestedBy || 'Lead Investigator Agent';
  const requestedAt = approval.requested_at || approval.requestedAt || 'Just now';

  const isPending = status === 'PENDING';

  const getRiskBorder = () => {
    switch (riskLevel) {
      case 'CRITICAL':
        return 'border-rose-800/80 bg-rose-950/15';
      case 'HIGH':
        return 'border-orange-800/80 bg-orange-950/15';
      case 'MEDIUM':
        return 'border-amber-800/80 bg-amber-950/15';
      case 'LOW':
      default:
        return 'border-slate-800 bg-slate-900/30';
    }
  };

  if (compact) {
    return (
      <div
        className={cn(
          'p-3 rounded-lg border font-mono text-xs flex items-center justify-between gap-3 transition-all',
          getRiskBorder(),
          className
        )}
      >
        <div className="flex items-center gap-2 truncate">
          <StatusBadge status={riskLevel} size="xs" />
          <span className="font-bold text-slate-200 truncate">{recommendedAction}</span>
          {targetHost && <span className="text-[10px] text-slate-400 font-mono">({targetHost})</span>}
        </div>
        <StatusBadge status={status} size="xs" />
      </div>
    );
  }

  return (
    <div
      className={cn(
        'rounded-xl border p-4 sm:p-5 font-mono text-xs shadow-xl transition-all flex flex-col justify-between gap-3.5',
        getRiskBorder(),
        className
      )}
    >
      {/* Top Banner */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-amber-950/80 border border-amber-700/60 text-amber-400">
            <Lock className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wide text-amber-300">
                {actionType.replace(/_/g, ' ')}
              </span>
              <span className="text-[10px] text-slate-500 font-mono">
                {id}
              </span>
            </div>
            <span className="text-[11px] text-slate-400 block mt-0.5">
              Requested by {requestedBy} • {requestedAt}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 self-start sm:self-auto">
          <StatusBadge status={riskLevel} size="sm" pulse={riskLevel === 'CRITICAL'} />
          <StatusBadge status={status} size="sm" />
        </div>
      </div>

      {/* Recommended Action & Justification */}
      <div className="space-y-2">
        <div className="flex items-center gap-2 text-slate-200 font-bold text-sm">
          <span>{recommendedAction}</span>
          {targetHost && (
            <span className="text-xs font-normal text-cyan-400 bg-cyan-950/60 border border-cyan-800/60 px-2 py-0.5 rounded flex items-center gap-1">
              <Server className="w-3 h-3" />
              {targetHost}
            </span>
          )}
        </div>

        <p className="text-slate-300 text-[11px] leading-relaxed bg-[#080C14]/60 p-3 rounded-lg border border-slate-900">
          {justification}
        </p>
      </div>

      {/* Trust Score Gate Check */}
      <div className="flex items-center justify-between p-2.5 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px]">
        <div className="flex items-center gap-2">
          {trustScore >= 85 ? (
            <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0" />
          ) : (
            <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />
          )}
          <span className="text-slate-300">
            Evidence Trust Score Gate: <strong className="text-white font-mono">{trustScore}/100</strong>
          </span>
        </div>

        {requiresOverride ? (
          <span className="text-[10px] font-bold text-amber-400 uppercase tracking-wide bg-amber-950/60 border border-amber-800/80 px-2 py-0.5 rounded">
            Safety Override Required
          </span>
        ) : (
          <span className="text-[10px] font-bold text-emerald-400 uppercase tracking-wide bg-emerald-950/60 border border-emerald-800/80 px-2 py-0.5 rounded">
            Automated Gate Cleared
          </span>
        )}
      </div>

      {/* Actions (if Pending) */}
      {isPending && (onApprove || onReject) && (
        <div className="pt-2 border-t border-slate-800/80 space-y-2">
          {showNotesInput && (
            <input
              type="text"
              value={decisionNotes}
              onChange={(e) => setDecisionNotes(e.target.value)}
              placeholder="Optional analyst justification or override notes..."
              className="w-full px-3 py-1.5 bg-slate-900 border border-slate-700 rounded-md text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
            />
          )}

          <div className="flex items-center justify-between gap-3">
            <button
              onClick={() => setShowNotesInput(!showNotesInput)}
              className="text-[11px] text-slate-400 hover:text-slate-200 underline transition-colors"
            >
              {showNotesInput ? 'Hide Notes' : '+ Add Decision Notes'}
            </button>

            <div className="flex items-center gap-2">
              {onReject && (
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => onReject(id, decisionNotes)}
                  disabled={isSubmitting}
                  className="h-8 text-xs font-mono border-rose-800/70 text-rose-300 hover:bg-rose-950/60 gap-1.5"
                >
                  <XCircle className="w-3.5 h-3.5" />
                  <span>Reject</span>
                </Button>
              )}

              {onApprove && (
                <Button
                  size="sm"
                  onClick={() => onApprove(id, decisionNotes)}
                  disabled={isSubmitting}
                  className="h-8 text-xs font-mono bg-emerald-600 hover:bg-emerald-500 text-white font-bold gap-1.5 shadow-md shadow-emerald-950"
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Approve Containment</span>
                </Button>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
