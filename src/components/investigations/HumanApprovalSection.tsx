import React, { useState, useEffect } from 'react';
import {
  UserCheck,
  ShieldAlert,
  CheckCircle2,
  XCircle,
  RotateCw,
  Plus,
  ChevronDown,
  ChevronUp,
  Lock,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type {
  ApprovalRequest,
  ApprovalActionType,
  ApprovalRiskLevel,
} from '../../types/soc';
import { cn } from '../../lib/utils';
import { Button } from '../ui/Button';

interface HumanApprovalSectionProps {
  investigationId: string;
}

export const HumanApprovalSection: React.FC<HumanApprovalSectionProps> = ({
  investigationId,
}) => {
  const [approvals, setApprovals] = useState<ApprovalRequest[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  // Form states for creating a new approval request
  const [showCreateForm, setShowCreateForm] = useState<boolean>(false);
  const [newActionType, setNewActionType] = useState<ApprovalActionType>('CASE_CLOSURE');
  const [newActionDesc, setNewActionDesc] = useState<string>('');
  const [newRiskLevel, setNewRiskLevel] = useState<ApprovalRiskLevel>('MEDIUM');

  // Form states for deciding on an approval
  const [selectedApprovalId, setSelectedApprovalId] = useState<string | null>(null);
  const [reviewerName, setReviewerName] = useState<string>('sec_analyst_01');
  const [decisionNotes, setDecisionNotes] = useState<string>('');
  const [overrideJustification, setOverrideJustification] = useState<string>('');
  const [showHistory, setShowHistory] = useState<boolean>(false);

  const fetchApprovals = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await socApi.getInvestigationApprovals(investigationId);
      setApprovals(data);
      const pending = data.find((a) => a.status === 'PENDING');
      if (pending) {
        setSelectedApprovalId(pending.id);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to load approval requests');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchApprovals();
  }, [investigationId]);

  const handleCreateRequest = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newActionDesc.trim()) return;
    setIsSubmitting(true);
    setError(null);
    setSuccessMsg(null);
    try {
      await socApi.createApprovalRequest(investigationId, {
        action_type: newActionType,
        recommended_action: newActionDesc.trim(),
        risk_level: newRiskLevel,
        requested_by: 'Analyst Console',
      });
      setNewActionDesc('');
      setShowCreateForm(false);
      setSuccessMsg('Approval request created successfully.');
      await fetchApprovals();
    } catch (err: any) {
      setError(err.message || 'Failed to create approval request');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleDecision = async (decision: 'APPROVED' | 'REJECTED') => {
    if (!selectedApprovalId) return;
    const targetApproval = approvals.find((a) => a.id === selectedApprovalId);
    if (!targetApproval) return;

    if (!reviewerName.trim()) {
      setError('Please provide reviewer identifier.');
      return;
    }
    if (!decisionNotes.trim() || decisionNotes.trim().length < 5) {
      setError('Please provide decision notes (minimum 5 characters).');
      return;
    }
    const reqOverride = targetApproval.requires_override ?? targetApproval.requiresOverride;
    if (decision === 'APPROVED' && reqOverride) {
      if (!overrideJustification.trim() || overrideJustification.trim().length < 10) {
        setError(
          'This case requires an explicit safety override justification (minimum 10 characters).'
        );
        return;
      }
    }

    setIsSubmitting(true);
    setError(null);
    setSuccessMsg(null);
    try {
      await socApi.submitApprovalDecision(selectedApprovalId, {
        decision,
        reviewer: reviewerName.trim(),
        decision_notes: decisionNotes.trim(),
        override_justification:
          decision === 'APPROVED' && reqOverride
            ? overrideJustification.trim()
            : undefined,
      });
      setSuccessMsg(`Approval ${selectedApprovalId} marked as ${decision}.`);
      setDecisionNotes('');
      setOverrideJustification('');
      await fetchApprovals();
    } catch (err: any) {
      setError(err.message || 'Failed to record decision');
    } finally {
      setIsSubmitting(false);
    }
  };

  const pendingApprovals = approvals.filter((a) => a.status === 'PENDING');
  const finalizedApprovals = approvals.filter((a) => a.status !== 'PENDING');
  const activeApproval =
    approvals.find((a) => a.id === selectedApprovalId) || pendingApprovals[0];

  return (
    <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-slate-800/80 gap-3">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-lg bg-indigo-950/80 border border-indigo-700/60 flex items-center justify-center text-indigo-400">
            <UserCheck className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                Human-in-the-Loop Approval Gates
              </h3>
              <span className="text-[10px] font-mono font-semibold bg-indigo-950 border border-indigo-700/60 text-indigo-300 px-2 py-0.5 rounded-full">
                Module 3J
              </span>
            </div>
            <p className="text-xs text-slate-400">
              Accountable human analyst safety checkpoints for high-impact actions and case closure
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowCreateForm(!showCreateForm)}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-semibold rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 border border-slate-700 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{showCreateForm ? 'Cancel' : 'Request Action'}</span>
          </button>
          <button
            onClick={fetchApprovals}
            disabled={isLoading}
            className="p-1.5 rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
            title="Refresh Approvals"
          >
            <RotateCw className={cn('w-3.5 h-3.5', isLoading && 'animate-spin')} />
          </button>
        </div>
      </div>

      {error && (
        <div className="bg-rose-950/40 border border-rose-800/50 rounded-lg p-3 text-xs text-rose-300">
          <strong>Approval Gate Warning:</strong> {error}
        </div>
      )}

      {successMsg && (
        <div className="bg-emerald-950/40 border border-emerald-800/50 rounded-lg p-3 text-xs text-emerald-300">
          {successMsg}
        </div>
      )}

      {/* Create Approval Request Form Drawer */}
      {showCreateForm && (
        <form
          onSubmit={handleCreateRequest}
          className="p-4 bg-[#0B0F19] border border-slate-800 rounded-lg space-y-3 text-xs animate-in fade-in duration-150"
        >
          <div className="font-semibold text-slate-200">Request New Approval Gate</div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-slate-400 mb-1">Action Type</label>
              <select
                value={newActionType}
                onChange={(e) => setNewActionType(e.target.value as ApprovalActionType)}
                className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-slate-200 font-mono"
              >
                <option value="CASE_CLOSURE">CASE_CLOSURE</option>
                <option value="CONTAINMENT_ISOLATE_HOST">CONTAINMENT_ISOLATE_HOST</option>
                <option value="CONTAINMENT_BLOCK_IP">CONTAINMENT_BLOCK_IP</option>
                <option value="REMEDIAL_ACTION">REMEDIAL_ACTION</option>
                <option value="ESCALATION_TIER2">ESCALATION_TIER2</option>
              </select>
            </div>
            <div>
              <label className="block text-slate-400 mb-1">Risk Level</label>
              <select
                value={newRiskLevel}
                onChange={(e) => setNewRiskLevel(e.target.value as ApprovalRiskLevel)}
                className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-slate-200 font-mono"
              >
                <option value="LOW">LOW</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="HIGH">HIGH</option>
                <option value="CRITICAL">CRITICAL</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-slate-400 mb-1">Recommended Action Description</label>
            <input
              type="text"
              value={newActionDesc}
              onChange={(e) => setNewActionDesc(e.target.value)}
              placeholder="e.g. Isolate host TEST-SRV-FIN-02 from subnet to prevent lateral movement"
              className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-slate-200"
              required
            />
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => setShowCreateForm(false)}
            >
              Cancel
            </Button>
            <Button type="submit" variant="primary" size="sm" disabled={isSubmitting}>
              {isSubmitting ? 'Submitting...' : 'Submit Approval Request'}
            </Button>
          </div>
        </form>
      )}

      {/* Active Pending Approval Decision Card */}
      {activeApproval && activeApproval.status === 'PENDING' ? (
        <div className="bg-[#0B0F19] border border-slate-800 rounded-lg p-4 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-slate-800/80">
            <div className="flex items-center gap-2">
              <span className="font-mono font-bold text-slate-200 text-sm">
                {activeApproval.id}
              </span>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/60 border border-amber-700/50 text-amber-300">
                PENDING ANALYST REVIEW
              </span>
              <span
                className={cn(
                  'px-2 py-0.5 rounded text-[10px] font-mono font-bold border',
                  activeApproval.risk_level === 'CRITICAL' || activeApproval.riskLevel === 'CRITICAL'
                    ? 'bg-rose-950/60 border-rose-700/50 text-rose-300'
                    : activeApproval.risk_level === 'HIGH' || activeApproval.riskLevel === 'HIGH'
                    ? 'bg-orange-950/60 border-orange-700/50 text-orange-300'
                    : 'bg-slate-800 border-slate-700 text-slate-300'
                )}
              >
                {activeApproval.risk_level || activeApproval.riskLevel} RISK
              </span>
            </div>

            <div className="text-[11px] font-mono text-slate-400">
              Snapshot Trust Score:{' '}
              <span className="text-cyan-400 font-bold">
                {activeApproval.trust_score ?? activeApproval.trustScore ?? 90}%
              </span>{' '}
              ({activeApproval.trust_verdict || activeApproval.trustVerdict})
            </div>
          </div>

          <div className="space-y-1">
            <div className="text-xs text-slate-400 font-mono">Proposed Action:</div>
            <div className="text-xs text-slate-200 font-semibold bg-slate-900/60 p-2.5 rounded border border-slate-800/60">
              <span className="font-mono text-cyan-400 mr-2">
                [{activeApproval.action_type || activeApproval.actionType}]:
              </span>
              {activeApproval.recommended_action || activeApproval.recommendedAction}
            </div>
          </div>

          {/* Safety Override Warning Banner */}
          {(activeApproval.requires_override || activeApproval.requiresOverride) && (
            <div className="bg-amber-950/30 border border-amber-800/50 rounded-lg p-3 flex items-start gap-2.5 text-xs text-amber-300">
              <ShieldAlert className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <div>
                <span className="font-bold text-amber-200">Safety Gating Triggered: </span>
                This investigation has low trust, uncorroborated claims, or contradictory evidence.
                Approval is gated and requires an explicit, documented override justification from the reviewer.
              </div>
            </div>
          )}

          {/* Decision Form */}
          <div className="space-y-3 pt-1">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label className="block text-slate-400 text-xs mb-1">Reviewer ID / Call Sign</label>
                <input
                  type="text"
                  value={reviewerName}
                  onChange={(e) => setReviewerName(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200 font-mono"
                  placeholder="e.g. tier2_lead"
                  required
                />
              </div>
              <div className="sm:col-span-2">
                <label className="block text-slate-400 text-xs mb-1">Decision Notes / Rationale</label>
                <input
                  type="text"
                  value={decisionNotes}
                  onChange={(e) => setDecisionNotes(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-xs text-slate-200"
                  placeholder="Document reasoning for containment approval or rejection..."
                  required
                />
              </div>
            </div>

            {(activeApproval.requires_override || activeApproval.requiresOverride) && (
              <div>
                <label className="block text-amber-400 text-xs mb-1 font-semibold">
                  Safety Override Justification (Required for Approval)
                </label>
                <input
                  type="text"
                  value={overrideJustification}
                  onChange={(e) => setOverrideJustification(e.target.value)}
                  className="w-full bg-amber-950/20 border border-amber-700/60 rounded p-2 text-xs text-slate-200 placeholder:text-slate-500"
                  placeholder="Specify why operational risk is accepted despite uncorroborated telemetry..."
                />
              </div>
            )}

            <div className="flex items-center justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => handleDecision('REJECTED')}
                disabled={isSubmitting}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-rose-950/60 hover:bg-rose-900/80 text-rose-300 border border-rose-700/60 transition-colors"
              >
                <XCircle className="w-3.5 h-3.5" />
                <span>Reject Action</span>
              </button>
              <button
                type="button"
                onClick={() => handleDecision('APPROVED')}
                disabled={isSubmitting}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg bg-emerald-950/60 hover:bg-emerald-900/80 text-emerald-300 border border-emerald-700/60 transition-colors"
              >
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Approve Action</span>
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="p-3 bg-[#0B0F19] border border-slate-800/80 rounded-lg text-xs text-slate-400 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
            <span>No pending approval gates currently waiting for human review.</span>
          </div>
          <span className="text-[11px] font-mono text-slate-500">Autonomous Execution Safe</span>
        </div>
      )}

      {/* Decision Audit Trail Toggle */}
      {finalizedApprovals.length > 0 && (
        <div className="pt-2">
          <button
            onClick={() => setShowHistory(!showHistory)}
            className="w-full py-1.5 px-3 bg-slate-900/60 hover:bg-slate-900 border border-slate-800/60 rounded-lg flex items-center justify-between text-xs font-mono text-slate-400 transition-colors"
          >
            <span className="flex items-center gap-2">
              <Lock className="w-3.5 h-3.5 text-slate-400" />
              <span>Historical Approval Audit Ledger ({finalizedApprovals.length})</span>
            </span>
            {showHistory ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </button>

          {showHistory && (
            <div className="mt-2 space-y-2">
              {finalizedApprovals.map((app) => (
                <div
                  key={app.id}
                  className="p-3 rounded-lg bg-[#0B0F19] border border-slate-800/80 text-xs font-mono space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-200">{app.id}</span>
                      <span
                        className={cn(
                          'px-2 py-0.5 rounded text-[10px] font-bold border',
                          app.status === 'APPROVED'
                            ? 'bg-emerald-950/60 border-emerald-700/50 text-emerald-300'
                            : 'bg-rose-950/60 border-rose-700/50 text-rose-300'
                        )}
                      >
                        {app.status}
                      </span>
                      <span className="text-slate-400 text-[11px]">
                        [{app.action_type || app.actionType}]
                      </span>
                    </div>
                    <span className="text-[10px] text-slate-500">
                      {app.decision_at || app.decisionAt}
                    </span>
                  </div>

                  <p className="text-slate-300 font-sans text-[11px]">
                    {app.recommended_action || app.recommendedAction}
                  </p>

                  <div className="text-[11px] text-slate-400 flex flex-wrap gap-x-4 pt-1 border-t border-slate-800/60">
                    <span>
                      Reviewer:{' '}
                      <strong className="text-slate-200">{app.reviewer}</strong>
                    </span>
                    <span>
                      Notes:{' '}
                      <span className="text-slate-300">{app.decision_notes || app.decisionNotes}</span>
                    </span>
                    {(app.override_justification || app.overrideJustification) && (
                      <span className="text-amber-300">
                        Override Rationale:{' '}
                        {app.override_justification || app.overrideJustification}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
