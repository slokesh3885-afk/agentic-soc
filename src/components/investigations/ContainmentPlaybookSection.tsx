import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  RotateCcw,
  Play,
  Lock,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Copy,
  Check,
  Server,
  Network,
  Zap,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type {
  ContainmentExecution,
  PlaybookDefinition,
} from '../../types/soc';

interface ContainmentPlaybookSectionProps {
  investigationId: string;
  defaultHost?: string;
  onContainmentUpdated?: () => void;
}

export const ContainmentPlaybookSection: React.FC<ContainmentPlaybookSectionProps> = ({
  investigationId,
  defaultHost = '',
  onContainmentUpdated,
}) => {
  const [playbooks, setPlaybooks] = useState<PlaybookDefinition[]>([]);
  const [containments, setContainments] = useState<ContainmentExecution[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false);
  const [showDispatchForm, setShowDispatchForm] = useState<boolean>(false);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState<string>('PLAYBOOK-HOST-ISOLATION');
  const [targetIdentifier, setTargetIdentifier] = useState<string>(defaultHost);
  const [dispatchNotes, setDispatchNotes] = useState<string>('');
  const [rollbackId, setRollbackId] = useState<string | null>(null);
  const [rollbackReason, setRollbackReason] = useState<string>('');
  const [isRollingBack, setIsRollingBack] = useState<boolean>(false);
  const [expandedContId, setExpandedContId] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const loadData = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const [pbList, contList] = await Promise.all([
        socApi.getPlaybooks(),
        socApi.getInvestigationContainments(investigationId),
      ]);
      setPlaybooks(pbList);
      setContainments(contList);
      if (contList.length > 0 && !expandedContId) {
        setExpandedContId(contList[0].id);
      }
    } catch (err: any) {
      console.error('Failed to load containment data:', err);
      setErrorMsg(err.message || 'Failed to load containment records');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
    if (defaultHost) {
      setTargetIdentifier(defaultHost);
    }
  }, [investigationId, defaultHost]);

  const handleDispatch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!targetIdentifier.trim()) {
      setErrorMsg('Please specify target identifier.');
      return;
    }
    setIsSubmitting(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      const result = await socApi.dispatchContainment({
        investigation_id: investigationId,
        playbook_id: selectedPlaybookId,
        target_identifier: targetIdentifier.trim(),
        dispatched_by: 'SecOps Analyst Console',
        notes: dispatchNotes.trim() || 'Automated containment dispatched via incident management modal.',
      });
      setSuccessMsg(`Playbook ${result.playbook_id} dispatched successfully (Quarantine ID: ${result.id})`);
      setShowDispatchForm(false);
      setDispatchNotes('');
      await loadData();
      if (onContainmentUpdated) {
        onContainmentUpdated();
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to dispatch containment playbook');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleRollback = async (containmentId: string) => {
    if (!rollbackReason.trim()) {
      setErrorMsg('Please enter a de-escalation reason for rollback.');
      return;
    }
    setIsRollingBack(true);
    setErrorMsg(null);
    setSuccessMsg(null);
    try {
      await socApi.rollbackContainment(containmentId, {
        rolled_back_by: 'SecOps Incident Commander',
        reason: rollbackReason.trim(),
      });
      setSuccessMsg(`Containment ${containmentId} safely rolled back and target restored.`);
      setRollbackId(null);
      setRollbackReason('');
      await loadData();
      if (onContainmentUpdated) {
        onContainmentUpdated();
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to rollback containment');
    } finally {
      setIsRollingBack(false);
    }
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  return (
    <div className="bg-[#090D16] border border-slate-800 rounded-xl p-4 sm:p-5 space-y-4 shadow-md">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-rose-950/70 border border-rose-800/70 flex items-center justify-center text-rose-400">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                Containment & Remediation Playbooks
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/80 text-cyan-400 border border-cyan-800/80">
                Module 3N
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/80 text-emerald-400 border border-emerald-800/80 flex items-center gap-1">
                <CheckCircle2 className="w-3 h-3" />
                Allow-listed SOAR
              </span>
            </div>
            <p className="text-[11px] text-slate-400 mt-0.5">
              Deterministic host isolation, perimeter IP drops, process termination & reversible quarantine.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowDispatchForm(!showDispatchForm)}
            className="px-2.5 py-1.5 text-xs font-medium text-cyan-300 bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-800/80 rounded-lg flex items-center gap-1.5 transition-colors font-mono"
          >
            <Play className="w-3.5 h-3.5 text-cyan-400" />
            <span>{showDispatchForm ? 'Close Dispatch' : 'Dispatch Playbook'}</span>
          </button>
          <button
            onClick={loadData}
            disabled={isLoading}
            className="p-1.5 text-slate-400 hover:text-slate-200 bg-slate-800 hover:bg-slate-700 rounded-lg border border-slate-700 transition-colors"
            title="Refresh containment records"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Status Messages */}
      {errorMsg && (
        <div className="p-3 bg-red-950/50 border border-red-800/80 rounded-lg text-xs text-red-300 font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}
      {successMsg && (
        <div className="p-3 bg-emerald-950/50 border border-emerald-800/80 rounded-lg text-xs text-emerald-300 font-mono flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
          <span>{successMsg}</span>
        </div>
      )}

      {/* Dispatch Playbook Interactive Form */}
      {showDispatchForm && (
        <form onSubmit={handleDispatch} className="p-4 bg-[#0B101E] border border-cyan-800/60 rounded-xl space-y-3.5 animate-in fade-in duration-200">
          <div className="text-xs font-bold text-cyan-300 font-mono flex items-center gap-2">
            <Zap className="w-4 h-4 text-cyan-400" />
            <span>Select & Dispatch Allow-listed Response Playbook</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-1">
              <label className="text-[11px] font-mono text-slate-400">Playbook Workflow:</label>
              <select
                value={selectedPlaybookId}
                onChange={(e) => {
                  setSelectedPlaybookId(e.target.value);
                  const pb = playbooks.find((p) => p.id === e.target.value);
                  if (pb?.target_type === 'IP_ADDRESS') {
                    setTargetIdentifier('198.51.100.42');
                  } else if (pb?.target_type === 'PROCESS') {
                    setTargetIdentifier('powershell.exe:PID-4820');
                  } else {
                    setTargetIdentifier(defaultHost || 'DC-PROD-01.corp.internal');
                  }
                }}
                className="w-full bg-[#070B14] border border-slate-700 text-xs text-slate-200 px-3 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500 font-mono"
              >
                {playbooks.map((pb) => (
                  <option key={pb.id} value={pb.id}>
                    {pb.name} ({pb.target_type})
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-[11px] font-mono text-slate-400">Target Entity Identifier:</label>
              <input
                type="text"
                value={targetIdentifier}
                onChange={(e) => setTargetIdentifier(e.target.value)}
                placeholder="e.g. host FQDN, IP, or process name"
                className="w-full bg-[#070B14] border border-slate-700 text-xs text-slate-200 px-3 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500 font-mono"
                required
              />
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-[11px] font-mono text-slate-400">Operational Notes / Reason:</label>
            <input
              type="text"
              value={dispatchNotes}
              onChange={(e) => setDispatchNotes(e.target.value)}
              placeholder="e.g. Containment ordered following verified threat detection."
              className="w-full bg-[#070B14] border border-slate-700 text-xs text-slate-200 px-3 py-1.5 rounded-lg focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>

          <div className="flex items-center justify-end gap-2 pt-1">
            <button
              type="button"
              onClick={() => setShowDispatchForm(false)}
              className="px-3 py-1 text-xs text-slate-400 hover:text-slate-200"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={isSubmitting}
              className="px-3.5 py-1.5 text-xs font-semibold text-white bg-cyan-600 hover:bg-cyan-500 rounded-lg flex items-center gap-1.5 shadow-sm disabled:opacity-50 font-mono"
            >
              <Play className="w-3.5 h-3.5" />
              <span>{isSubmitting ? 'Executing Playbook...' : 'Execute Containment'}</span>
            </button>
          </div>
        </form>
      )}

      {/* Containment Records List */}
      <div className="space-y-3">
        <div className="flex items-center justify-between text-xs text-slate-400 font-mono">
          <span>Active Quarantines & Containment Records ({containments.length})</span>
          <span>Reversible & Sealed</span>
        </div>

        {containments.length === 0 ? (
          <div className="p-6 text-center bg-[#070B14] border border-slate-800/80 rounded-xl text-xs text-slate-400 space-y-1.5">
            <ShieldCheck className="w-6 h-6 text-slate-600 mx-auto" />
            <div>No active quarantine or containment actions dispatched for this investigation.</div>
            <div className="text-[11px] text-slate-500">
              Click &quot;Dispatch Playbook&quot; above to isolate the endpoint or block malicious C2 egress.
            </div>
          </div>
        ) : (
          containments.map((cont) => {
            const isExpanded = expandedContId === cont.id;
            const isContained = cont.status === 'CONTAINED';
            const isRolledBack = cont.status === 'ROLLED_BACK';

            return (
              <div
                key={cont.id}
                className="bg-[#070B14] border border-slate-800/90 rounded-xl overflow-hidden text-xs transition-all"
              >
                {/* Header row */}
                <div
                  onClick={() => setExpandedContId(isExpanded ? null : cont.id)}
                  className="p-3.5 flex flex-wrap items-center justify-between gap-3 cursor-pointer hover:bg-slate-800/20"
                >
                  <div className="flex items-center gap-2.5">
                    <span className="font-mono text-cyan-400 font-bold">{cont.id}</span>
                    <span className="text-slate-500">•</span>
                    <span className="font-semibold text-slate-200">{cont.playbook_name}</span>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded-full border font-bold ${
                        isContained
                          ? 'bg-emerald-950/80 text-emerald-400 border-emerald-800/80'
                          : isRolledBack
                          ? 'bg-slate-800 text-slate-400 border-slate-700'
                          : 'bg-amber-950/80 text-amber-400 border-amber-800/80'
                      }`}
                    >
                      {cont.status}
                    </span>
                  </div>

                  <div className="flex items-center gap-3 text-slate-400 font-mono text-[11px]">
                    <span className="flex items-center gap-1">
                      {cont.target_type === 'HOST' ? <Server className="w-3.5 h-3.5" /> : <Network className="w-3.5 h-3.5" />}
                      <span className="text-slate-300">{cont.target_identifier}</span>
                    </span>
                    <span>{cont.dispatched_at}</span>
                    {isExpanded ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div className="p-4 border-t border-slate-800/80 bg-[#050811] space-y-3.5">
                    {/* Digital Proof & Audit Receipt */}
                    <div className="p-3 bg-[#0A0F1D] border border-slate-800 rounded-lg flex flex-wrap items-center justify-between gap-2 font-mono text-[11px]">
                      <div className="flex items-center gap-2">
                        <Lock className="w-3.5 h-3.5 text-cyan-400" />
                        <span className="text-slate-400">Proof Hash:</span>
                        <span className="text-cyan-300 truncate max-w-[200px]" title={cont.quarantine_receipt_hash}>
                          {cont.quarantine_receipt_hash}
                        </span>
                        <button
                          onClick={() => handleCopy(cont.quarantine_receipt_hash)}
                          className="text-slate-400 hover:text-slate-200"
                          title="Copy receipt proof hash"
                        >
                          {copiedHash === cont.quarantine_receipt_hash ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        </button>
                      </div>

                      {cont.audit_entry_id && (
                        <div className="text-[10px] px-2 py-0.5 rounded bg-blue-950/80 text-blue-300 border border-blue-800/80">
                          Ledger Block: {cont.audit_entry_id}
                        </div>
                      )}
                    </div>

                    {/* Step-by-step Execution Log */}
                    <div className="space-y-2">
                      <div className="text-[11px] font-bold text-slate-300 font-mono">
                        Deterministic Step Receipts:
                      </div>
                      <div className="space-y-1.5">
                        {cont.execution_steps?.map((step) => (
                          <div
                            key={step.step_number}
                            className="p-2.5 bg-[#090D16] border border-slate-800 rounded-lg flex items-start gap-2.5 text-xs"
                          >
                            <span className="w-5 h-5 rounded-full bg-slate-800 text-slate-300 font-mono text-[10px] flex items-center justify-center shrink-0 border border-slate-700 font-bold">
                              {step.step_number}
                            </span>
                            <div className="space-y-0.5 flex-1 min-w-0">
                              <div className="flex items-center justify-between font-mono text-[10px]">
                                <span className="font-bold text-slate-200">{step.action}</span>
                                <span className="text-emerald-400 flex items-center gap-0.5">
                                  <CheckCircle2 className="w-3 h-3" />
                                  Verified
                                </span>
                              </div>
                              <p className="text-[11px] text-slate-400 font-sans">{step.details}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Rollback controls / status */}
                    <div className="pt-2 border-t border-slate-800/80 flex items-center justify-between">
                      {isContained && cont.rollback_enabled ? (
                        rollbackId === cont.id ? (
                          <div className="flex flex-col sm:flex-row items-center gap-2 w-full">
                            <input
                              type="text"
                              value={rollbackReason}
                              onChange={(e) => setRollbackReason(e.target.value)}
                              placeholder="Reason for restoring network (e.g. host verified clean)"
                              className="flex-1 bg-[#090D16] border border-slate-700 text-xs text-slate-200 px-3 py-1 rounded-lg focus:outline-none font-mono"
                            />
                            <div className="flex items-center gap-2">
                              <button
                                onClick={() => handleRollback(cont.id)}
                                disabled={isRollingBack}
                                className="px-3 py-1 bg-amber-600 hover:bg-amber-500 text-white rounded text-xs font-mono font-bold flex items-center gap-1.5"
                              >
                                <RotateCcw className="w-3.5 h-3.5" />
                                <span>{isRollingBack ? 'Restoring...' : 'Confirm Restore'}</span>
                              </button>
                              <button
                                onClick={() => setRollbackId(null)}
                                className="text-xs text-slate-400 hover:text-slate-200"
                              >
                                Cancel
                              </button>
                            </div>
                          </div>
                        ) : (
                          <button
                            onClick={() => setRollbackId(cont.id)}
                            className="px-2.5 py-1 text-xs text-amber-300 bg-amber-950/60 hover:bg-amber-900 border border-amber-800/60 rounded-lg flex items-center gap-1.5 transition-colors font-mono"
                          >
                            <RotateCcw className="w-3.5 h-3.5" />
                            <span>Rollback / Restore Target</span>
                          </button>
                        )
                      ) : isRolledBack ? (
                        <div className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
                          <CheckCircle2 className="w-3.5 h-3.5 text-slate-500" />
                          <span>Restored at {cont.rolled_back_at} • Reason: {cont.rollback_notes}</span>
                        </div>
                      ) : (
                        <div className="text-[11px] font-mono text-slate-500">
                          Non-reversible containment action.
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
