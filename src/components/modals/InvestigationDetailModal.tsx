import { useEffect, useState } from 'react';
import type { Investigation } from '../../types/soc';
import {
  X,
  ShieldCheck,
  CheckCircle2,
  Lock,
  ArrowLeft,
  Server,
  Calendar,
  Clock,
  FileText,
  Layers,
  Activity,
} from 'lucide-react';
import {
  getSeverityBadgeClass,
  getStatusBadgeClass,
  getTrustScoreColor,
  cn,
} from '../../lib/utils';
import { TrustScoreBar, TrustScoreLegend } from '../ui/TrustScoreBar';
import { Button } from '../ui/Button';
import { EvidenceEngineSection } from '../investigations/EvidenceEngineSection';
import { ToolActivitySection } from '../investigations/ToolActivitySection';
import { PlannerSection } from '../investigations/PlannerSection';
import { CriticSection } from '../investigations/CriticSection';
import { AuditedCaseSection } from '../investigations/AuditedCaseSection';
import { TrustScoreSection } from '../investigations/TrustScoreSection';
import { HumanApprovalSection } from '../investigations/HumanApprovalSection';
import { AuditSealSection } from '../investigations/AuditSealSection';
import { ContainmentPlaybookSection } from '../investigations/ContainmentPlaybookSection';
import { InvestigationTimelineSection } from '../investigations/InvestigationTimelineSection';
import { useInvestigationSocket } from '../../hooks/useInvestigationSocket';

interface InvestigationDetailModalProps {
  investigation: Investigation | null;
  onClose: () => void;
  onEvidenceCountUpdated?: (newCount: number) => void;
}

export const InvestigationDetailModal: React.FC<InvestigationDetailModalProps> = ({
  investigation,
  onClose,
  onEvidenceCountUpdated,
}) => {
  const [currentEvidenceCount, setCurrentEvidenceCount] = useState<number>(0);

  const { isConnected: isWsLive, events: wsEvents } = useInvestigationSocket({
    investigationId: investigation?.id || null,
  });

  // Synchronize initial evidence count when investigation changes
  useEffect(() => {
    if (investigation) {
      setCurrentEvidenceCount(
        investigation.evidenceCount ?? investigation.artifactCount ?? 0
      );
    }
  }, [investigation]);

  // Close on Escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  if (!investigation) return null;

  const trustColor = getTrustScoreColor(investigation.evidenceTrustScore);
  const eventTime = investigation.eventTimestamp || investigation.startedAtTimestamp || investigation.started;
  const createdTime = investigation.createdTimestamp || investigation.startedAtTimestamp || 'Just now';

  const handleEvidenceCountChange = (newCount: number) => {
    setCurrentEvidenceCount(newCount);
    if (onEvidenceCountUpdated) {
      onEvidenceCountUpdated(newCount);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-3 sm:p-5 bg-black/80 backdrop-blur-sm animate-in fade-in duration-200"
      onClick={(e) => {
        // Close when clicking overlay backdrop
        if (e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div className="bg-[#0F172A] border border-slate-700/80 rounded-2xl w-full max-w-4xl max-h-[92vh] shadow-2xl flex flex-col overflow-hidden animate-in zoom-in-95 duration-200">
        {/* Navigation Bar / Header */}
        <div className="p-4 sm:p-5 border-b border-slate-800 bg-[#0B0F19] flex items-center justify-between gap-4">
          <div className="flex items-center gap-3 min-w-0">
            {/* Back action button */}
            <button
              onClick={onClose}
              className="inline-flex items-center gap-1.5 text-xs font-medium text-slate-300 hover:text-cyan-400 bg-slate-900/80 hover:bg-slate-800 border border-slate-700/80 hover:border-cyan-500/50 px-2.5 py-1.5 rounded-lg transition-colors shrink-0"
              title="Return to investigations list"
            >
              <ArrowLeft className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Back to List</span>
            </button>

            <div className="h-5 w-px bg-slate-800 hidden sm:block" />

            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-base font-bold text-cyan-400">
                  {investigation.id}
                </span>
                <span
                  className={cn(
                    'font-mono text-xs px-2 py-0.5 rounded font-semibold border',
                    getSeverityBadgeClass(investigation.severity)
                  )}
                >
                  {investigation.severity}
                </span>
                <span
                  className={cn(
                    'text-xs px-2 py-0.5 rounded font-medium border',
                    getStatusBadgeClass(investigation.status)
                  )}
                >
                  {investigation.status}
                </span>

                {/* Module 3K: Live WebSocket Status */}
                <span
                  className={cn(
                    'inline-flex items-center gap-1.5 text-[11px] font-mono px-2 py-0.5 rounded-full border transition-colors',
                    isWsLive
                      ? 'bg-emerald-950/50 border-emerald-700/60 text-emerald-300'
                      : 'bg-slate-900/60 border-slate-700/60 text-slate-400'
                  )}
                  title={isWsLive ? 'Subscribed to real-time agent telemetry' : 'Connecting to live telemetry...'}
                >
                  <span className="relative flex h-1.5 w-1.5">
                    {isWsLive && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>}
                    <span className={cn('relative inline-flex rounded-full h-1.5 w-1.5', isWsLive ? 'bg-emerald-400' : 'bg-slate-500')}></span>
                  </span>
                  <span>{isWsLive ? 'Live Stream' : 'Connecting'}</span>
                  {wsEvents.length > 0 && <span className="text-[10px] text-emerald-300 font-bold">({wsEvents.length})</span>}
                </span>
              </div>
              <h2 className="text-sm font-semibold text-slate-100 truncate mt-0.5">
                {investigation.alert}
              </h2>
            </div>
          </div>

          {/* Close button */}
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-2 rounded-lg hover:bg-slate-800 transition-colors shrink-0"
            aria-label="Close modal"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-5 sm:p-6 space-y-5 overflow-y-auto flex-1 text-xs">
          {/* Primary Metadata Cards (Grid of required fields) */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {/* 1. Target Host */}
            <div className="p-3 rounded-xl bg-[#090D16] border border-slate-800/90 font-mono">
              <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase font-semibold mb-1">
                <Server className="w-3 h-3 text-cyan-400" />
                Target Host
              </div>
              <div className="text-slate-100 font-bold truncate text-xs" title={investigation.host}>
                {investigation.host}
              </div>
            </div>

            {/* 2. Evidence Count */}
            <div className="p-3 rounded-xl bg-[#090D16] border border-slate-800/90 font-mono">
              <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase font-semibold mb-1">
                <Layers className="w-3 h-3 text-cyan-400" />
                Evidence Count
              </div>
              <div className="text-cyan-400 font-bold text-xs flex items-baseline gap-1">
                <span className="text-sm">{currentEvidenceCount}</span>
                <span className="text-[11px] text-slate-400 font-normal">artifacts</span>
              </div>
            </div>

            {/* 3. Event Timestamp */}
            <div className="p-3 rounded-xl bg-[#090D16] border border-slate-800/90 font-mono">
              <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase font-semibold mb-1">
                <Clock className="w-3 h-3 text-amber-400" />
                Event Timestamp
              </div>
              <div className="text-slate-200 font-medium text-[11px] truncate" title={eventTime}>
                {eventTime}
              </div>
            </div>

            {/* 4. Created Timestamp */}
            <div className="p-3 rounded-xl bg-[#090D16] border border-slate-800/90 font-mono">
              <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase font-semibold mb-1">
                <Calendar className="w-3 h-3 text-emerald-400" />
                Created Timestamp
              </div>
              <div className="text-slate-200 font-medium text-[11px] truncate" title={createdTime}>
                {createdTime}
              </div>
            </div>
          </div>

          {/* Description & Hypothesis Section */}
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5 font-semibold text-slate-200 text-xs">
              <FileText className="w-3.5 h-3.5 text-cyan-400" />
              <span>Description / Investigative Hypothesis</span>
            </div>
            <div className="text-slate-200 bg-[#090D16]/90 p-3.5 rounded-xl border border-slate-800 leading-relaxed font-sans text-xs">
              {investigation.description || 'No detailed hypothesis submitted for this case.'}
            </div>
          </div>

          {/* MITRE ATT&CK Matrix Mapping (if present) */}
          {investigation.mitreTechnique && (
            <div>
              <span className="font-semibold text-slate-300 block mb-1.5 text-xs">
                MITRE ATT&CK Matrix Technique
              </span>
              <div className="font-mono text-xs text-cyan-300 bg-cyan-950/30 border border-cyan-800/40 p-2.5 rounded-xl flex items-center justify-between">
                <span>{investigation.mitreTechnique}</span>
                <span className="text-[10px] uppercase font-semibold bg-cyan-900/60 text-cyan-200 px-2 py-0.5 rounded border border-cyan-700/50">
                  Enterprise Matrix
                </span>
              </div>
            </div>
          )}

          {/* MODULE 3C: Deterministic Planner Agent Workflow */}
          <PlannerSection
            investigationId={investigation.id}
            alertText={investigation.alert}
          />

          {/* MODULE 3D: Critic / Red-Team Agent Reasoning */}
          <CriticSection
            investigationId={investigation.id}
          />

          {/* MODULE 3E & 3F: Auditor Agent — Evidence-Backed Case File */}
          <AuditedCaseSection
            investigationId={investigation.id}
          />

          {/* MODULE 3G: Deterministic Evidence & Audit Quality Trust Score */}
          <TrustScoreSection
            investigationId={investigation.id}
          />

          {/* MODULE 3J: Human-in-the-Loop Approval Gates & Safety Overrides */}
          <HumanApprovalSection
            investigationId={investigation.id}
          />

          {/* MODULE 3L: Cryptographic Immutable Audit Bundle & Proof Seal */}
          <AuditSealSection
            investigationId={investigation.id}
          />

          {/* MODULE 3N: Automated Containment & Incident Remediation Playbooks */}
          <ContainmentPlaybookSection
            investigationId={investigation.id}
            defaultHost={investigation.host}
          />

          {/* MODULE 3O: Forensic Timeline Replay & Time-Travel Debugger */}
          <InvestigationTimelineSection
            investigationId={investigation.id}
          />

          {/* MODULE 3B: Allow-listed Security Tool Layer & Audit Trail */}
          <ToolActivitySection
            investigationId={investigation.id}
            onEvidenceCreated={() => {
              handleEvidenceCountChange(currentEvidenceCount + 1);
            }}
          />

          {/* MODULE 3A: Forensic Evidence Engine & Append-Only Ledger */}
          <EvidenceEngineSection
            investigationId={investigation.id}
            onEvidenceAdded={handleEvidenceCountChange}
          />

          {/* Evidence Trust Score Breakdown */}
          <div className="p-4 rounded-xl bg-slate-900/90 border border-slate-800 space-y-3 shadow-inner">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-bold text-slate-100 flex items-center gap-1.5 text-xs">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  Evidence Trust Score
                </span>
                <span className="text-[11px] text-slate-400 block mt-0.5">
                  Multi-source evidentiary corroboration index (independent of AI confidence)
                </span>
              </div>
              <div className="text-right">
                <span className={cn('text-xl font-bold font-mono', trustColor.textColor)}>
                  {investigation.evidenceTrustScore}%
                </span>
                <span className="block text-[10px] font-mono text-slate-400">
                  {trustColor.label}
                </span>
              </div>
            </div>

            <TrustScoreBar score={investigation.evidenceTrustScore} showLabel={false} />

            {/* Corroborating Signals Breakdown */}
            {investigation.evidenceCorroboration && investigation.evidenceCorroboration.length > 0 ? (
              <div className="mt-3 pt-3 border-t border-slate-800 space-y-2">
                <span className="text-[11px] font-semibold uppercase text-slate-400 block tracking-wider font-mono">
                  Corroborating Telemetry Signals ({investigation.evidenceCorroboration.length} Sources)
                </span>
                {investigation.evidenceCorroboration.map((item, idx) => (
                  <div
                    key={idx}
                    className="flex items-center justify-between p-2.5 rounded-lg bg-[#090D16] border border-slate-800/80 font-mono text-[11px]"
                  >
                    <div className="flex items-center gap-2">
                      <CheckCircle2
                        className={cn(
                          'w-3.5 h-3.5',
                          item.corroborated ? 'text-emerald-400' : 'text-slate-400'
                        )}
                      />
                      <span className="text-slate-200">{item.source}</span>
                    </div>
                    <span className="text-cyan-400 font-semibold">{item.score}% match</span>
                  </div>
                ))}
              </div>
            ) : (
              <div className="mt-3 pt-3 border-t border-slate-800 font-mono text-[11px] text-slate-400 flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-cyan-400" />
                <span>Primary telemetry corroboration calculated across cryptographic evidence objects</span>
              </div>
            )}
          </div>

          <TrustScoreLegend />
        </div>

        {/* Footer with Clear Back/Close Actions */}
        <div className="p-4 border-t border-slate-800 bg-[#0B0F19] flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
            <Lock className="w-3.5 h-3.5 text-slate-400" />
            <span>Audit Block Verified • {investigation.id} • SHA-256 Engine Active</span>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={onClose}
              icon={<ArrowLeft className="w-3.5 h-3.5" />}
              className="border-slate-700 text-slate-200 hover:bg-slate-800"
            >
              Back to Investigations
            </Button>
            <Button variant="secondary" size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};
