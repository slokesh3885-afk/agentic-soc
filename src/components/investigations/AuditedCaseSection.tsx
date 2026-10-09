import React, { useState, useEffect, useCallback } from 'react';
import type { AuditedCase } from '../../types/soc';
import { socApi } from '../../lib/api';
import {
  FileCheck2,
  ShieldCheck,
  AlertTriangle,
  FileQuestion,
  RefreshCw,
  Info,
  CheckCircle2,
  XCircle,
  Clock,
  Wrench,
  ChevronDown,
  ChevronRight,
  Fingerprint,
  FileCode2,
  Copy,
  Check,
} from 'lucide-react';
import { Button } from '../ui/Button';
import { cn } from '../../lib/utils';

interface AuditedCaseSectionProps {
  investigationId: string;
}

export const AuditedCaseSection: React.FC<AuditedCaseSectionProps> = ({
  investigationId,
}) => {
  const [auditedCase, setAuditedCase] = useState<AuditedCase | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isAuditing, setIsAuditing] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [showTools, setShowTools] = useState<boolean>(false);
  const [showCaseJson, setShowCaseJson] = useState<boolean>(false);
  const [caseJsonData, setCaseJsonData] = useState<any>(null);
  const [isLoadingJson, setIsLoadingJson] = useState<boolean>(false);
  const [copied, setCopied] = useState<boolean>(false);

  const fetchLatestCase = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await socApi.getAuditedCase(investigationId);
      setAuditedCase(data);
    } catch (err: any) {
      console.error('Failed to load audited case:', err);
      setError(err?.message || 'Failed to load audited case');
    } finally {
      setIsLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    fetchLatestCase();
  }, [fetchLatestCase]);

  const handleRunAudit = async () => {
    setIsAuditing(true);
    setError(null);
    try {
      // Collect claims from existing case or default standard claims
      const claimsToAudit = auditedCase?.claims?.map((c) => ({
        claim: c.claim,
        evidence_ids: c.evidence_ids || c.evidenceIds || [],
      })) || [
        {
          claim: 'PowerShell execution occurred on PC-DB-TEST',
          evidence_ids: ['E-001'],
        },
        {
          claim: 'Threat actor is APT-X',
          evidence_ids: [],
        },
      ];

      const result = await socApi.createAuditedCase(investigationId, {
        claims: claimsToAudit,
      });
      setAuditedCase(result);
      setCaseJsonData(null);
    } catch (err: any) {
      console.error('Failed to generate audited case:', err);
      setError(err?.message || 'Failed to generate audited case');
    } finally {
      setIsAuditing(false);
    }
  };

  const handleToggleCaseJson = async () => {
    if (!showCaseJson && !caseJsonData) {
      setIsLoadingJson(true);
      try {
        const data = await socApi.getCanonicalCaseJson(investigationId);
        setCaseJsonData(data);
      } catch (err: any) {
        console.error('Failed to load canonical case JSON:', err);
      } finally {
        setIsLoadingJson(false);
      }
    }
    setShowCaseJson(!showCaseJson);
  };

  const handleCopyJson = () => {
    if (!caseJsonData) return;
    navigator.clipboard.writeText(JSON.stringify(caseJsonData, null, 2));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'SUPPORTED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-700/60 uppercase flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            SUPPORTED
          </span>
        );
      case 'UNSUPPORTED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-700/60 uppercase flex items-center gap-1">
            <XCircle className="w-3 h-3 text-rose-400" />
            UNSUPPORTED
          </span>
        );
      case 'CONTRADICTED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-700/60 uppercase flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            CONTRADICTED
          </span>
        );
      case 'UNCERTAIN':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-yellow-950/80 text-yellow-300 border border-yellow-700/60 uppercase flex items-center gap-1">
            <FileQuestion className="w-3 h-3 text-yellow-400" />
            UNCERTAIN
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-900 text-slate-300 border border-slate-700 uppercase">
            {status}
          </span>
        );
    }
  };

  return (
    <div className="rounded-xl bg-[#090D16] border border-emerald-900/40 p-4 space-y-4 shadow-xl">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-emerald-950/70 border border-emerald-700/50 text-emerald-400">
              <FileCheck2 className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-emerald-300 font-mono">
                  Audited Case
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-emerald-950/60 border border-emerald-800/60 text-emerald-300 font-semibold">
                  Module 3E & 3F
                </span>
                {auditedCase && (
                  <>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 font-semibold">
                      {auditedCase.case_id || auditedCase.caseId}
                    </span>
                    <span className="text-[10px] font-mono px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wide border border-emerald-700/80 bg-emerald-950/80 text-emerald-300 flex items-center gap-1">
                      <ShieldCheck className="w-3 h-3" />
                      AUDIT VERIFIED
                    </span>
                  </>
                )}
              </div>
            </div>
          </div>
          <p className="text-[11px] text-slate-400">
            Final evidence-accountability ledger synthesizing verified facts and exposing uncertainty.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <Button
            size="sm"
            variant="outline"
            onClick={handleToggleCaseJson}
            disabled={isLoading || isAuditing}
            className="h-8 text-xs font-mono border-cyan-800/60 hover:bg-cyan-950/40 text-cyan-300 gap-1.5"
            title="View and export Canonical Case JSON (Module 3F)"
          >
            <FileCode2 className={cn('w-3.5 h-3.5', isLoadingJson && 'animate-spin')} />
            {isLoadingJson ? 'Loading...' : showCaseJson ? 'Hide Case JSON' : 'Case JSON (v1.0.0)'}
          </Button>

          <Button
            size="sm"
            variant="outline"
            onClick={handleRunAudit}
            disabled={isAuditing || isLoading}
            className="h-8 text-xs font-mono border-emerald-800/60 hover:bg-emerald-950/40 text-emerald-300 gap-1.5"
            title="Re-run deterministic case audit"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isAuditing && 'animate-spin')} />
            {isAuditing ? 'Auditing Case...' : 'Re-Audit Case'}
          </Button>
        </div>
      </div>

      {/* Module 3F: Canonical Case JSON Viewer */}
      {showCaseJson && (
        <div className="rounded-lg bg-slate-950/90 border border-cyan-900/60 p-3 space-y-2 font-mono">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800">
            <div className="flex items-center gap-2 text-xs">
              <span className="font-bold text-cyan-300 flex items-center gap-1.5">
                <FileCode2 className="w-4 h-4 text-cyan-400" />
                Canonical Case JSON
              </span>
              <span className="px-2 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 text-[10px]">
                Schema: v1.0.0 (Module 3F)
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950/60 border border-emerald-800/60 text-emerald-300 text-[10px]">
                Deterministic Validated
              </span>
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={handleCopyJson}
              disabled={!caseJsonData}
              className="h-7 px-2.5 text-[11px] border-cyan-800/60 hover:bg-cyan-950/40 text-cyan-300 gap-1"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              {copied ? 'Copied!' : 'Copy JSON'}
            </Button>
          </div>

          {isLoadingJson ? (
            <div className="py-6 text-center text-xs text-slate-400">Loading canonical Case JSON...</div>
          ) : caseJsonData ? (
            <pre className="text-[11px] text-slate-300 bg-slate-900/90 p-3 rounded border border-slate-800/80 overflow-x-auto max-h-80 overflow-y-auto leading-relaxed">
              {JSON.stringify(caseJsonData, null, 2)}
            </pre>
          ) : (
            <div className="py-4 text-center text-xs text-slate-500">
              No canonical case JSON available. Audit the case first.
            </div>
          )}
        </div>
      )}

      {/* Safety Notice */}
      <div className="flex items-start gap-2 p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-[11px] text-emerald-300/90 font-mono">
        <Info className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
        <span>
          <strong>Audit Principle:</strong> NO EVIDENCE → NO CLAIM. The Auditor converts investigations into verifiable cases without blind trust in investigator drafts, requiring cryptographic SHA-256 evidence integrity.
        </span>
      </div>


      {/* Error Notice */}
      {error && (
        <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs font-mono text-rose-300 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Content Area */}
      {isLoading ? (
        <div className="p-8 text-center text-xs font-mono text-slate-400 space-y-2">
          <RefreshCw className="w-5 h-5 animate-spin mx-auto text-emerald-400" />
          <div>Retrieving verified case file...</div>
        </div>
      ) : !auditedCase ? (
        <div className="p-8 text-center rounded-xl bg-slate-950/40 border border-dashed border-slate-800 space-y-3">
          <FileCheck2 className="w-8 h-8 text-slate-600 mx-auto" />
          <div className="text-xs text-slate-300 font-mono">No audited case file generated yet.</div>
          <p className="text-[11px] text-slate-400 max-w-md mx-auto">
            Click &quot;Re-Audit Case&quot; to compile all verified evidence, tool executions, and Critic findings into an auditable case file.
          </p>
          <Button
            size="sm"
            onClick={handleRunAudit}
            disabled={isAuditing}
            className="h-8 text-xs font-mono bg-emerald-700 hover:bg-emerald-600 text-white"
          >
            <FileCheck2 className="w-3.5 h-3.5 mr-1.5" />
            Generate Audited Case
          </Button>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Final Conclusion (Evidence-Backed Synthesis) */}
          <div className="p-3.5 rounded-xl bg-slate-950/90 border border-emerald-900/60 font-mono space-y-1.5">
            <div className="flex items-center justify-between text-[10px] text-emerald-400 uppercase font-bold tracking-wider">
              <span>FINAL CONCLUSION (EVIDENCE-BACKED):</span>
              {auditedCase.created_at && (
                <span className="flex items-center gap-1 text-slate-500 font-normal">
                  <Clock className="w-3 h-3" />
                  Audited: {new Date(auditedCase.created_at).toLocaleTimeString()}
                </span>
              )}
            </div>
            <div className="text-xs text-slate-100 font-sans font-medium leading-relaxed">
              &quot;{auditedCase.final_conclusion || auditedCase.finalConclusion}&quot;
            </div>
          </div>

          {/* Claims Breakdown */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 px-1">
              <span className="uppercase font-semibold tracking-wider">
                AUDITED CLAIMS ({auditedCase.claims?.length || 0})
              </span>
              <span className="text-[10px] text-slate-500">
                Rule: NO EVIDENCE → NO CLAIM
              </span>
            </div>

            <div className="space-y-2">
              {auditedCase.claims.map((claimItem, idx) => {
                const eids = claimItem.evidence_ids || claimItem.evidenceIds || [];
                const isIntegrityOk = Boolean(
                  claimItem.evidence_integrity_verified ??
                    claimItem.evidenceIntegrityVerified
                );

                return (
                  <div
                    key={idx}
                    className="p-3.5 rounded-lg bg-slate-950/80 border border-slate-800 space-y-2 font-mono text-xs hover:border-slate-700 transition-colors"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-slate-100 font-sans font-medium text-xs">
                        {claimItem.claim}
                      </div>
                      {getStatusBadge(claimItem.status)}
                    </div>

                    <div className="flex flex-wrap items-center gap-3 text-[11px] text-slate-400">
                      <div className="flex items-center gap-1.5">
                        <span>Evidence:</span>
                        {eids.length > 0 ? (
                          eids.map((eid) => (
                            <span
                              key={eid}
                              className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 text-[10px]"
                            >
                              {eid}
                            </span>
                          ))
                        ) : (
                          <span className="text-rose-400 italic">None</span>
                        )}
                      </div>

                      {eids.length > 0 && (
                        <div className="flex items-center gap-1 text-[10px]">
                          <Fingerprint className="w-3 h-3 text-emerald-400" />
                          <span
                            className={
                              isIntegrityOk
                                ? 'text-emerald-400'
                                : 'text-rose-400 font-bold'
                            }
                          >
                            {isIntegrityOk ? 'SHA-256 Verified' : 'Integrity Failed'}
                          </span>
                        </div>
                      )}
                    </div>

                    <div className="text-[11px] text-slate-300 font-sans pt-1 border-t border-slate-900 leading-relaxed">
                      <span className="text-slate-400 font-mono text-[10px] uppercase">
                        Reason:{' '}
                      </span>
                      {claimItem.reason}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Contradictions, Uncertainties & Unsupported Claims Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Contradictions */}
            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-2 font-mono">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">
                Contradictions ({auditedCase.contradictions?.length || 0})
              </span>
              {auditedCase.contradictions && auditedCase.contradictions.length > 0 ? (
                <ul className="space-y-1 text-[11px] text-amber-300/90 font-sans list-disc list-inside">
                  {auditedCase.contradictions.map((c, idx) => (
                    <li key={idx} className="leading-snug">
                      {c}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-[11px] text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> None detected
                </div>
              )}
            </div>

            {/* Uncertainties */}
            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-2 font-mono">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">
                Uncertainties ({auditedCase.uncertainties?.length || 0})
              </span>
              {auditedCase.uncertainties && auditedCase.uncertainties.length > 0 ? (
                <ul className="space-y-1 text-[11px] text-yellow-300/90 font-sans list-disc list-inside">
                  {auditedCase.uncertainties.map((u, idx) => (
                    <li key={idx} className="leading-snug">
                      {u}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-[11px] text-slate-500 italic">None exposed</div>
              )}
            </div>

            {/* Unsupported Claims */}
            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-2 font-mono">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">
                Unsupported Claims ({auditedCase.unsupported_claims?.length || 0})
              </span>
              {auditedCase.unsupported_claims &&
              auditedCase.unsupported_claims.length > 0 ? (
                <ul className="space-y-1 text-[11px] text-rose-300/90 font-sans list-disc list-inside">
                  {auditedCase.unsupported_claims.map((un, idx) => (
                    <li key={idx} className="leading-snug">
                      {un}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-[11px] text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> All claims proven
                </div>
              )}
            </div>
          </div>

          {/* Collapsible Tool Executions Section */}
          {auditedCase.tool_executions && auditedCase.tool_executions.length > 0 && (
            <div className="rounded-lg bg-slate-950/70 border border-slate-800/80 p-3 font-mono text-xs">
              <button
                type="button"
                onClick={() => setShowTools(!showTools)}
                className="w-full flex items-center justify-between text-left text-slate-300 hover:text-slate-100"
              >
                <div className="flex items-center gap-1.5">
                  <Wrench className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="font-bold text-[11px] uppercase tracking-wider">
                    Audited Tool Executions ({auditedCase.tool_executions.length} Recorded)
                  </span>
                </div>
                {showTools ? (
                  <ChevronDown className="w-4 h-4 text-slate-400" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-slate-400" />
                )}
              </button>

              {showTools && (
                <div className="mt-3 pt-3 border-t border-slate-800 space-y-2">
                  {auditedCase.tool_executions.map((te, idx) => (
                    <div
                      key={idx}
                      className="p-2.5 rounded bg-slate-900/60 border border-slate-800 flex items-center justify-between text-[11px]"
                    >
                      <div className="flex items-center gap-2">
                        <span className="px-1.5 py-0.5 rounded bg-slate-950 text-cyan-300 border border-slate-700 text-[10px]">
                          {te.tool_name || te.toolName}
                        </span>
                        <span className="text-slate-400 text-[10px]">ID: {te.id}</span>
                      </div>
                      <div className="flex items-center gap-2 text-slate-400 text-[10px]">
                        {te.evidence_id || te.evidenceId ? (
                          <span className="text-emerald-400">
                            Evidence: {te.evidence_id || te.evidenceId}
                          </span>
                        ) : (
                          <span className="text-slate-500">No Evidence</span>
                        )}
                        <span>{te.timestamp}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
