import React, { useState, useEffect, useCallback } from 'react';
import type {
  CriticReview,
  ClaimInput,
  ClaimStatus,
} from '../../types/soc';
import { socApi } from '../../lib/api';
import {
  ShieldAlert,
  ShieldCheck,
  AlertTriangle,
  Flame,
  FileQuestion,
  RefreshCw,
  Plus,
  Trash2,
  Info,
  CheckCircle2,
  XCircle,
  Clock,
  Sparkles,
  Search,
} from 'lucide-react';
import { Button } from '../ui/Button';
import { cn } from '../../lib/utils';

interface CriticSectionProps {
  investigationId: string;
}

export const CriticSection: React.FC<CriticSectionProps> = ({ investigationId }) => {
  const [review, setReview] = useState<CriticReview | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isEvaluating, setIsEvaluating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Interactive Draft Form State
  const [showTester, setShowTester] = useState<boolean>(false);
  const [draftConclusion, setDraftConclusion] = useState<string>(
    'This definitely proves an APT attack by Threat Actor X.'
  );
  const [claimsList, setClaimsList] = useState<ClaimInput[]>([
    {
      claim: 'PowerShell execution occurred on PC-DB-TEST',
      evidence_ids: ['E-001'],
    },
    {
      claim: 'Threat actor is Threat Actor X',
      evidence_ids: [],
    },
  ]);

  const fetchLatestReview = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await socApi.getCriticReview(investigationId);
      setReview(data);
    } catch (err: any) {
      console.error('Failed to load critic review:', err);
      setError(err?.message || 'Failed to load critic review');
    } finally {
      setIsLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    fetchLatestReview();
  }, [fetchLatestReview]);

  const handleRunEvaluation = async (conclusionText?: string, customClaims?: ClaimInput[]) => {
    setIsEvaluating(true);
    setError(null);
    try {
      const text = conclusionText !== undefined ? conclusionText : draftConclusion;
      const claimsToEval = customClaims !== undefined ? customClaims : claimsList;

      const result = await socApi.evaluateCritic(investigationId, {
        draft_conclusion: text,
        claims: claimsToEval,
      });
      setReview(result);
    } catch (err: any) {
      console.error('Failed to evaluate critic draft:', err);
      setError(err?.message || 'Critic evaluation failed');
    } finally {
      setIsEvaluating(false);
    }
  };

  const handleApplyPreset = (presetType: 'ATTRIBUTION' | 'CORROBORATED' | 'CONTRADICTION') => {
    if (presetType === 'ATTRIBUTION') {
      const text = 'This is an APT attack by Threat Actor X.';
      const claims: ClaimInput[] = [
        {
          claim: 'PowerShell execution occurred on PC-DB-TEST',
          evidence_ids: ['E-001'],
        },
        {
          claim: 'Threat actor is Threat Actor X',
          evidence_ids: [],
        },
      ];
      setDraftConclusion(text);
      setClaimsList(claims);
      handleRunEvaluation(text, claims);
    } else if (presetType === 'CORROBORATED') {
      const text = 'Suspicious PowerShell execution observed on PC-DB-TEST.';
      const claims: ClaimInput[] = [
        {
          claim: 'PowerShell execution occurred on PC-DB-TEST',
          evidence_ids: ['E-001'],
        },
      ];
      setDraftConclusion(text);
      setClaimsList(claims);
      handleRunEvaluation(text, claims);
    } else if (presetType === 'CONTRADICTION') {
      const text = 'Malicious PowerShell execution occurred on host.';
      const claims: ClaimInput[] = [
        {
          claim: 'Malicious PowerShell execution occurred on host',
          evidence_ids: ['E-049', 'E-053'],
        },
      ];
      setDraftConclusion(text);
      setClaimsList(claims);
      handleRunEvaluation(text, claims);
    }
  };

  const getStatusBadge = (status: ClaimStatus | string) => {
    switch (status) {
      case 'SUPPORTED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-950/70 text-emerald-300 border border-emerald-700/60 uppercase flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            SUPPORTED
          </span>
        );
      case 'UNSUPPORTED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/70 text-rose-300 border border-rose-700/60 uppercase flex items-center gap-1">
            <XCircle className="w-3 h-3 text-rose-400" />
            UNSUPPORTED
          </span>
        );
      case 'CONTRADICTED':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/70 text-amber-300 border border-amber-700/60 uppercase flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            CONTRADICTED
          </span>
        );
      case 'UNCERTAIN':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-yellow-950/70 text-yellow-300 border border-yellow-700/60 uppercase flex items-center gap-1">
            <FileQuestion className="w-3 h-3 text-yellow-400" />
            UNCERTAIN
          </span>
        );
      case 'INVALID_EVIDENCE_REFERENCE':
        return (
          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-950/70 text-purple-300 border border-purple-700/60 uppercase flex items-center gap-1">
            <XCircle className="w-3 h-3 text-purple-400" />
            INVALID EVIDENCE
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

  const isRequiresRevision =
    review?.overall_status === 'REQUIRES_REVISION' ||
    review?.overallStatus === 'REQUIRES_REVISION';

  return (
    <div className="rounded-xl bg-[#090D16] border border-rose-900/40 p-4 space-y-4 shadow-xl">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-rose-950/70 border border-rose-700/50 text-rose-400">
              <Flame className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-rose-300 font-mono">
                  Critic / Red-Team Agent
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-rose-950/60 border border-rose-800/60 text-rose-300 font-semibold">
                  Module 3D
                </span>
                {review && (
                  <span
                    className={cn(
                      'text-[10px] font-mono px-2.5 py-0.5 rounded-full font-bold uppercase tracking-wide border flex items-center gap-1',
                      isRequiresRevision
                        ? 'bg-rose-950/80 border-rose-700/80 text-rose-300'
                        : 'bg-emerald-950/80 border-emerald-700/80 text-emerald-300'
                    )}
                  >
                    {isRequiresRevision ? (
                      <>
                        <AlertTriangle className="w-3 h-3" />
                        Status: REQUIRES REVISION
                      </>
                    ) : (
                      <>
                        <ShieldCheck className="w-3 h-3" />
                        Status: PASS
                      </>
                    )}
                  </span>
                )}
              </div>
            </div>
          </div>
          <p className="text-[11px] text-slate-400">
            Adversarial security reasoning checkpoint challenging draft conclusions against verifiable evidence.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <Button
            size="sm"
            variant="outline"
            onClick={() => setShowTester(!showTester)}
            className="h-8 text-xs font-mono border-slate-700 hover:bg-slate-800 text-slate-300 gap-1.5"
          >
            <Sparkles className="w-3.5 h-3.5 text-cyan-400" />
            {showTester ? 'Hide Challenge Tester' : 'Challenge Draft Conclusion'}
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={() => handleRunEvaluation()}
            disabled={isEvaluating || isLoading}
            className="h-8 text-xs font-mono border-rose-800/60 hover:bg-rose-950/40 text-rose-300 gap-1.5"
            title="Re-run deterministic Critic challenge"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isEvaluating && 'animate-spin')} />
            {isEvaluating ? 'Critiquing...' : 'Re-run Critic'}
          </Button>
        </div>
      </div>

      {/* Safety Notice */}
      <div className="flex items-start gap-2 p-2.5 rounded-lg bg-rose-950/20 border border-rose-800/40 text-[11px] text-rose-300/90 font-mono">
        <Info className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
        <span>
          <strong>Audit Principle:</strong> The Critic is a security reasoning checkpoint. It challenges claims, flags unsupported attribution, and demands evidence IDs. It <em>never</em> executes tools, runs commands, or mutates forensic evidence.
        </span>
      </div>

      {/* Interactive Challenge Tester Panel */}
      {showTester && (
        <div className="p-3.5 rounded-xl bg-slate-950/90 border border-slate-800 space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800/80">
            <span className="text-slate-300 font-bold uppercase text-[11px] flex items-center gap-1.5">
              <Search className="w-3.5 h-3.5 text-rose-400" />
              Adversarial Red-Team Challenge Tester
            </span>
            <div className="flex items-center gap-1 text-[10px]">
              <span className="text-slate-500">Presets:</span>
              <button
                type="button"
                onClick={() => handleApplyPreset('ATTRIBUTION')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-rose-300 border border-slate-700"
              >
                APT Attribution
              </button>
              <button
                type="button"
                onClick={() => handleApplyPreset('CORROBORATED')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-emerald-300 border border-slate-700"
              >
                Corroborated
              </button>
              <button
                type="button"
                onClick={() => handleApplyPreset('CONTRADICTION')}
                className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-amber-300 border border-slate-700"
              >
                Contradiction
              </button>
            </div>
          </div>

          <div className="space-y-1">
            <label className="text-[10px] text-slate-400 uppercase font-semibold">
              Investigator Draft Conclusion:
            </label>
            <input
              type="text"
              value={draftConclusion}
              onChange={(e) => setDraftConclusion(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded p-2 text-slate-200 text-xs focus:outline-none focus:border-rose-500 font-sans"
              placeholder="e.g. This definitely proves an APT attack by Threat Actor X."
            />
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase font-semibold">
              <span>Granular Claims & Evidence IDs:</span>
              <button
                type="button"
                onClick={() =>
                  setClaimsList([
                    ...claimsList,
                    { claim: '', evidence_ids: [] },
                  ])
                }
                className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1"
              >
                <Plus className="w-3 h-3" /> Add Claim
              </button>
            </div>

            {claimsList.map((c, idx) => (
              <div
                key={idx}
                className="grid grid-cols-1 md:grid-cols-12 gap-2 bg-slate-900/60 p-2 rounded border border-slate-800/80 items-center"
              >
                <div className="md:col-span-7">
                  <input
                    type="text"
                    value={c.claim}
                    onChange={(e) => {
                      const updated = [...claimsList];
                      updated[idx].claim = e.target.value;
                      setClaimsList(updated);
                    }}
                    placeholder="Claim text..."
                    className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-slate-200 text-xs font-sans"
                  />
                </div>
                <div className="md:col-span-4">
                  <input
                    type="text"
                    value={(c.evidence_ids || []).join(', ')}
                    onChange={(e) => {
                      const updated = [...claimsList];
                      updated[idx].evidence_ids = e.target.value
                        .split(',')
                        .map((s) => s.trim())
                        .filter(Boolean);
                      setClaimsList(updated);
                    }}
                    placeholder="Evidence IDs (e.g. E-001)"
                    className="w-full bg-slate-950 border border-slate-700 rounded px-2 py-1 text-cyan-300 text-xs font-mono"
                  />
                </div>
                <div className="md:col-span-1 text-right">
                  <button
                    type="button"
                    onClick={() => {
                      const updated = claimsList.filter((_, i) => i !== idx);
                      setClaimsList(updated);
                    }}
                    className="text-slate-500 hover:text-rose-400 p-1"
                    title="Remove claim"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            ))}
          </div>

          <div className="pt-1 flex justify-end">
            <Button
              size="sm"
              onClick={() => handleRunEvaluation()}
              disabled={isEvaluating}
              className="bg-rose-700 hover:bg-rose-600 text-white text-xs font-mono h-8"
            >
              <Flame className="w-3.5 h-3.5 mr-1" />
              {isEvaluating ? 'Evaluating Draft...' : 'Run Red-Team Challenge'}
            </Button>
          </div>
        </div>
      )}

      {/* Error Notice */}
      {error && (
        <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs font-mono text-rose-300 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Content Area */}
      {isLoading ? (
        <div className="p-8 text-center text-xs font-mono text-slate-400 space-y-2">
          <RefreshCw className="w-5 h-5 animate-spin mx-auto text-rose-400" />
          <div>Retrieving Critic / Red-Team evaluation...</div>
        </div>
      ) : !review ? (
        <div className="p-8 text-center rounded-xl bg-slate-950/40 border border-dashed border-slate-800 space-y-3">
          <Flame className="w-8 h-8 text-slate-600 mx-auto" />
          <div className="text-xs text-slate-300 font-mono">No Critic evaluation has been conducted yet.</div>
          <p className="text-[11px] text-slate-400 max-w-md mx-auto">
            Click &quot;Challenge Draft Conclusion&quot; to test investigator hypotheses against the forensic evidence ledger.
          </p>
          <Button
            size="sm"
            onClick={() => handleRunEvaluation()}
            disabled={isEvaluating}
            className="h-8 text-xs font-mono bg-rose-700 hover:bg-rose-600 text-white"
          >
            <Flame className="w-3.5 h-3.5 mr-1.5" />
            Execute Initial Red-Team Check
          </Button>
        </div>
      ) : (
        <div className="space-y-4">
          {/* Draft Conclusion Card */}
          <div className="p-3 rounded-xl bg-slate-950/80 border border-slate-800 font-mono space-y-1">
            <div className="flex items-center justify-between text-[10px] text-slate-400 uppercase font-semibold">
              <span>Investigator Draft Conclusion:</span>
              {review.created_at && (
                <span className="flex items-center gap-1 text-slate-500 font-normal">
                  <Clock className="w-3 h-3" />
                  Reviewed: {new Date(review.created_at).toLocaleTimeString()}
                </span>
              )}
            </div>
            <div className="text-xs text-slate-200 font-sans font-medium pl-0.5 leading-relaxed">
              &quot;{review.draft_conclusion || review.draftConclusion}&quot;
            </div>
          </div>

          {/* Objections Section (Prominently displayed) */}
          {review.objections && review.objections.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-1.5 text-xs font-mono uppercase tracking-wider text-rose-300 font-bold">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                <span>CRITIC OBJECTIONS ({review.objections.length})</span>
              </div>

              <div className="space-y-2">
                {review.objections.map((obj, idx) => {
                  const evIds = obj.evidence_ids || obj.evidenceIds || [];
                  return (
                    <div
                      key={idx}
                      className="rounded-lg bg-rose-950/20 border border-rose-800/60 p-3 space-y-1.5 font-mono text-xs"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-[11px] font-bold text-rose-300 flex items-center gap-1">
                          ⚠ {obj.category ? obj.category.replace(/_/g, ' ') : 'Objection'}
                        </span>
                        {getStatusBadge(obj.status)}
                      </div>

                      <div className="text-slate-200 font-sans text-xs">
                        <strong>Claim:</strong> &quot;{obj.claim}&quot;
                      </div>

                      <div className="text-[11px] text-slate-400">
                        <strong>Evidence:</strong>{' '}
                        {evIds.length > 0 ? (
                          <span className="text-cyan-300">{evIds.join(', ')}</span>
                        ) : (
                          <span className="text-rose-400 italic">None provided</span>
                        )}
                      </div>

                      <div className="text-[11px] text-rose-200/90 pt-1 border-t border-rose-900/40 font-sans">
                        <strong>Reason:</strong> {obj.reason}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Missing Evidence / Contradictions / Overclaims Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {/* Missing Evidence */}
            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-2 font-mono">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">
                Missing Evidence ({review.missing_evidence?.length || 0})
              </span>
              {review.missing_evidence && review.missing_evidence.length > 0 ? (
                <ul className="space-y-1 text-[11px] text-rose-300/90 font-sans list-disc list-inside">
                  {review.missing_evidence.map((item, idx) => (
                    <li key={idx} className="leading-snug">
                      {item}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-[11px] text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> None missing
                </div>
              )}
            </div>

            {/* Contradictions */}
            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-2 font-mono">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">
                Contradictions ({review.contradictions?.length || 0})
              </span>
              {review.contradictions && review.contradictions.length > 0 ? (
                <ul className="space-y-1 text-[11px] text-amber-300/90 font-sans list-disc list-inside">
                  {review.contradictions.map((item, idx) => (
                    <li key={idx} className="leading-snug">
                      {item}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-[11px] text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> No conflicts found
                </div>
              )}
            </div>

            {/* Overclaims */}
            <div className="p-3 rounded-lg bg-slate-950/70 border border-slate-800 space-y-2 font-mono">
              <span className="text-[10px] text-slate-400 uppercase font-semibold block">
                Overclaims ({review.overclaims?.length || 0})
              </span>
              {review.overclaims && review.overclaims.length > 0 ? (
                <ul className="space-y-1 text-[11px] text-yellow-300/90 font-sans list-disc list-inside">
                  {review.overclaims.map((item, idx) => (
                    <li key={idx} className="leading-snug">
                      {item}
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="text-[11px] text-emerald-400 flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> No overclaims
                </div>
              )}
            </div>
          </div>

          {/* Claim-by-Claim Detailed Evaluation Breakdown */}
          <div className="space-y-2 pt-2 border-t border-slate-800">
            <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400 block font-semibold">
              Claim-by-Claim Evaluation ({review.claims_evaluation?.length || 0} Evaluated)
            </span>

            <div className="space-y-2">
              {(review.claims_evaluation || review.claimsEvaluation || []).map((evalItem, idx) => {
                const refIds = evalItem.evidence_ids || evalItem.evidenceIds || [];
                return (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-slate-950/90 border border-slate-800/90 space-y-1.5 font-mono text-xs"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-slate-100 font-sans font-medium text-xs">
                        {evalItem.claim}
                      </div>
                      {getStatusBadge(evalItem.status)}
                    </div>

                    <div className="flex items-center gap-2 text-[11px] text-slate-400">
                      <span>Referenced Evidence:</span>
                      {refIds.length > 0 ? (
                        <div className="flex items-center gap-1">
                          {refIds.map((eid) => (
                            <span
                              key={eid}
                              className="px-1.5 py-0.5 rounded bg-slate-900 border border-slate-700 text-cyan-300 text-[10px]"
                            >
                              {eid}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="text-rose-400 italic">None</span>
                      )}
                    </div>

                    <div className="text-[11px] text-slate-300 font-sans pt-1 border-t border-slate-900 leading-relaxed">
                      <span className="text-slate-400 font-mono text-[10px] uppercase">Reason: </span>
                      {evalItem.reason}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
