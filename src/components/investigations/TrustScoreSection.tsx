import React, { useState, useEffect, useCallback } from 'react';
import type { TrustScore as TrustScoreData } from '../../types/soc';
import { socApi } from '../../lib/api';
import {
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Info,
  Scale,
  MinusCircle,
  HelpCircle,
} from 'lucide-react';
import { Button } from '../ui/Button';
import { TrustScore } from '../ui/TrustScore';
import { cn } from '../../lib/utils';

interface TrustScoreSectionProps {
  investigationId: string;
}

export const TrustScoreSection: React.FC<TrustScoreSectionProps> = ({
  investigationId,
}) => {
  const [trustScore, setTrustScore] = useState<TrustScoreData | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchScore = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await socApi.getTrustScore(investigationId);
      setTrustScore(data);
    } catch (err: any) {
      console.error('Failed to load trust score:', err);
      setError(err?.message || 'Failed to load trust score');
    } finally {
      setIsLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    fetchScore();
  }, [fetchScore]);

  const getVerdictBadge = (verdict: string) => {
    switch (verdict) {
      case 'HIGH_TRUST':
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 uppercase flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-emerald-400" />
            HIGH TRUST
          </span>
        );
      case 'MODERATE_TRUST':
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-cyan-950/80 text-cyan-300 border border-cyan-700/80 uppercase flex items-center gap-1">
            <ShieldCheck className="w-3 h-3 text-cyan-400" />
            MODERATE TRUST
          </span>
        );
      case 'LOW_TRUST':
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-amber-950/80 text-amber-300 border border-amber-700/80 uppercase flex items-center gap-1">
            <AlertTriangle className="w-3 h-3 text-amber-400" />
            LOW TRUST
          </span>
        );
      case 'UNTRUSTED':
      default:
        return (
          <span className="px-2.5 py-0.5 rounded-full text-[10px] font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-700/80 uppercase flex items-center gap-1">
            <ShieldAlert className="w-3 h-3 text-rose-400" />
            UNTRUSTED
          </span>
        );
    }
  };

  const getScoreColor = (score: number) => {
    if (score >= 85) return 'text-emerald-400 border-emerald-800/80 bg-emerald-950/40';
    if (score >= 65) return 'text-cyan-400 border-cyan-800/80 bg-cyan-950/40';
    if (score >= 40) return 'text-amber-400 border-amber-800/80 bg-amber-950/40';
    return 'text-rose-400 border-rose-800/80 bg-rose-950/40';
  };

  return (
    <div className="rounded-xl bg-[#090D16] border border-cyan-900/40 p-4 space-y-4 shadow-xl font-mono">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-cyan-950/70 border border-cyan-700/50 text-cyan-400">
              <Scale className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                  TRUST SCORE
                </span>
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 font-semibold">
                  Module 3G
                </span>
                {trustScore && getVerdictBadge(trustScore.explanation.verdict)}
              </div>
            </div>
          </div>
          <p className="text-[11px] text-slate-400">
            Evidence & Audit Quality Score — Measures evidentiary backing, cryptographic integrity, and audit completeness.
          </p>
        </div>

        {/* Score Display & Refresh */}
        <div className="flex items-center gap-3 self-start sm:self-auto">
          {trustScore && (
            <div
              className={cn(
                'px-3 py-1 rounded-lg border flex items-center gap-1.5',
                getScoreColor(trustScore.trust_score ?? trustScore.trustScore ?? 0)
              )}
            >
              <span className="text-xs text-slate-400 uppercase tracking-wide">Score:</span>
              <span className="text-base font-bold">
                {trustScore.trust_score ?? trustScore.trustScore}
              </span>
              <span className="text-xs text-slate-400">/ 100</span>
            </div>
          )}
          <Button
            size="sm"
            variant="outline"
            onClick={fetchScore}
            disabled={isLoading}
            className="h-8 text-xs font-mono border-cyan-800/60 hover:bg-cyan-950/40 text-cyan-300 gap-1.5"
            title="Recalculate deterministic Trust Score"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isLoading && 'animate-spin')} />
            {isLoading ? 'Calculating...' : 'Recalculate'}
          </Button>
        </div>
      </div>

      {/* Safety / Purpose Disclaimer */}
      <div className="flex items-start gap-2 p-2.5 rounded-lg bg-cyan-950/20 border border-cyan-800/40 text-[11px] text-cyan-300/90">
        <Info className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
        <span>
          <strong>Evidence & Audit Quality Score:</strong> This score strictly measures evidentiary proof quality, SHA-256 integrity, and multi-agent audit completeness. It does <strong>NOT</strong> represent probability of attack or threat severity.
        </span>
      </div>

      {/* Error state */}
      {error && (
        <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs text-rose-300 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Content Area */}
      {isLoading ? (
        <div className="p-6 text-center text-xs text-slate-400 space-y-2">
          <RefreshCw className="w-5 h-5 animate-spin mx-auto text-cyan-400" />
          <div>Computing deterministic evidence trust score...</div>
        </div>
      ) : trustScore ? (
        <div className="space-y-4">
          {/* Radial Circular Progress & 6-Factor Breakdown (Module 3Y) */}
          <TrustScore
            trustScore={trustScore}
            size="md"
            showBreakdown={true}
            showVerdict={false}
            title="Explainable Trust Score & Six Breakdown Factors"
          />

          {/* Base Scoring Components */}
          <div className="space-y-2">
            <span className="text-[11px] font-bold text-slate-300 uppercase tracking-wider block">
              Core Quality Components (Max 100 Points)
            </span>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {(trustScore.score_components || trustScore.scoreComponents || []).map(
                (comp, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-slate-900/60 border border-slate-800 space-y-1 text-xs"
                  >
                    <div className="flex items-center justify-between">
                      <span className="font-semibold text-slate-200 flex items-center gap-1.5">
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                        {comp.name}
                      </span>
                      <span className="font-bold text-emerald-400">
                        +{comp.contribution} / {comp.weight} pts
                      </span>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      {comp.explanation}
                    </p>
                  </div>
                )
              )}
            </div>
          </div>

          {/* Penalties Section (if any) */}
          {(trustScore.penalties || []).length > 0 ? (
            <div className="space-y-2 pt-2 border-t border-slate-800/80">
              <span className="text-[11px] font-bold text-rose-300 uppercase tracking-wider block flex items-center gap-1.5">
                <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
                Deduction Penalties ({trustScore.penalties.length} Active)
              </span>
              <div className="space-y-2">
                {trustScore.penalties.map((pen, idx) => (
                  <div
                    key={idx}
                    className="p-2.5 rounded-lg bg-rose-950/20 border border-rose-900/50 flex items-center justify-between text-xs"
                  >
                    <div className="space-y-0.5">
                      <span className="font-semibold text-rose-200 flex items-center gap-1.5">
                        <MinusCircle className="w-3.5 h-3.5 text-rose-400" />
                        {pen.name} ({pen.value} incident{pen.value !== 1 ? 's' : ''})
                      </span>
                      <p className="text-[11px] text-rose-300/80">{pen.explanation}</p>
                    </div>
                    <span className="font-bold text-rose-400 text-sm whitespace-nowrap ml-3">
                      -{pen.deduction} pts
                    </span>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="p-2.5 rounded-lg bg-emerald-950/20 border border-emerald-900/40 text-[11px] text-emerald-300 flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>Zero deduction penalties applied. No contradictions or unsupported claims detected.</span>
            </div>
          )}

          {/* Key Findings & Audit Notes */}
          {trustScore.explanation.key_findings && trustScore.explanation.key_findings.length > 0 && (
            <div className="space-y-1.5 pt-2 border-t border-slate-800/80 text-[11px]">
              <span className="font-bold text-slate-300 uppercase tracking-wider block">
                Evidence Evaluation Findings
              </span>
              <ul className="space-y-1 text-slate-400">
                {trustScore.explanation.key_findings.map((f, idx) => (
                  <li key={idx} className="flex items-start gap-1.5">
                    <span className="text-cyan-400">•</span>
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Formula Specification */}
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-[10px] text-slate-400 space-y-1">
            <span className="font-bold text-slate-300 flex items-center gap-1">
              <HelpCircle className="w-3 h-3 text-cyan-400" />
              Deterministic Formula:
            </span>
            <div className="text-cyan-300/90 overflow-x-auto whitespace-pre-wrap">
              {trustScore.explanation.formula}
            </div>
          </div>
        </div>
      ) : (
        <div className="p-6 text-center text-xs text-slate-500">
          No audited case available to compute trust score. Run the Auditor Agent first.
        </div>
      )}
    </div>
  );
};
