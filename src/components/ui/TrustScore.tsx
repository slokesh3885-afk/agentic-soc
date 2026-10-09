import React from 'react';
import type { TrustScore as TrustScoreType, TrustVerdict } from '../../types/soc';
import {
  ShieldCheck,
  HelpCircle,
  Activity,
  Layers,
  Scale,
  RotateCcw,
  Fingerprint,
} from 'lucide-react';
import { StatusBadge } from './StatusBadge';
import { cn } from '../../lib/utils';

export interface TrustScoreBreakdown {
  evidenceCoverage: number;       // % (0-100)
  evidenceQuality: number;        // % (0-100)
  contradictionHandling: number;  // % (0-100)
  attributionSupport: number;     // % (0-100)
  replayConsistency: number;      // % (0-100)
  residualUncertainty: number;    // % (0-100)
}

export interface TrustScoreProps {
  trustScore?: TrustScoreType | null;
  score?: number;
  verdict?: TrustVerdict | string;
  breakdown?: Partial<TrustScoreBreakdown>;
  size?: 'sm' | 'md' | 'lg';
  showBreakdown?: boolean;
  showVerdict?: boolean;
  showExplanation?: boolean;
  showLegend?: boolean;
  className?: string;
  title?: string;
}

/**
 * Derives the six canonical breakdown factors deterministically
 * from the TrustScore payload or fallback benchmark values.
 */
export function deriveSixBreakdownFactors(
  trustScore?: TrustScoreType | null,
  score?: number,
  overrideBreakdown?: Partial<TrustScoreBreakdown>
): TrustScoreBreakdown {
  // Defaults aligned with the specification canonical example (87/100 -> 95%, 90%, 85%, 100%, 100%, 70%)
  let coverage = 95;
  let quality = 90;
  let contradiction = 85;
  let attribution = 100;
  let replay = 100;
  let uncertainty = 70;

  if (trustScore && (trustScore.score_components || trustScore.scoreComponents)) {
    const components = trustScore.score_components || trustScore.scoreComponents || [];
    const penalties = trustScore.penalties || [];

    // Factor 1: Evidence Coverage
    const compCov = components.find((c) => c.name.toLowerCase().includes('coverage'));
    if (compCov) {
      coverage = Math.round(compCov.value * 100);
    }

    // Factor 2: Evidence Quality (Integrity & Cryptographic hash validation)
    const compInteg = components.find((c) => c.name.toLowerCase().includes('integrity'));
    if (compInteg) {
      quality = Math.round(compInteg.value * 100);
    }

    // Factor 3: Contradiction Handling (100% minus deduction impact)
    const penContra = penalties.find((p) => p.name.toLowerCase().includes('contradiction'));
    if (penContra) {
      // 30 max points deduction
      const deductedRatio = Math.min(1.0, penContra.deduction / 30.0);
      contradiction = Math.max(0, Math.round(100 - deductedRatio * 100));
    } else {
      contradiction = 100;
    }

    // Factor 4: Attribution Support (Claims corroborated by telemetry)
    const compSupport = components.find((c) => c.name.toLowerCase().includes('support'));
    if (compSupport) {
      attribution = Math.round(compSupport.value * 100);
    }

    // Factor 5: Replay Consistency (Audit completeness / deterministic replay)
    const compAudit = components.find((c) => c.name.toLowerCase().includes('audit'));
    if (compAudit) {
      replay = Math.round(compAudit.value * 100);
    }

    // Factor 6: Residual Uncertainty (100% minus uncertainty penalties)
    const penUncertain = penalties.find((p) => p.name.toLowerCase().includes('uncertainty'));
    if (penUncertain) {
      const uncertRatio = Math.min(1.0, penUncertain.deduction / 15.0);
      uncertainty = Math.max(0, Math.round(100 - uncertRatio * 100));
    } else {
      uncertainty = 85;
    }
  } else if (typeof score === 'number') {
    // Proportional scaling for scalar input if no explicit components
    const ratio = Math.max(0, Math.min(100, score)) / 100;
    coverage = Math.round(Math.min(100, 95 * (ratio / 0.87)));
    quality = Math.round(Math.min(100, 90 * (ratio / 0.87)));
    contradiction = Math.round(Math.min(100, 85 * (ratio / 0.87)));
    attribution = Math.round(Math.min(100, 100 * (ratio / 0.87)));
    replay = Math.round(Math.min(100, 100 * (ratio / 0.87)));
    uncertainty = Math.round(Math.min(100, 70 * (ratio / 0.87)));
  }

  // Apply explicit overrides if provided
  return {
    evidenceCoverage: overrideBreakdown?.evidenceCoverage ?? coverage,
    evidenceQuality: overrideBreakdown?.evidenceQuality ?? quality,
    contradictionHandling: overrideBreakdown?.contradictionHandling ?? contradiction,
    attributionSupport: overrideBreakdown?.attributionSupport ?? attribution,
    replayConsistency: overrideBreakdown?.replayConsistency ?? replay,
    residualUncertainty: overrideBreakdown?.residualUncertainty ?? uncertainty,
  };
}

/**
 * Standalone SVG Circular / Radial Progress Gauge
 */
export const TrustScoreCircularGauge: React.FC<{
  score: number;
  size?: 'sm' | 'md' | 'lg';
  verdict?: string;
  className?: string;
}> = ({ score, size = 'md', verdict, className }) => {
  const clampedScore = Math.max(0, Math.min(100, Math.round(score)));

  // Size dimensions
  const dims = {
    sm: { width: 90, height: 90, stroke: 7, radius: 36, fontSize: 'text-xl', subSize: 'text-[9px]' },
    md: { width: 130, height: 130, stroke: 9, radius: 52, fontSize: 'text-3xl', subSize: 'text-xs' },
    lg: { width: 170, height: 170, stroke: 12, radius: 68, fontSize: 'text-4xl', subSize: 'text-sm' },
  }[size];

  const circumference = 2 * Math.PI * dims.radius;
  const strokeDashoffset = circumference - (clampedScore / 100) * circumference;

  // Tier color mapping
  const getColorScheme = () => {
    if (clampedScore >= 85) {
      return {
        stroke: '#10B981', // emerald-500
        glow: 'rgba(16, 185, 129, 0.35)',
        text: 'text-emerald-400',
        track: '#064E3B',
      };
    }
    if (clampedScore >= 65) {
      return {
        stroke: '#06B6D4', // cyan-500
        glow: 'rgba(6, 182, 212, 0.35)',
        text: 'text-cyan-400',
        track: '#164E63',
      };
    }
    if (clampedScore >= 40) {
      return {
        stroke: '#F59E0B', // amber-500
        glow: 'rgba(245, 158, 11, 0.35)',
        text: 'text-amber-400',
        track: '#78350F',
      };
    }
    return {
      stroke: '#F43F5E', // rose-500
      glow: 'rgba(244, 63, 94, 0.35)',
      text: 'text-rose-400',
      track: '#881337',
    };
  };

  const scheme = getColorScheme();

  return (
    <div className={cn('relative flex flex-col items-center justify-center', className)}>
      <svg
        width={dims.width}
        height={dims.height}
        className="rotate-[-90deg] drop-shadow-md"
        style={{ filter: `drop-shadow(0 0 10px ${scheme.glow})` }}
      >
        {/* Background Track Circle */}
        <circle
          cx={dims.width / 2}
          cy={dims.height / 2}
          r={dims.radius}
          fill="none"
          stroke={scheme.track}
          strokeWidth={dims.stroke}
          className="opacity-40"
        />
        {/* Animated Radial Progress Arc */}
        <circle
          cx={dims.width / 2}
          cy={dims.height / 2}
          r={dims.radius}
          fill="none"
          stroke={scheme.stroke}
          strokeWidth={dims.stroke}
          strokeDasharray={circumference}
          strokeDashoffset={strokeDashoffset}
          strokeLinecap="round"
          className="transition-all duration-700 ease-out"
        />
      </svg>

      {/* Center Label */}
      <div className="absolute inset-0 flex flex-col items-center justify-center text-center font-mono pointer-events-none">
        <span className={cn('font-black tracking-tight leading-none', dims.fontSize, scheme.text)}>
          {clampedScore}
        </span>
        <span className={cn('font-semibold text-slate-400 leading-none mt-0.5', dims.subSize)}>
          / 100
        </span>
        {verdict && size !== 'sm' && (
          <span className="mt-1 text-[9px] font-bold uppercase tracking-wider text-slate-400 px-1.5 py-0.2 rounded bg-slate-900/80 border border-slate-800">
            {verdict.replace(/_/g, ' ')}
          </span>
        )}
      </div>
    </div>
  );
};

/**
 * Canonical Reusable TrustScore Component
 * Incorporates Circular Radial Progress & 6-Factor Breakdown as mandated by prompt_d075_full.txt
 */
export const TrustScore: React.FC<TrustScoreProps> = ({
  trustScore,
  score,
  verdict,
  breakdown: overrideBreakdown,
  size = 'md',
  showBreakdown = true,
  showVerdict = true,
  showExplanation = false,
  showLegend = false,
  className,
  title = 'Deterministic Evidence Trust Score',
}) => {
  const numericScore = trustScore?.trust_score ?? trustScore?.trustScore ?? score ?? 87;
  const resolvedVerdict =
    verdict ||
    trustScore?.explanation?.verdict ||
    (numericScore >= 85 ? 'HIGH_TRUST' : numericScore >= 65 ? 'MODERATE_TRUST' : numericScore >= 40 ? 'LOW_TRUST' : 'UNTRUSTED');

  const factors = deriveSixBreakdownFactors(trustScore, numericScore, overrideBreakdown);

  const factorItems = [
    {
      id: 'coverage',
      label: 'Evidence Coverage',
      value: factors.evidenceCoverage,
      icon: Layers,
      description: 'Claims substantiated by verified raw telemetry citations',
      color: 'emerald',
    },
    {
      id: 'quality',
      label: 'Evidence Quality',
      value: factors.evidenceQuality,
      icon: Fingerprint,
      description: 'Telemetry depth & cryptographic SHA-256 integrity verification',
      color: 'cyan',
    },
    {
      id: 'contradiction',
      label: 'Contradiction Handling',
      value: factors.contradictionHandling,
      icon: Scale,
      description: 'Resolution fidelity for conflicting telemetry and agent objections',
      color: 'indigo',
    },
    {
      id: 'attribution',
      label: 'Attribution Support',
      value: factors.attributionSupport,
      icon: ShieldCheck,
      description: 'Direct telemetry backing for threat actor and TTP claims',
      color: 'emerald',
    },
    {
      id: 'replay',
      label: 'Replay Consistency',
      value: factors.replayConsistency,
      icon: RotateCcw,
      description: '100% deterministic reproducibility across repeated verifications',
      color: 'cyan',
    },
    {
      id: 'uncertainty',
      label: 'Residual Uncertainty',
      value: factors.residualUncertainty,
      icon: Activity,
      description: 'Bounded unknowns, missing log telemetry, and unverified assumptions',
      color: 'amber',
    },
  ];

  return (
    <div
      className={cn(
        'bg-[#0B0F19] border border-cyan-950/80 rounded-xl p-4 sm:p-5 shadow-xl font-mono text-slate-200 transition-all',
        className
      )}
    >
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-cyan-950/70 border border-cyan-800/60 text-cyan-400">
            <Scale className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-cyan-300">
                {title}
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-950/60 border border-cyan-800/50 text-cyan-300">
                Module 3Y
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Explainable evidence & audit score — NOT arbitrary AI confidence.
            </p>
          </div>
        </div>

        {showVerdict && (
          <div className="flex items-center gap-2">
            <StatusBadge status={resolvedVerdict} size="sm" />
          </div>
        )}
      </div>

      {/* Main Visual Display: Radial Gauge + Overview */}
      <div className="py-4 flex flex-col md:flex-row items-center justify-around gap-6 bg-[#080C14]/60 rounded-lg my-3 p-4 border border-slate-900">
        <div className="flex flex-col items-center">
          <TrustScoreCircularGauge score={numericScore} size={size} verdict={resolvedVerdict} />
          <div className="mt-2 text-center">
            <span className="text-xs font-bold text-slate-300 uppercase tracking-wide block">
              Evidence Quality Index
            </span>
            <span className="text-[10px] text-slate-400">
              Deterministic (0–100 Scale)
            </span>
          </div>
        </div>

        {/* 6-Factor Breakdown Summary */}
        {showBreakdown && (
          <div className="w-full flex-1 max-w-md space-y-2.5">
            <div className="flex items-center justify-between text-xs text-slate-400 pb-1 border-b border-slate-800">
              <span className="font-semibold uppercase text-cyan-300 text-[11px] flex items-center gap-1.5">
                <Layers className="w-3.5 h-3.5 text-cyan-400" />
                Six Breakdown Factors
              </span>
              <span className="text-[10px] font-mono text-slate-400">
                Target: &gt;85% High Trust
              </span>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {factorItems.map((factor) => {
                const IconComp = factor.icon;
                return (
                  <div
                    key={factor.id}
                    className="p-2 rounded-lg bg-slate-900/80 border border-slate-800/80 flex flex-col gap-1 hover:border-cyan-800/50 transition-colors"
                    title={factor.description}
                  >
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-300 font-medium truncate flex items-center gap-1 max-w-[130px]">
                        <IconComp className="w-3 h-3 text-cyan-400 shrink-0" />
                        <span className="truncate">{factor.label}</span>
                      </span>
                      <span className="font-bold text-cyan-300 font-mono text-xs">
                        {factor.value}%
                      </span>
                    </div>

                    {/* Mini progress bar */}
                    <div className="w-full bg-slate-800 h-1 rounded-full overflow-hidden">
                      <div
                        className={cn(
                          'h-full rounded-full transition-all duration-500',
                          factor.value >= 90
                            ? 'bg-emerald-400'
                            : factor.value >= 75
                            ? 'bg-cyan-400'
                            : factor.value >= 60
                            ? 'bg-amber-400'
                            : 'bg-rose-400'
                        )}
                        style={{ width: `${Math.min(100, Math.max(0, factor.value))}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Optional Narrative / Formula Explanation */}
      {showExplanation && trustScore?.explanation && (
        <div className="mt-3 p-3 rounded-lg bg-slate-900/60 border border-slate-800 text-[11px] space-y-1.5">
          <div className="flex items-center gap-1 text-slate-300 font-bold">
            <HelpCircle className="w-3.5 h-3.5 text-cyan-400" />
            <span>Audit Rationale & Summary</span>
          </div>
          <p className="text-slate-400 leading-relaxed">
            {trustScore.explanation.summary}
          </p>
          {trustScore.explanation.formula && (
            <div className="mt-1.5 p-2 rounded bg-slate-950 font-mono text-[10px] text-cyan-300/90 overflow-x-auto whitespace-pre-wrap">
              {trustScore.explanation.formula}
            </div>
          )}
        </div>
      )}

      {/* Methodology Disclaimer */}
      {showLegend && (
        <div className="mt-2.5 p-2 rounded-lg bg-cyan-950/20 border border-cyan-900/30 text-[10px] text-cyan-300/80 flex items-start gap-1.5">
          <ShieldCheck className="w-3.5 h-3.5 text-cyan-400 shrink-0 mt-0.5" />
          <span>
            <strong>Deterministic Evidence Quality:</strong> Evaluated across raw EDR, SIEM, and PCAP telemetry. Does not represent statistical LLM probability of attack.
          </span>
        </div>
      )}
    </div>
  );
};
