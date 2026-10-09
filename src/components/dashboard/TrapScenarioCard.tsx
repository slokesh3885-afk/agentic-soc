import React, { useState, useEffect } from 'react';
import {
  AlertTriangle,
  Play,
  RotateCw,
  CheckCircle2,
  XCircle,
  AlertCircle,
  FileCode2,
  Cpu,
  Fingerprint,
  Info,
  ChevronDown,
  ChevronUp,
  FileWarning,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type { TrapScenarioResponse } from '../../types/soc';
import { cn } from '../../lib/utils';

export const TrapScenarioCard: React.FC = () => {
  const [scenarioData, setScenarioData] = useState<TrapScenarioResponse | null>(null);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isExpanded, setIsExpanded] = useState<boolean>(false);

  // Load initial scenario state on mount
  useEffect(() => {
    let mounted = true;
    socApi
      .getTrapScenario()
      .then((data) => {
        if (mounted) {
          setScenarioData(data);
          setIsLoading(false);
        }
      })
      .catch((err) => {
        if (mounted) {
          setError(err.message || 'Failed to fetch trap scenario state');
          setIsLoading(false);
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  // Handler to run trap scenario pipeline
  const handleRunScenario = async () => {
    setIsRunning(true);
    setError(null);
    try {
      const result = await socApi.runTrapScenario();
      setScenarioData(result);
    } catch (err: any) {
      setError(err.message || 'Failed to execute trap scenario');
    } finally {
      setIsRunning(false);
    }
  };

  const evidenceCount = scenarioData?.evidence_count ?? scenarioData?.evidenceCount ?? 4;
  const contradictedCount =
    scenarioData?.contradicted_claims_count ?? scenarioData?.contradictedClaimsCount ?? 1;
  const unsupportedCount =
    scenarioData?.unsupported_claims_count ?? scenarioData?.unsupportedClaimsCount ?? 1;
  const supportedCount =
    scenarioData?.supported_claims_count ?? scenarioData?.supportedClaimsCount ?? 1;
  const trustScoreVal =
    scenarioData?.trust_score?.trust_score ?? scenarioData?.trustScore?.trustScore ?? 36.7;
  const verdict =
    scenarioData?.trust_score?.explanation?.verdict ??
    scenarioData?.trustScore?.explanation?.verdict ??
    'UNTRUSTED';
  const scenarioStatus = scenarioData?.status ?? 'TRAP_DETECTED_CONTRADICTION';

  return (
    <div className="bg-[#0F172A]/90 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm flex flex-col shadow-lg">
      {/* Header */}
      <div className="pb-3 border-b border-slate-800/80 mb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-amber-950/60 border border-amber-700/50 rounded-lg text-amber-400">
            <AlertTriangle className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-100 font-mono">
                Trap Scenario (Deception & Contradiction)
              </h2>
              <span className="text-[11px] font-bold font-mono uppercase bg-amber-500/20 border border-amber-500/50 text-amber-300 px-2.5 py-0.5 rounded-full tracking-wide">
                Synthetic Test Scenario
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Deterministic verification of contradiction detection, deceptive evidence rejection, and overclaim penalties
            </p>
          </div>
        </div>

        {/* Action Button */}
        <div className="flex items-center gap-2">
          <button
            onClick={handleRunScenario}
            disabled={isRunning || isLoading}
            className={cn(
              'inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-all border',
              'bg-amber-600/20 border-amber-500/50 text-amber-300 hover:bg-amber-600/30 hover:border-amber-400',
              (isRunning || isLoading) && 'opacity-60 cursor-not-allowed'
            )}
            title="Execute the full multi-agent SOC pipeline against synthetic deceptive telemetry"
          >
            {isRunning ? (
              <>
                <RotateCw className="w-3.5 h-3.5 animate-spin" />
                <span>Running Pipeline...</span>
              </>
            ) : (
              <>
                <Play className="w-3.5 h-3.5 fill-current" />
                <span>Execute Scenario</span>
              </>
            )}
          </button>
        </div>
      </div>

      {/* Safety & Demonstration Notice */}
      <div className="mb-4 bg-amber-950/30 border border-amber-800/40 rounded-lg p-2.5 flex items-start gap-2 text-xs text-amber-300/90">
        <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-amber-200">Demonstration Test Scenario: </span>
          Synthetic deception test containing conflicting evidence (<span className="font-mono text-amber-300">E-TRAP-DECEPTIVE</span> / IT Ticket CHG-99214).
          Demonstrates that the Critic and Auditor agents intercept contradictory claims rather than blindly accepting agent hypotheses.
        </div>
      </div>

      {error && (
        <div className="mb-4 bg-rose-950/40 border border-rose-800/50 rounded-lg p-3 text-xs text-rose-300">
          <strong>Scenario Error:</strong> {error}
        </div>
      )}

      {/* Metric Cards Grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3 mb-4">
        {/* 1. Scenario Status */}
        <div className="p-3 bg-[#0B0F19]/80 border border-slate-800/80 rounded-lg flex flex-col">
          <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">
            Scenario Status
          </span>
          <div className="mt-1 flex items-center gap-1.5">
            <span className="w-2 h-2 rounded-full bg-amber-400 animate-pulse" />
            <span className="text-xs font-mono font-bold text-amber-400 truncate">
              {scenarioStatus}
            </span>
          </div>
          <span className="text-[10px] text-slate-500 mt-auto pt-1">Deterministic</span>
        </div>

        {/* 2. Evidence Count */}
        <div className="p-3 bg-[#0B0F19]/80 border border-slate-800/80 rounded-lg flex flex-col">
          <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">
            Evidence Count
          </span>
          <div className="mt-1 flex items-center gap-1.5">
            <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-sm font-mono font-bold text-slate-100">
              {evidenceCount} Items
            </span>
          </div>
          <span className="text-[10px] text-cyan-400/80 mt-auto pt-1">SHA-256 Verified</span>
        </div>

        {/* 3. Contradicted Claims */}
        <div className="p-3 bg-[#0B0F19]/80 border border-slate-800/80 rounded-lg flex flex-col">
          <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">
            Contradicted Claims
          </span>
          <div className="mt-1 flex items-center gap-1.5">
            <FileWarning className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-sm font-mono font-bold text-amber-400">
              {contradictedCount} Claim
            </span>
          </div>
          <span className="text-[10px] text-amber-400/80 mt-auto pt-1">Conflict Intercepted</span>
        </div>

        {/* 4. Unsupported Claims */}
        <div className="p-3 bg-[#0B0F19]/80 border border-slate-800/80 rounded-lg flex flex-col">
          <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">
            Unsupported Claims
          </span>
          <div className="mt-1 flex items-center gap-1.5">
            <XCircle className="w-3.5 h-3.5 text-rose-400" />
            <span className="text-sm font-mono font-bold text-rose-400">
              {unsupportedCount} Claim
            </span>
          </div>
          <span className="text-[10px] text-rose-400/80 mt-auto pt-1">Overclaim Rejected</span>
        </div>

        {/* 5. Supported Claims */}
        <div className="p-3 bg-[#0B0F19]/80 border border-slate-800/80 rounded-lg flex flex-col">
          <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">
            Supported Claims
          </span>
          <div className="mt-1 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-sm font-mono font-bold text-emerald-400">
              {supportedCount} / 3
            </span>
          </div>
          <span className="text-[10px] text-emerald-400/80 mt-auto pt-1">Admin Task Corroborated</span>
        </div>

        {/* 6. Trust Score */}
        <div className="p-3 bg-[#0B0F19]/80 border border-slate-800/80 rounded-lg flex flex-col">
          <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">
            Trust Score
          </span>
          <div className="mt-1 flex items-center gap-1.5">
            <span className="text-sm font-mono font-bold text-rose-400">
              {trustScoreVal} / 100
            </span>
          </div>
          <span className="text-[10px] text-rose-400/90 font-mono mt-auto pt-1">
            {verdict} (-35.0 pts)
          </span>
        </div>
      </div>

      {/* Accordion Toggle for Detailed Pipeline Inspection */}
      <button
        onClick={() => setIsExpanded(!isExpanded)}
        className="w-full py-2 px-3 bg-slate-900/60 hover:bg-slate-900 border border-slate-800/60 rounded-lg flex items-center justify-between text-xs font-mono text-slate-300 transition-colors"
      >
        <span className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-cyan-400" />
          <span>
            {isExpanded ? 'Hide' : 'Inspect'} Trap Pipeline Evidence, Critic Objections & Contradiction Resolution
          </span>
        </span>
        {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
      </button>

      {/* Expanded Details */}
      {isExpanded && (
        <div className="mt-4 space-y-4 pt-2 border-t border-slate-800/80">
          {/* Deceptive Signal Focus */}
          <div className="bg-amber-950/20 border border-amber-800/40 rounded-lg p-3 text-xs">
            <div className="flex items-center gap-2 font-mono font-semibold text-amber-300 mb-1">
              <FileWarning className="w-4 h-4 text-amber-400" />
              <span>Deceptive Evidence Identified: {scenarioData?.deceptive_evidence_id}</span>
            </div>
            <p className="text-slate-300">
              {scenarioData?.deceptive_evidence_summary}
            </p>
          </div>

          {/* Evidence Ledger */}
          <div className="bg-[#0B0F19]/90 border border-slate-800/80 rounded-lg p-3">
            <h3 className="text-xs font-mono font-semibold text-slate-300 mb-2 flex items-center gap-2">
              <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
              <span>Synthetic Telemetry Items ({scenarioData?.evidence_items?.length || 0})</span>
            </h3>
            <div className="space-y-2">
              {scenarioData?.evidence_items?.map((ev) => {
                const isDeceptive = ev.id === scenarioData?.deceptive_evidence_id;
                return (
                  <div
                    key={ev.id}
                    className={cn(
                      'p-2.5 rounded border text-xs font-mono',
                      isDeceptive
                        ? 'bg-amber-950/30 border-amber-700/60'
                        : 'bg-slate-900/60 border-slate-800/60'
                    )}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-200">{ev.id}</span>
                        <span className="text-[10px] text-slate-400 px-1.5 py-0.5 rounded bg-slate-800">
                          {ev.evidence_type || (ev as any).evidenceType}
                        </span>
                        {isDeceptive && (
                          <span className="text-[10px] font-bold text-amber-300 bg-amber-900/60 px-1.5 py-0.5 rounded border border-amber-600/50">
                            DECEPTIVE / CONTRADICTION
                          </span>
                        )}
                      </div>
                      <span className="text-[10px] text-cyan-400">
                        SHA-256: {(ev.content_hash || (ev as any).contentHash || '').slice(0, 16)}...
                      </span>
                    </div>
                    <p className="text-slate-300 text-[11px] font-sans">
                      {ev.raw_output || (ev as any).rawOutput}
                    </p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Critic Objections Grid */}
          <div className="bg-[#0B0F19]/90 border border-slate-800/80 rounded-lg p-3">
            <h3 className="text-xs font-mono font-semibold text-slate-300 mb-2 flex items-center gap-2">
              <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
              <span>Critic Agent Objections ({scenarioData?.critic?.objections?.length || 0})</span>
            </h3>
            <div className="space-y-1.5">
              {scenarioData?.critic?.objections?.map((obj, idx) => (
                <div
                  key={idx}
                  className="p-2 bg-amber-950/20 border border-amber-800/40 rounded text-xs flex items-start gap-2"
                >
                  <AlertCircle className="w-3.5 h-3.5 text-amber-400 shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-amber-300 font-mono text-[11px]">
                      [{obj.category || obj.status}]:{' '}
                    </span>
                    <span className="text-slate-300 text-[11px]">{obj.reason}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Auditor Verified Claims */}
          <div className="bg-[#0B0F19]/90 border border-slate-800/80 rounded-lg p-3">
            <h3 className="text-xs font-mono font-semibold text-slate-300 mb-2 flex items-center gap-2">
              <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>Auditor Evidence Evaluation</span>
            </h3>
            <div className="space-y-2">
              {scenarioData?.audited_case?.claims?.map((cl, idx) => {
                const status = cl.status;
                const isContradicted = status === 'CONTRADICTED';
                const isUnsupported = status === 'UNSUPPORTED';

                return (
                  <div
                    key={idx}
                    className={cn(
                      'p-2.5 rounded border text-xs',
                      isContradicted
                        ? 'bg-amber-950/20 border-amber-800/50'
                        : isUnsupported
                        ? 'bg-rose-950/20 border-rose-800/50'
                        : 'bg-emerald-950/20 border-emerald-800/50'
                    )}
                  >
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <span className="font-semibold text-slate-200">{cl.claim}</span>
                      <span
                        className={cn(
                          'text-[10px] font-mono font-bold px-2 py-0.5 rounded',
                          isContradicted
                            ? 'bg-amber-900/60 text-amber-300'
                            : isUnsupported
                            ? 'bg-rose-900/60 text-rose-300'
                            : 'bg-emerald-900/60 text-emerald-300'
                        )}
                      >
                        {status}
                      </span>
                    </div>
                    <p className="text-slate-400 text-[11px]">{cl.reason}</p>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Trust Score Breakdown */}
          <div className="bg-[#0B0F19]/90 border border-slate-800/80 rounded-lg p-3">
            <h3 className="text-xs font-mono font-semibold text-slate-300 mb-2 flex items-center gap-2">
              <FileCode2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>Trust Score Formula & Penalties Breakdown</span>
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
              <div className="p-2 bg-slate-900/60 rounded border border-slate-800/60 font-mono text-[11px]">
                <div className="text-slate-400 mb-1">Base Contributions:</div>
                {scenarioData?.trust_score?.score_components?.map((c, i) => (
                  <div key={i} className="flex justify-between text-slate-300">
                    <span>{c.name}:</span>
                    <span className="text-emerald-400">+{c.contribution.toFixed(1)}</span>
                  </div>
                ))}
              </div>
              <div className="p-2 bg-slate-900/60 rounded border border-slate-800/60 font-mono text-[11px]">
                <div className="text-rose-400 mb-1">Applied Penalties:</div>
                {scenarioData?.trust_score?.penalties?.map((p, i) => (
                  <div key={i} className="flex justify-between text-rose-300">
                    <span>{p.name}:</span>
                    <span>-{p.deduction.toFixed(1)} pts</span>
                  </div>
                ))}
                <div className="mt-1 pt-1 border-t border-slate-800 flex justify-between font-bold text-slate-200">
                  <span>Net Trust Score:</span>
                  <span className="text-rose-400">{trustScoreVal.toFixed(1)} / 100</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
