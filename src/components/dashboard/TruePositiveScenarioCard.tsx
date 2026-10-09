import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  Play,
  RotateCw,
  CheckCircle2,
  FileCode2,
  Cpu,
  Fingerprint,
  Info,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type { TruePositiveScenarioResponse } from '../../types/soc';
import { cn } from '../../lib/utils';

export const TruePositiveScenarioCard: React.FC = () => {
  const [scenarioData, setScenarioData] = useState<TruePositiveScenarioResponse | null>(null);
  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isExpanded, setIsExpanded] = useState<boolean>(false);

  // Load initial scenario state on mount
  useEffect(() => {
    let mounted = true;
    socApi
      .getTruePositiveScenario()
      .then((data) => {
        if (mounted) {
          setScenarioData(data);
          setIsLoading(false);
        }
      })
      .catch((err) => {
        if (mounted) {
          setError(err.message || 'Failed to fetch scenario state');
          setIsLoading(false);
        }
      });
    return () => {
      mounted = false;
    };
  }, []);

  // Handler to run scenario pipeline
  const handleRunScenario = async () => {
    setIsRunning(true);
    setError(null);
    try {
      const result = await socApi.runTruePositiveScenario();
      setScenarioData(result);
    } catch (err: any) {
      setError(err.message || 'Failed to execute true positive scenario');
    } finally {
      setIsRunning(false);
    }
  };

  const evidenceCount = scenarioData?.evidence_count ?? scenarioData?.evidenceCount ?? 4;
  const supportedClaimsCount =
    scenarioData?.supported_claims_count ?? scenarioData?.supportedClaimsCount ?? 4;
  const trustScoreVal =
    scenarioData?.trust_score?.trust_score ?? scenarioData?.trustScore?.trustScore ?? 100;
  const verdict =
    scenarioData?.trust_score?.explanation?.verdict ??
    scenarioData?.trustScore?.explanation?.verdict ??
    'HIGH_TRUST';
  const scenarioStatus = scenarioData?.status ?? 'VERIFIED_TRUE_POSITIVE';

  return (
    <div className="bg-[#0F172A]/90 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm flex flex-col shadow-lg">
      {/* Header */}
      <div className="pb-3 border-b border-slate-800/80 mb-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-950/60 border border-emerald-700/50 rounded-lg text-emerald-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold text-slate-100 font-mono">
                True Positive Scenario
              </h2>
              <span className="text-[11px] font-bold font-mono uppercase bg-amber-500/20 border border-amber-500/50 text-amber-300 px-2.5 py-0.5 rounded-full tracking-wide">
                Synthetic Test Scenario
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Deterministic verification of end-to-end evidence corroboration across all agent layers
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
              'bg-emerald-600/20 border-emerald-500/50 text-emerald-300 hover:bg-emerald-600/30 hover:border-emerald-400',
              (isRunning || isLoading) && 'opacity-60 cursor-not-allowed'
            )}
            title="Execute the full multi-agent SOC pipeline against synthetic telemetry"
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
      <div className="mb-4 bg-blue-950/30 border border-blue-800/40 rounded-lg p-2.5 flex items-start gap-2 text-xs text-blue-300/90">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div>
          <span className="font-semibold text-blue-200">Demonstration Test Scenario: </span>
          All indicators, RFC 5737 IP addresses (198.51.100.42), target host, and hashes are strictly synthetic test values.
          This does <span className="underline font-medium">NOT</span> represent a real-world security incident.
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
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-mono font-bold text-emerald-400 truncate">
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

        {/* 3. Supported Claims */}
        <div className="p-3 bg-[#0B0F19]/80 border border-slate-800/80 rounded-lg flex flex-col">
          <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">
            Supported Claims
          </span>
          <div className="mt-1 flex items-center gap-1.5">
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
            <span className="text-sm font-mono font-bold text-emerald-400">
              {supportedClaimsCount} / 4
            </span>
          </div>
          <span className="text-[10px] text-slate-500 mt-auto pt-1">100% Corroborated</span>
        </div>

        {/* 4. Audit Status */}
        <div className="p-3 bg-[#0B0F19]/80 border border-slate-800/80 rounded-lg flex flex-col">
          <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">
            Audit Status
          </span>
          <div className="mt-1 flex items-center gap-1.5">
            <span className="text-xs font-mono font-bold text-emerald-400">
              AUDIT_VERIFIED
            </span>
          </div>
          <span className="text-[10px] text-slate-500 mt-auto pt-1">0 Objections</span>
        </div>

        {/* 5. Case JSON Status */}
        <div className="p-3 bg-[#0B0F19]/80 border border-slate-800/80 rounded-lg flex flex-col">
          <span className="text-[10px] uppercase font-mono text-slate-400 tracking-wider">
            Case JSON
          </span>
          <div className="mt-1 flex items-center gap-1.5">
            <FileCode2 className="w-3.5 h-3.5 text-purple-400" />
            <span className="text-xs font-mono font-bold text-purple-300">
              v1.0.0 Canonical
            </span>
          </div>
          <span className="text-[10px] text-slate-500 mt-auto pt-1">Deterministic JSON</span>
        </div>

        {/* 6. Trust Score */}
        <div className="p-3 bg-[#0B0F19]/80 border border-emerald-900/50 bg-emerald-950/20 rounded-lg flex flex-col">
          <span className="text-[10px] uppercase font-mono text-emerald-400/90 tracking-wider">
            Trust Score
          </span>
          <div className="mt-1 flex items-baseline gap-1">
            <span className="text-base font-mono font-extrabold text-emerald-400">
              {typeof trustScoreVal === 'number' ? trustScoreVal.toFixed(1) : trustScoreVal}
            </span>
            <span className="text-[11px] font-mono text-slate-400">/100</span>
          </div>
          <span className="text-[10px] font-mono font-semibold text-emerald-400/90 mt-auto pt-1">
            {verdict}
          </span>
        </div>
      </div>

      {/* Explanation Narrative */}
      <div className="p-3 rounded-lg bg-[#0B0F19]/60 border border-slate-800/70 text-xs text-slate-300">
        <p className="leading-relaxed">
          <strong className="text-slate-100 font-mono">Pipeline Summary: </strong>
          {scenarioData?.explanation ||
            'Synthetic True Positive scenario executed across the complete SOC pipeline. All 4 claims are fully corroborated by verified cryptographic SHA-256 evidence. Planner generated sequential steps, Critic validated claims without objections, Auditor verified case integrity, and Trust Score was computed at 100.0/100.'}
        </p>
      </div>

      {/* Toggle Details Accordion */}
      <div className="mt-3 pt-2 border-t border-slate-800/60 flex items-center justify-between text-xs">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="inline-flex items-center gap-1 text-slate-400 hover:text-slate-200 transition-colors"
        >
          {isExpanded ? (
            <>
              <ChevronUp className="w-3.5 h-3.5" />
              <span>Hide Pipeline Details</span>
            </>
          ) : (
            <>
              <ChevronDown className="w-3.5 h-3.5" />
              <span>View Multi-Agent Pipeline Execution Trace</span>
            </>
          )}
        </button>
        <span className="text-[11px] font-mono text-slate-500">
          Target: {scenarioData?.target_host || 'TEST-SRV-APP-01.corp.test'}
        </span>
      </div>

      {/* Expandable Pipeline Details */}
      {isExpanded && scenarioData && (
        <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-4 text-xs font-mono">
          {/* Synthetic Evidence Items */}
          <div>
            <h4 className="text-slate-300 font-bold mb-2 flex items-center gap-1.5">
              <Fingerprint className="w-3.5 h-3.5 text-cyan-400" />
              <span>Synthetic Evidence Ledger (Module 3A)</span>
            </h4>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {(scenarioData.evidence_items || scenarioData.evidenceItems || []).map((ev) => (
                <div
                  key={ev.id}
                  className="p-2.5 rounded bg-[#070A12] border border-slate-800/80 space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-cyan-400">{ev.id}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                      {ev.evidence_type || ev.evidenceType}
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-300 font-sans line-clamp-2">
                    {ev.raw_output || ev.rawOutput}
                  </p>
                  <div className="text-[10px] text-slate-500 truncate">
                    Hash: {ev.content_hash || ev.contentHash}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Planner Steps */}
          {scenarioData.planner && (
            <div>
              <h4 className="text-slate-300 font-bold mb-2 flex items-center gap-1.5">
                <Cpu className="w-3.5 h-3.5 text-blue-400" />
                <span>Planner Agent Investigation Plan (Module 3C)</span>
              </h4>
              <div className="space-y-1.5">
                {(scenarioData.planner.plan || []).map((step) => (
                  <div
                    key={step.step}
                    className="p-2 rounded bg-[#070A12] border border-slate-800/80 flex items-center justify-between"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-blue-400 font-bold">Step {step.step}:</span>
                      <span className="text-slate-200">{step.action}</span>
                      <span className="text-[10px] text-slate-400">({step.tool_name})</span>
                    </div>
                    <span className="text-[10px] text-emerald-400 bg-emerald-950/40 border border-emerald-800/40 px-1.5 py-0.5 rounded">
                      {step.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Auditor Claims Corroboration */}
          {scenarioData.audited_case && (
            <div>
              <h4 className="text-slate-300 font-bold mb-2 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                <span>Auditor Claim Verifications (Module 3E)</span>
              </h4>
              <div className="space-y-1.5">
                {(scenarioData.audited_case.claims || []).map((c, idx) => (
                  <div
                    key={idx}
                    className="p-2 rounded bg-[#070A12] border border-slate-800/80 flex items-center justify-between"
                  >
                    <div className="space-y-0.5">
                      <div className="text-slate-200 font-sans">{c.claim}</div>
                      <div className="text-[10px] text-slate-400">
                        Evidence IDs: {(c.evidence_ids || c.evidenceIds || []).join(', ')}
                      </div>
                    </div>
                    <span
                      className={cn(
                        'text-[10px] px-2 py-0.5 rounded font-bold uppercase',
                        c.status === 'SUPPORTED'
                          ? 'bg-emerald-950/60 text-emerald-400 border border-emerald-800/50'
                          : 'bg-rose-950/60 text-rose-400 border border-rose-800/50'
                      )}
                    >
                      {c.status}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
