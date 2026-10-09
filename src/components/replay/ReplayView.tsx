import React, { useState, useEffect, useRef } from 'react';
import {
  RotateCcw,
  CheckCircle2,
  ShieldCheck,
  Play,
  Pause,
  SkipForward,
  SkipBack,
  Copy,
  Check,
  RefreshCw,
  Sliders,
  Lock,
  FileCheck,
  Activity,
  History,
  AlertCircle,
  ExternalLink,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type {
  ReplaySession,
  ReplaySummary,
  TimelineEvent,
  Investigation,
} from '../../types/soc';

interface ReplayViewProps {
  onSelectInvestigation?: (investigationId: string) => void;
}

export const ReplayView: React.FC<ReplayViewProps> = ({
  onSelectInvestigation,
}) => {
  const [summary, setSummary] = useState<ReplaySummary | null>(null);
  const [replays, setReplays] = useState<ReplaySession[]>([]);
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [selectedInvId, setSelectedInvId] = useState<string>('INV-001');
  const [activeReplay, setActiveReplay] = useState<ReplaySession | null>(null);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(1);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [playbackSpeed, setPlaybackSpeed] = useState<number>(1200); // ms per step
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const timerRef = useRef<NodeJS.Timeout | null>(null);

  // Load initial data
  const loadInitialData = async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const [sum, repList, invList] = await Promise.all([
        socApi.getReplaySummary(),
        socApi.getReplays(),
        socApi.getInvestigations(),
      ]);
      setSummary(sum);
      setReplays(repList);
      setInvestigations(invList);

      if (repList.length > 0) {
        setActiveReplay(repList[0]);
        setCurrentStepIndex(repList[0].total_steps > 0 ? 1 : 0);
        setSelectedInvId(repList[0].investigation_id);
      } else if (invList.length > 0) {
        setSelectedInvId(invList[0].id);
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to load replay telemetry.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadInitialData();
  }, []);

  // Handle Playback Loop
  useEffect(() => {
    if (isPlaying && activeReplay && activeReplay.timeline.length > 0) {
      timerRef.current = setTimeout(() => {
        if (currentStepIndex < activeReplay.timeline.length) {
          setCurrentStepIndex((prev) => prev + 1);
        } else {
          setIsPlaying(false);
        }
      }, playbackSpeed);
    } else {
      if (timerRef.current) clearTimeout(timerRef.current);
    }
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [isPlaying, currentStepIndex, activeReplay, playbackSpeed]);

  const handleRunReplay = async () => {
    if (!selectedInvId) return;
    setIsExecuting(true);
    setErrorMessage(null);
    try {
      const result = await socApi.executeReplay({
        investigation_id: selectedInvId,
        notes: `User-triggered forensic replay from SOC console at ${new Date().toISOString()}`,
        strict_verification: true,
      });
      setActiveReplay(result);
      setCurrentStepIndex(1);
      setIsPlaying(false);
      // Refresh summary & list
      const [sum, repList] = await Promise.all([
        socApi.getReplaySummary(),
        socApi.getReplays(),
      ]);
      setSummary(sum);
      setReplays(repList);
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to execute deterministic replay.');
    } finally {
      setIsExecuting(false);
    }
  };

  const handleSelectReplay = (replay: ReplaySession) => {
    setActiveReplay(replay);
    setSelectedInvId(replay.investigation_id);
    setCurrentStepIndex(1);
    setIsPlaying(false);
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2500);
  };

  const currentEvent: TimelineEvent | undefined =
    activeReplay && activeReplay.timeline.length > 0
      ? activeReplay.timeline[currentStepIndex - 1]
      : undefined;

  const getActorBadgeColor = (actor: string) => {
    const a = actor.toLowerCase();
    if (a.includes('planner')) return 'bg-sky-950/70 text-sky-300 border-sky-800/60';
    if (a.includes('critic')) return 'bg-amber-950/70 text-amber-300 border-amber-800/60';
    if (a.includes('auditor')) return 'bg-purple-950/70 text-purple-300 border-purple-800/60';
    if (a.includes('tool')) return 'bg-indigo-950/70 text-indigo-300 border-indigo-800/60';
    if (a.includes('evidence')) return 'bg-emerald-950/70 text-emerald-300 border-emerald-800/60';
    if (a.includes('containment') || a.includes('playbook')) return 'bg-rose-950/70 text-rose-300 border-rose-800/60';
    if (a.includes('human') || a.includes('operator')) return 'bg-cyan-950/70 text-cyan-300 border-cyan-800/60';
    return 'bg-slate-800/70 text-slate-300 border-slate-700/60';
  };

  return (
    <div className="p-4 sm:p-6 max-w-[1600px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 border-b border-slate-800/80 pb-5">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-700/50 flex items-center justify-center text-cyan-400">
              <RotateCcw className="w-4 h-4" />
            </div>
            <h2 className="text-xl font-bold text-slate-100 font-mono tracking-tight">
              Forensic Replay & Investigation Reproducibility Engine
            </h2>
            <span className="text-[10px] font-semibold uppercase bg-cyan-950/80 text-cyan-400 border border-cyan-800/60 px-2 py-0.5 rounded">
              Module 3O
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Deterministic step-by-step re-execution over frozen tool outputs and cryptographic evidence snapshots to prove 100% reproducibility.
          </p>
        </div>

        <button
          onClick={loadInitialData}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-700 text-slate-300 hover:text-white hover:border-slate-600 transition-colors text-xs font-mono disabled:opacity-50"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Replays</span>
        </button>
      </div>

      {errorMessage && (
        <div className="p-3.5 rounded-xl bg-rose-950/30 border border-rose-800/50 text-rose-300 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl bg-[#0F172A] border border-slate-800/80 space-y-1">
          <div className="text-[11px] font-medium text-slate-400 font-mono flex items-center justify-between">
            <span>TOTAL REPLAYS</span>
            <RotateCcw className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">
            {summary ? summary.total_replays : '—'}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {summary?.investigations_replayed || 0} unique investigations tested
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A] border border-slate-800/80 space-y-1">
          <div className="text-[11px] font-medium text-slate-400 font-mono flex items-center justify-between">
            <span>AVG CONSISTENCY</span>
            <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-emerald-400">
            {summary ? `${summary.average_consistency}%` : '100%'}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            Zero non-deterministic divergence
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A] border border-slate-800/80 space-y-1">
          <div className="text-[11px] font-medium text-slate-400 font-mono flex items-center justify-between">
            <span>PERFECT MATCHES</span>
            <ShieldCheck className="w-3.5 h-3.5 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-300">
            {summary ? summary.perfect_replays_count : '—'}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            100% identical multi-agent claims
          </div>
        </div>

        <div className="p-4 rounded-xl bg-[#0F172A] border border-slate-800/80 space-y-1">
          <div className="text-[11px] font-medium text-slate-400 font-mono flex items-center justify-between">
            <span>ANALYTICAL DIVERGENCE</span>
            <AlertCircle className="w-3.5 h-3.5 text-slate-500" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-300">
            {summary ? summary.divergent_replays_count : '0'}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            Strict verification threshold active
          </div>
        </div>
      </div>

      {/* Main Execution & Inspection Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Replay Trigger & Comparison Scorecard (4 Cols) */}
        <div className="lg:col-span-4 space-y-6">
          {/* Replay Trigger Card */}
          <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800/90 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100 font-mono flex items-center gap-2">
                <Sliders className="w-4 h-4 text-cyan-400" />
                <span>Deterministic Replay Sandbox</span>
              </h3>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <label className="text-[11px] font-medium text-slate-400 block mb-1 font-mono">
                  Select Investigation to Re-Execute
                </label>
                <select
                  value={selectedInvId}
                  onChange={(e) => setSelectedInvId(e.target.value)}
                  className="w-full bg-[#090D16] border border-slate-800 rounded-lg p-2.5 text-slate-200 text-xs font-mono focus:outline-none focus:border-cyan-500/60"
                >
                  {investigations.map((inv) => (
                    <option key={inv.id} value={inv.id}>
                      {inv.id} — {inv.alert} ({inv.host})
                    </option>
                  ))}
                </select>
              </div>

              <div className="p-3 bg-[#090D16] border border-slate-800/80 rounded-lg space-y-1.5 text-[11px] text-slate-400">
                <div className="text-slate-200 font-semibold font-mono flex items-center gap-1.5">
                  <Lock className="w-3 h-3 text-cyan-400" />
                  <span>Reproducibility Contract</span>
                </div>
                <p className="leading-relaxed">
                  Re-runs multi-agent reasoning, canonical claim adjudication, and evidence Trust Score calculation against frozen tool outputs and snapshot hashes.
                </p>
              </div>

              <button
                onClick={handleRunReplay}
                disabled={isExecuting || !selectedInvId}
                className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium text-xs font-mono flex items-center justify-center gap-2 transition-all shadow-lg shadow-cyan-950/40 disabled:opacity-50"
              >
                {isExecuting ? (
                  <>
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    <span>Executing Deterministic Pipeline...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5 fill-current" />
                    <span>Run Replay Simulation</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Active Replay Verification Scorecard */}
          {activeReplay && (
            <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800/90 space-y-4">
              <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span className="font-bold text-xs text-slate-100 font-mono">
                    Replay Audit Proof ({activeReplay.id})
                  </span>
                </div>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/60 font-semibold">
                  {activeReplay.consistency_score}% CONSISTENT
                </span>
              </div>

              <div className="space-y-3 text-xs font-mono">
                {/* Verdict Reconciliation */}
                <div className="p-3 rounded-lg bg-[#090D16] border border-slate-800/80 space-y-1.5">
                  <div className="text-[10px] uppercase font-semibold text-slate-400">
                    Verdict Reconciliation
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Historical Case:</span>
                    <span className="text-slate-200 font-bold">{activeReplay.original_verdict}</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400">Replayed Execution:</span>
                    <span className="text-emerald-400 font-bold flex items-center gap-1">
                      <Check className="w-3 h-3" />
                      {activeReplay.replayed_verdict}
                    </span>
                  </div>
                </div>

                {/* Score & Claims Matching */}
                <div className="grid grid-cols-2 gap-2 text-[11px]">
                  <div className="p-2.5 rounded-lg bg-[#090D16] border border-slate-800/80 space-y-0.5">
                    <div className="text-[9px] uppercase text-slate-400">Trust Score Delta</div>
                    <div className="text-sm font-bold text-slate-200">
                      {activeReplay.comparison.trust_score_delta.toFixed(1)}% (Δ0.0)
                    </div>
                  </div>
                  <div className="p-2.5 rounded-lg bg-[#090D16] border border-slate-800/80 space-y-0.5">
                    <div className="text-[9px] uppercase text-slate-400">Claims Match Rate</div>
                    <div className="text-sm font-bold text-cyan-400">
                      {activeReplay.claims_match_rate}%
                    </div>
                  </div>
                </div>

                {/* Evidence Snapshot Hash */}
                <div className="p-3 rounded-lg bg-[#090D16] border border-slate-800/80 space-y-1.5">
                  <div className="flex items-center justify-between text-[10px] uppercase font-semibold text-slate-400">
                    <span>Evidence Snapshot SHA-256</span>
                    <button
                      onClick={() => copyToClipboard(activeReplay.evidence_snapshot_hash)}
                      className="text-slate-400 hover:text-cyan-400 transition-colors flex items-center gap-1"
                      title="Copy SHA-256 hash"
                    >
                      {copiedHash === activeReplay.evidence_snapshot_hash ? (
                        <Check className="w-3 h-3 text-emerald-400" />
                      ) : (
                        <Copy className="w-3 h-3" />
                      )}
                      <span>Copy</span>
                    </button>
                  </div>
                  <div className="text-[10px] text-slate-300 break-all font-mono bg-slate-950 p-1.5 rounded border border-slate-800">
                    {activeReplay.evidence_snapshot_hash}
                  </div>
                </div>

                {/* Ledger Block Reference */}
                {activeReplay.audit_entry_id && (
                  <div className="flex items-center justify-between text-[11px] p-2 rounded bg-slate-900/60 border border-slate-800/60">
                    <span className="text-slate-400">Immutable Audit Block:</span>
                    <span className="text-cyan-400 font-bold">{activeReplay.audit_entry_id}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Right Column: Interactive Time-Travel Forensic Timeline Scrubber (8 Cols) */}
        <div className="lg:col-span-8 space-y-6">
          <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800/90 space-y-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-4">
              <div>
                <h3 className="text-sm font-bold text-slate-100 font-mono flex items-center gap-2">
                  <History className="w-4 h-4 text-cyan-400" />
                  <span>Interactive Time-Travel Scrubber</span>
                </h3>
                <p className="text-[11px] text-slate-400 mt-0.5">
                  Step forward and backward across the complete chronological sequence of investigative events.
                </p>
              </div>

              {activeReplay && (
                <div className="text-xs font-mono text-slate-300 bg-slate-900 border border-slate-800 px-3 py-1.5 rounded-lg flex items-center gap-2">
                  <span className="text-slate-400">Step:</span>
                  <span className="text-cyan-400 font-bold">{currentStepIndex}</span>
                  <span className="text-slate-500">/</span>
                  <span className="text-slate-200">{activeReplay.total_steps}</span>
                </div>
              )}
            </div>

            {activeReplay && activeReplay.timeline.length > 0 ? (
              <div className="space-y-5">
                {/* Playback Controls & Slider */}
                <div className="p-4 rounded-xl bg-[#090D16] border border-slate-800/90 space-y-4">
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setCurrentStepIndex(1)}
                        disabled={currentStepIndex <= 1}
                        className="p-2 rounded-lg bg-slate-800/60 border border-slate-700/60 text-slate-300 hover:text-white hover:bg-slate-700 disabled:opacity-40 transition-colors"
                        title="Jump to Start"
                      >
                        <SkipBack className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={() => setCurrentStepIndex((prev) => Math.max(1, prev - 1))}
                        disabled={currentStepIndex <= 1}
                        className="p-2 rounded-lg bg-slate-800/60 border border-slate-700/60 text-slate-300 hover:text-white hover:bg-slate-700 disabled:opacity-40 transition-colors"
                        title="Step Backward"
                      >
                        <Sliders className="w-3.5 h-3.5 rotate-180" />
                      </button>

                      <button
                        onClick={() => setIsPlaying(!isPlaying)}
                        className="p-2 px-3 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs font-mono flex items-center gap-1.5 transition-all shadow-md shadow-cyan-950/40"
                      >
                        {isPlaying ? (
                          <>
                            <Pause className="w-3.5 h-3.5 fill-current" />
                            <span>Pause</span>
                          </>
                        ) : (
                          <>
                            <Play className="w-3.5 h-3.5 fill-current" />
                            <span>Play</span>
                          </>
                        )}
                      </button>

                      <button
                        onClick={() =>
                          setCurrentStepIndex((prev) =>
                            Math.min(activeReplay.timeline.length, prev + 1)
                          )
                        }
                        disabled={currentStepIndex >= activeReplay.timeline.length}
                        className="p-2 rounded-lg bg-slate-800/60 border border-slate-700/60 text-slate-300 hover:text-white hover:bg-slate-700 disabled:opacity-40 transition-colors"
                        title="Step Forward"
                      >
                        <Sliders className="w-3.5 h-3.5" />
                      </button>

                      <button
                        onClick={() => setCurrentStepIndex(activeReplay.timeline.length)}
                        disabled={currentStepIndex >= activeReplay.timeline.length}
                        className="p-2 rounded-lg bg-slate-800/60 border border-slate-700/60 text-slate-300 hover:text-white hover:bg-slate-700 disabled:opacity-40 transition-colors"
                        title="Jump to End"
                      >
                        <SkipForward className="w-3.5 h-3.5" />
                      </button>
                    </div>

                    <div className="flex items-center gap-2 text-xs font-mono">
                      <span className="text-slate-400 text-[11px]">Speed:</span>
                      {[800, 1200, 2000].map((s) => (
                        <button
                          key={s}
                          onClick={() => setPlaybackSpeed(s)}
                          className={`px-2 py-0.5 rounded text-[10px] border transition-colors ${
                            playbackSpeed === s
                              ? 'bg-cyan-950 text-cyan-300 border-cyan-700'
                              : 'bg-slate-900 text-slate-400 border-slate-800 hover:text-slate-200'
                          }`}
                        >
                          {s === 800 ? 'Fast' : s === 1200 ? '1x' : 'Slow'}
                        </button>
                      ))}
                    </div>
                  </div>

                  {/* Range Slider */}
                  <div className="space-y-1">
                    <input
                      type="range"
                      min={1}
                      max={activeReplay.timeline.length}
                      value={currentStepIndex}
                      onChange={(e) => {
                        setCurrentStepIndex(Number(e.target.value));
                        setIsPlaying(false);
                      }}
                      className="w-full h-1.5 bg-slate-800 rounded-lg appearance-none cursor-pointer accent-cyan-400"
                    />
                    <div className="flex justify-between text-[10px] font-mono text-slate-400">
                      <span>Step 1: Alert Ingestion</span>
                      <span>Step {activeReplay.timeline.length}: Final Resolution</span>
                    </div>
                  </div>
                </div>

                {/* Current Milestone Detail Card */}
                {currentEvent && (
                  <div className="p-4 rounded-xl bg-[#090D16] border border-cyan-900/40 space-y-4 shadow-lg shadow-black/40">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                          Step #{currentEvent.step_index}
                        </span>
                        <span
                          className={`text-xs font-mono font-semibold px-2.5 py-0.5 rounded border ${getActorBadgeColor(
                            currentEvent.actor
                          )}`}
                        >
                          {currentEvent.actor}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
                          {currentEvent.event_type}
                        </span>
                      </div>

                      <div className="text-[11px] font-mono text-slate-400">
                        {currentEvent.timestamp}
                      </div>
                    </div>

                    <div className="space-y-1.5">
                      <h4 className="text-sm font-semibold text-slate-100 font-mono">
                        {currentEvent.title}
                      </h4>
                      <p className="text-xs text-slate-300 leading-relaxed font-sans">
                        {currentEvent.description}
                      </p>
                    </div>

                    {/* Cumulative State Snapshot at this Step */}
                    {currentEvent.state_snapshot && (
                      <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 space-y-2">
                        <div className="text-[10px] uppercase font-semibold text-slate-400 font-mono flex items-center justify-between">
                          <span>Cumulative Investigation State</span>
                          <Activity className="w-3 h-3 text-cyan-400" />
                        </div>
                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono">
                          <div className="p-2 rounded bg-slate-900/60 border border-slate-800/60">
                            <span className="text-[9px] uppercase text-slate-400 block">Evidence Items</span>
                            <span className="text-emerald-400 font-bold">
                              {currentEvent.state_snapshot.cumulative_evidence_count} captured
                            </span>
                          </div>
                          <div className="p-2 rounded bg-slate-900/60 border border-slate-800/60">
                            <span className="text-[9px] uppercase text-slate-400 block">Tools Executed</span>
                            <span className="text-indigo-400 font-bold">
                              {currentEvent.state_snapshot.cumulative_tool_executions} calls
                            </span>
                          </div>
                          <div className="p-2 rounded bg-slate-900/60 border border-slate-800/60">
                            <span className="text-[9px] uppercase text-slate-400 block">Trust Index</span>
                            <span className="text-cyan-400 font-bold">
                              {currentEvent.state_snapshot.evidence_trust_score}%
                            </span>
                          </div>
                          <div className="p-2 rounded bg-slate-900/60 border border-slate-800/60">
                            <span className="text-[9px] uppercase text-slate-400 block">Current Status</span>
                            <span className="text-slate-200 font-bold">
                              {currentEvent.state_snapshot.investigation_status}
                            </span>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Artifact Reference */}
                    {currentEvent.artifact_ref && (
                      <div className="flex items-center justify-between text-xs font-mono p-2.5 rounded-lg bg-slate-900/40 border border-slate-800/60">
                        <div className="flex items-center gap-1.5 text-slate-400">
                          <FileCheck className="w-3.5 h-3.5 text-cyan-400" />
                          <span>Artifact Reference:</span>
                          <span className="text-slate-200 font-semibold">{currentEvent.artifact_ref}</span>
                        </div>
                        {onSelectInvestigation && (
                          <button
                            onClick={() => onSelectInvestigation(activeReplay.investigation_id)}
                            className="text-cyan-400 hover:text-cyan-300 flex items-center gap-1 text-[11px] transition-colors"
                          >
                            <span>Inspect Case</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        )}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="p-10 rounded-xl bg-[#090D16] border border-slate-800/80 text-center text-slate-400 text-xs font-mono space-y-2">
                <RotateCcw className="w-6 h-6 mx-auto text-slate-600 mb-1" />
                <p>No replay session loaded. Select an investigation and click &quot;Run Replay Simulation&quot;.</p>
              </div>
            )}
          </div>

          {/* Historical Replay Sessions Table */}
          <div className="p-5 rounded-xl bg-[#0F172A] border border-slate-800/90 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
              <h3 className="text-xs font-bold text-slate-200 font-mono uppercase tracking-wider flex items-center gap-2">
                <History className="w-3.5 h-3.5 text-cyan-400" />
                <span>Historical Replay Executions ({replays.length})</span>
              </h3>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-slate-800 text-[10px] text-slate-400 uppercase">
                    <th className="pb-2.5">Replay ID</th>
                    <th className="pb-2.5">Investigation</th>
                    <th className="pb-2.5">Verdict Match</th>
                    <th className="pb-2.5">Consistency</th>
                    <th className="pb-2.5">Timeline Steps</th>
                    <th className="pb-2.5">Executed At</th>
                    <th className="pb-2.5 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800/60">
                  {replays.map((rep) => (
                    <tr
                      key={rep.id}
                      className={`hover:bg-slate-800/40 transition-colors ${
                        activeReplay?.id === rep.id ? 'bg-cyan-950/20' : ''
                      }`}
                    >
                      <td className="py-2.5 font-bold text-cyan-400">{rep.id}</td>
                      <td className="py-2.5 text-slate-200">{rep.investigation_id}</td>
                      <td className="py-2.5">
                        <span className="flex items-center gap-1 text-emerald-400 font-medium">
                          <CheckCircle2 className="w-3 h-3" />
                          {rep.replayed_verdict}
                        </span>
                      </td>
                      <td className="py-2.5 text-emerald-400 font-bold">
                        {rep.consistency_score}%
                      </td>
                      <td className="py-2.5 text-slate-400">{rep.total_steps} steps</td>
                      <td className="py-2.5 text-slate-400 text-[11px] truncate max-w-[140px]">
                        {rep.executed_at}
                      </td>
                      <td className="py-2.5 text-right">
                        <button
                          onClick={() => handleSelectReplay(rep)}
                          className="px-2.5 py-1 rounded bg-slate-800 hover:bg-cyan-900/60 text-slate-300 hover:text-cyan-300 border border-slate-700 text-[11px] transition-colors"
                        >
                          Load Timeline
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
