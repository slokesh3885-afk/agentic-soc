import React, { useState, useEffect } from 'react';
import {
  ShieldAlert,
  Swords,
  Play,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Shield,
  FileCode2,
  Lock,
  Layers,
  Terminal,
  FileSearch,
  RefreshCw,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import { JsonViewer } from '../ui/JsonViewer';
import type {
  RedTeamChallengeResponse,
  RedTeamScenarioPreset,
  InteractiveDemoSessionState,
  CompleteCaseAuditObject,
} from '../../types/soc';

interface CriticRedTeamViewProps {
  onSelectInvestigation?: (id: string) => void;
}

export const CriticRedTeamView: React.FC<CriticRedTeamViewProps> = ({ onSelectInvestigation: _onSelectInvestigation }) => {
  // State
  const [activeTab, setActiveTab] = useState<'critic' | 'pipeline' | 'json'>('critic');
  const [scenarios, setScenarios] = useState<RedTeamScenarioPreset[]>([]);
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('SCN-PEN-TEST');
  const [preliminaryConclusion, setPreliminaryConclusion] = useState<string>('Endpoint compromised by malware.');
  const [attackerHypothesis, setAttackerHypothesis] = useState<string>('External adversary executed PowerShell reverse shell');
  const [assertedThreatActor, setAssertedThreatActor] = useState<string>('APT-29 (Cozy Bear)');
  const [challengeResult, setChallengeResult] = useState<RedTeamChallengeResponse | null>(null);
  const [demoState, setDemoState] = useState<InteractiveDemoSessionState | null>(null);
  const [auditObject, setAuditObject] = useState<CompleteCaseAuditObject | null>(null);

  const [isLoadingChallenge, setIsLoadingChallenge] = useState<boolean>(false);
  const [isExecutingStep, setIsExecutingStep] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Load initial data
  useEffect(() => {
    loadInitialData();
  }, []);

  const loadInitialData = async () => {
    try {
      setError(null);
      const [scList, latestChal, dState, aObj] = await Promise.all([
        socApi.getRedTeamScenarios().catch(() => []),
        socApi.getLatestRedTeamChallenge().catch(() => null),
        socApi.getDemoPipelineState().catch(() => null),
        socApi.getCompleteCaseAuditObject('CASE-2026-0042').catch(() => null),
      ]);

      if (scList && scList.length > 0) setScenarios(scList);
      if (latestChal) setChallengeResult(latestChal);
      if (dState) setDemoState(dState);
      if (aObj) setAuditObject(aObj);
    } catch (err: any) {
      console.error('Error loading Critic / Red-Team data:', err);
      setError(err?.message || 'Failed to initialize Critic data');
    }
  };

  const handleScenarioChange = (scId: string) => {
    setSelectedScenarioId(scId);
    const found = scenarios.find((s) => s.scenario_id === scId);
    if (found) {
      setPreliminaryConclusion(found.preliminary_conclusion);
      setAttackerHypothesis(found.attacker_hypothesis);
      setAssertedThreatActor(found.asserted_threat_actor || 'None');
    }
  };

  const handleRunChallenge = async () => {
    setIsLoadingChallenge(true);
    setError(null);
    try {
      const res = await socApi.runRedTeamChallenge({
        investigation_id: 'INV-001',
        scenario_id: selectedScenarioId,
        preliminary_conclusion: preliminaryConclusion,
        attacker_hypothesis: attackerHypothesis,
        asserted_threat_actor: assertedThreatActor,
      });
      setChallengeResult(res);
      // Also refresh audit object
      const updatedAudit = await socApi.getCompleteCaseAuditObject('CASE-2026-0042').catch(() => null);
      if (updatedAudit) setAuditObject(updatedAudit);
    } catch (err: any) {
      console.error('Failed to run redteam challenge:', err);
      setError(err?.message || 'Failed to execute adversarial challenge');
    } finally {
      setIsLoadingChallenge(false);
    }
  };

  const handleExecuteDemoStep = async (stepId: string) => {
    setIsExecutingStep(stepId);
    setError(null);
    try {
      const nextState = await socApi.runDemoPipelineStep(stepId);
      setDemoState(nextState);
    } catch (err: any) {
      console.error('Failed to execute demo step:', err);
      setError(err?.message || `Failed to execute step: ${stepId}`);
    } finally {
      setIsExecutingStep(null);
    }
  };

  const handleResetDemo = async () => {
    setError(null);
    try {
      const resetState = await socApi.resetDemoPipeline();
      setDemoState(resetState);
    } catch (err: any) {
      console.error('Failed to reset demo:', err);
    }
  };

  const demoStepsList = [
    { id: 'start_investigation', label: 'Start Investigation', number: 1 },
    { id: 'run_planner', label: 'Run Planner', number: 2 },
    { id: 'collect_evidence', label: 'Collect Evidence', number: 3 },
    { id: 'run_analysis', label: 'Run Analysis', number: 4 },
    { id: 'challenge_conclusion', label: 'Challenge Conclusion', number: 5 },
    { id: 'audit_case', label: 'Audit Case', number: 6 },
    { id: 'replay_investigation', label: 'Replay Investigation', number: 7 },
  ];

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-[1600px] mx-auto">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-slate-800 pb-5">
        <div>
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-rose-500/20 via-pink-600/20 to-purple-600/30 border border-rose-500/30 flex items-center justify-center shadow-lg shadow-rose-950/40">
              <Swords className="w-5 h-5 text-rose-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-xl sm:text-2xl font-bold text-white font-mono tracking-tight">
                  Critic / Red-Team Adversarial Engine
                </h1>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950 text-rose-300 border border-rose-800/60 uppercase">
                  Module 3S / 3T
                </span>
              </div>
              <p className="text-xs text-slate-400 font-mono mt-0.5">
                Investigate → Challenge → Prove → Audit • Deterministic Contradiction Resolution & Attribution Guard
              </p>
            </div>
          </div>
        </div>

        {/* Tab Buttons */}
        <div className="flex items-center gap-2 bg-[#0B0F19] p-1.5 rounded-xl border border-slate-800">
          <button
            onClick={() => setActiveTab('critic')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium font-mono transition-all flex items-center gap-1.5 ${
              activeTab === 'critic'
                ? 'bg-rose-950 text-rose-200 border border-rose-800 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <ShieldAlert className="w-3.5 h-3.5" />
            Critic / Red-Team Panel
          </button>
          <button
            onClick={() => setActiveTab('pipeline')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium font-mono transition-all flex items-center gap-1.5 ${
              activeTab === 'pipeline'
                ? 'bg-cyan-950 text-cyan-200 border border-cyan-800 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            Interactive Demo Pipeline (7 Steps)
          </button>
          <button
            onClick={() => setActiveTab('json')}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium font-mono transition-all flex items-center gap-1.5 ${
              activeTab === 'json'
                ? 'bg-emerald-950 text-emerald-200 border border-emerald-800 shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <FileCode2 className="w-3.5 h-3.5" />
            Case JSON Viewer
          </button>
        </div>
      </div>

      {error && (
        <div className="p-3.5 bg-rose-950/60 border border-rose-800/80 rounded-xl text-xs text-rose-300 font-mono flex items-center gap-2.5">
          <AlertTriangle className="w-4 h-4 shrink-0 text-rose-400" />
          <span>{error}</span>
        </div>
      )}

      {/* ============================================================== */}
      {/* 1. CRITIC / RED-TEAM ATTACK PANEL TAB                          */}
      {/* ============================================================== */}
      {activeTab === 'critic' && (
        <div className="space-y-6">
          {/* Controls Bar: Scenario Selection & Custom Inputs */}
          <div className="bg-[#0D1322] border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4">
              <div className="space-y-1">
                <span className="text-xs font-mono font-semibold text-rose-400 uppercase tracking-wider">
                  Adversarial Test Setup
                </span>
                <p className="text-xs text-slate-400">
                  Select a pre-packaged challenge scenario or supply a preliminary conclusion for Critic attack
                </p>
              </div>

              <div className="flex items-center gap-3 w-full lg:w-auto">
                <select
                  value={selectedScenarioId}
                  onChange={(e) => handleScenarioChange(e.target.value)}
                  className="bg-[#070A12] border border-slate-700 text-slate-200 text-xs rounded-lg px-3 py-2 font-mono focus:outline-none focus:border-rose-500 w-full lg:w-80"
                >
                  {scenarios.map((s) => (
                    <option key={s.scenario_id} value={s.scenario_id}>
                      {s.title}
                    </option>
                  ))}
                </select>

                <button
                  onClick={handleRunChallenge}
                  disabled={isLoadingChallenge}
                  className="px-4 py-2 rounded-lg bg-gradient-to-r from-rose-600 to-pink-600 hover:from-rose-500 hover:to-pink-500 text-white font-mono text-xs font-semibold flex items-center gap-2 shadow-lg shadow-rose-950/40 shrink-0 transition-all disabled:opacity-50"
                >
                  {isLoadingChallenge ? (
                    <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  ) : (
                    <Swords className="w-3.5 h-3.5" />
                  )}
                  <span>{isLoadingChallenge ? 'Attacking...' : 'Challenge Conclusion'}</span>
                </button>
              </div>
            </div>

            {/* Inputs Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3 pt-2 border-t border-slate-800/80">
              <div>
                <label className="text-[11px] font-mono text-slate-400 block mb-1">
                  Preliminary Conclusion (Under Attack):
                </label>
                <input
                  type="text"
                  value={preliminaryConclusion}
                  onChange={(e) => setPreliminaryConclusion(e.target.value)}
                  className="w-full bg-[#070A12] border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 font-mono focus:border-rose-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-[11px] font-mono text-slate-400 block mb-1">
                  Attacker Hypothesis:
                </label>
                <input
                  type="text"
                  value={attackerHypothesis}
                  onChange={(e) => setAttackerHypothesis(e.target.value)}
                  className="w-full bg-[#070A12] border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 font-mono focus:border-rose-500 focus:outline-none"
                />
              </div>

              <div>
                <label className="text-[11px] font-mono text-slate-400 block mb-1">
                  Asserted Threat Actor Attribution:
                </label>
                <input
                  type="text"
                  value={assertedThreatActor}
                  onChange={(e) => setAssertedThreatActor(e.target.value)}
                  className="w-full bg-[#070A12] border border-slate-800 text-slate-200 text-xs rounded-lg px-3 py-2 font-mono focus:border-rose-500 focus:outline-none"
                />
              </div>
            </div>
          </div>

          {/* Results Grid */}
          {challengeResult && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Column: Critic Findings & Contradictions (8 Cols) */}
              <div className="lg:col-span-8 space-y-6">
                {/* 1. Preliminary vs Final Decision Banner */}
                <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {/* Preliminary Draft */}
                    <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2">
                      <div className="flex items-center gap-2 text-slate-400 text-xs font-mono">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                        <span>PRELIMINARY CONCLUSION</span>
                      </div>
                      <p className="text-sm font-mono font-semibold text-slate-200">
                        &quot;{challengeResult.preliminary_conclusion}&quot;
                      </p>
                      <div className="flex items-center gap-2 pt-1 text-[11px] text-slate-400 font-mono">
                        <span>Original Trust Score:</span>
                        <span className="text-amber-400 font-bold">
                          {challengeResult.original_trust_score}/100
                        </span>
                      </div>
                    </div>

                    {/* Final Critic Decision */}
                    <div className="p-4 rounded-xl bg-rose-950/30 border border-rose-800/60 space-y-2">
                      <div className="flex items-center gap-2 text-rose-400 text-xs font-mono font-bold">
                        <CheckCircle2 className="w-3.5 h-3.5 text-rose-400" />
                        <span>FINAL CRITIC DECISION</span>
                      </div>
                      <p className="text-sm font-mono font-bold text-rose-200">
                        &quot;{challengeResult.final_critic_decision}&quot;
                      </p>
                      <div className="flex items-center gap-2 pt-1 text-[11px] text-slate-400 font-mono">
                        <span>Revised Trust Score:</span>
                        <span className="text-rose-400 font-bold">
                          {challengeResult.revised_trust_score}/100
                        </span>
                        <span className="text-[10px] text-rose-400/80 bg-rose-950 px-1.5 py-0.5 rounded border border-rose-800/40">
                          -44.5 pts
                        </span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* 2. Canonical Critic Findings (Lines 214-219 of Spec) */}
                <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs font-mono font-semibold text-slate-200 uppercase tracking-wider">
                      <Swords className="w-4 h-4 text-rose-400" />
                      <span>Critic Findings ({challengeResult.critic_findings.length})</span>
                    </div>
                    <span className="text-[11px] font-mono text-slate-400">
                      Evaluated against verified evidence
                    </span>
                  </div>

                  <div className="space-y-3">
                    {challengeResult.critic_findings.map((finding) => (
                      <div
                        key={finding.finding_id}
                        className="p-3.5 rounded-lg bg-[#0E1526] border border-slate-800 space-y-2 hover:border-slate-700 transition-colors"
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono font-bold text-slate-100">
                              • {finding.finding_text}
                            </span>
                          </div>

                          <span
                            className={`text-[10px] font-mono font-semibold px-2 py-0.5 rounded border uppercase shrink-0 ${
                              finding.status === 'CONFIRMED'
                                ? 'bg-amber-950/70 text-amber-300 border-amber-800/60'
                                : finding.status === 'AUTHORIZED_ACTIVITY'
                                ? 'bg-emerald-950/70 text-emerald-300 border-emerald-800/60'
                                : finding.status === 'INCONCLUSIVE'
                                ? 'bg-sky-950/70 text-sky-300 border-sky-800/60'
                                : 'bg-rose-950/70 text-rose-300 border-rose-800/60'
                            }`}
                          >
                            {finding.status}
                          </span>
                        </div>

                        <p className="text-xs text-slate-400 font-mono leading-relaxed pl-3 border-l-2 border-slate-700">
                          {finding.counter_argument}
                        </p>

                        <div className="flex items-center gap-2 pl-3 pt-1">
                          <span className="text-[10px] font-mono text-slate-400">Supporting Evidence:</span>
                          {finding.supporting_evidence_ids.map((eid) => (
                            <span
                              key={eid}
                              className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-cyan-300 border border-slate-700"
                            >
                              {eid}
                            </span>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* 3. Contradictions Callout Box (Lines 223 of Spec) */}
                <div className="bg-[#0B0F19] border border-amber-800/60 rounded-xl p-5 space-y-3 shadow-lg">
                  <div className="flex items-center gap-2 text-xs font-mono font-semibold text-amber-400 uppercase tracking-wider">
                    <AlertTriangle className="w-4 h-4 text-amber-400" />
                    <span>Evidence Contradictions Detected ({challengeResult.contradictions.length})</span>
                  </div>

                  <div className="space-y-3">
                    {challengeResult.contradictions.map((ctrd) => (
                      <div
                        key={ctrd.contradiction_id}
                        className="p-3.5 rounded-lg bg-amber-950/20 border border-amber-800/40 space-y-2"
                      >
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
                          <div className="p-2.5 rounded bg-[#090D16] border border-slate-800">
                            <span className="text-rose-400 font-semibold block mb-1">
                              Evidence {ctrd.evidence_a_id}:
                            </span>
                            <span className="text-slate-300 text-[11px]">{ctrd.evidence_a_summary}</span>
                          </div>

                          <div className="p-2.5 rounded bg-[#090D16] border border-slate-800">
                            <span className="text-emerald-400 font-semibold block mb-1">
                              Evidence {ctrd.evidence_b_id}:
                            </span>
                            <span className="text-slate-300 text-[11px]">{ctrd.evidence_b_summary}</span>
                          </div>
                        </div>

                        <div className="text-xs font-mono text-amber-200/90 pt-1">
                          <span className="font-semibold text-amber-400">Critic Resolution: </span>
                          <span>{ctrd.resolution}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Right Column: Attribution Guard & Cryptographic Seal (4 Cols) */}
              <div className="lg:col-span-4 space-y-6">
                {/* Threat Actor Attribution Guard Card (Lines 256-275 of Spec) */}
                <div className="bg-[#0B0F19] border border-rose-800/70 rounded-xl p-5 space-y-4 shadow-xl">
                  <div className="flex items-center gap-2 text-xs font-mono font-bold text-rose-400 uppercase tracking-wider">
                    <Lock className="w-4 h-4 text-rose-400" />
                    <span>Threat Actor Attribution Policy Guard</span>
                  </div>

                  <div className="p-3.5 rounded-lg bg-[#070A12] border border-slate-800 space-y-3 font-mono text-xs">
                    <div>
                      <span className="text-slate-400 text-[10px] uppercase block">Rule:</span>
                      <p className="text-slate-300 text-[11px] italic mt-0.5">
                        &quot;{challengeResult.attribution_guard.policy_rule}&quot;
                      </p>
                    </div>

                    <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800">
                      <div>
                        <span className="text-slate-400 text-[10px] uppercase block">Attribution:</span>
                        <span className="text-rose-400 font-bold text-xs">
                          {challengeResult.attribution_guard.attribution_status}
                        </span>
                      </div>

                      <div>
                        <span className="text-slate-400 text-[10px] uppercase block">Evidence:</span>
                        <span className="text-amber-400 font-bold text-xs">
                          {challengeResult.attribution_guard.evidence_sufficiency}
                        </span>
                      </div>
                    </div>

                    <div className="pt-2 border-t border-slate-800">
                      <span className="text-slate-400 text-[10px] uppercase block">Action:</span>
                      <div className="flex items-center gap-2 mt-1">
                        <XCircle className="w-4 h-4 text-rose-400" />
                        <span className="text-rose-300 font-bold text-xs uppercase">
                          {challengeResult.attribution_guard.action}
                        </span>
                      </div>
                    </div>

                    <p className="text-[11px] text-slate-400 leading-relaxed pt-1">
                      {challengeResult.attribution_guard.reason}
                    </p>
                  </div>
                </div>

                {/* Cryptographic Seal & Challenge Meta */}
                <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center gap-2 text-xs font-mono font-semibold text-slate-300 uppercase tracking-wider">
                    <Shield className="w-4 h-4 text-cyan-400" />
                    <span>Cryptographic Audit Proof</span>
                  </div>

                  <div className="space-y-2 font-mono text-xs text-slate-400">
                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block">Challenge ID:</span>
                      <span className="text-slate-200">{challengeResult.challenge_id}</span>
                    </div>

                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block">SHA-256 Signature:</span>
                      <span className="text-cyan-300 text-[11px] break-all">
                        {challengeResult.tamper_proof_signature}
                      </span>
                    </div>

                    <div>
                      <span className="text-[10px] text-slate-400 uppercase block">Timestamp:</span>
                      <span className="text-slate-300">{challengeResult.timestamp}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* 2. INTERACTIVE DEMO PIPELINE TAB (Lines 411-428 of Spec)       */}
      {/* ============================================================== */}
      {activeTab === 'pipeline' && (
        <div className="space-y-6">
          {/* Header & Controls */}
          <div className="bg-[#0D1322] border border-slate-800 rounded-xl p-5 shadow-lg space-y-4">
            <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
              <div>
                <h3 className="text-sm font-mono font-bold text-cyan-400 uppercase tracking-wider">
                  Interactive Demo Simulation Pipeline
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Click any stage button below to execute simulated autonomous agent activity and update case telemetry
                </p>
              </div>

              <button
                onClick={handleResetDemo}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 font-mono text-xs font-medium flex items-center gap-1.5 border border-slate-700 transition-colors"
              >
                <RotateCcw className="w-3.5 h-3.5 text-slate-400" />
                <span>Reset Simulation</span>
              </button>
            </div>

            {/* The 7 Interactive Demo Buttons Required by Spec */}
            <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5 pt-2">
              {demoStepsList.map((step) => {
                const isCurrent = demoState?.current_step_id === step.id;
                const isCompleted = demoState?.completed_steps.some(
                  (s) => s.step_id === step.id && s.status === 'completed'
                );

                return (
                  <button
                    key={step.id}
                    onClick={() => handleExecuteDemoStep(step.id)}
                    disabled={isExecutingStep !== null}
                    className={`p-3 rounded-xl border text-left flex flex-col justify-between transition-all font-mono min-h-[86px] ${
                      isCurrent
                        ? 'bg-cyan-950/80 border-cyan-500 text-white shadow-lg shadow-cyan-950/50 scale-[1.02]'
                        : isCompleted
                        ? 'bg-[#0E1526] border-emerald-800/80 text-emerald-200 hover:border-emerald-700'
                        : 'bg-[#0A0E17] border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-[10px] font-bold text-slate-400">0{step.number}</span>
                      {isCompleted ? (
                        <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                      ) : isCurrent ? (
                        <Play className="w-3.5 h-3.5 text-cyan-400 animate-pulse" />
                      ) : (
                        <div className="w-2 h-2 rounded-full bg-slate-700" />
                      )}
                    </div>
                    <span className="text-xs font-semibold leading-tight mt-1">{step.label}</span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Pipeline Active Telemetry & State View */}
          {demoState && (
            <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
              {/* Left Column: Active Step Details & Telemetry (8 Cols) */}
              <div className="lg:col-span-8 space-y-6">
                {/* Active Step Card */}
                <div className="bg-[#0B0F19] border border-cyan-800/60 rounded-xl p-5 space-y-4 shadow-xl">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-cyan-400 uppercase tracking-wider">
                        Active Stage: {demoState.current_step_number}/7
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-cyan-950 text-cyan-300 border border-cyan-800/60 uppercase">
                        {demoState.current_step_id.replace('_', ' ')}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-xs font-mono">
                      <span className="text-slate-400">Trust Score:</span>
                      <span className="text-emerald-400 font-bold">{demoState.current_trust_score}/100</span>
                    </div>
                  </div>

                  <div className="p-3.5 rounded-lg bg-[#070A12] border border-slate-800 font-mono text-xs space-y-2">
                    <span className="text-slate-400 text-[10px] uppercase block">Current Verdict:</span>
                    <p className="text-slate-100 font-semibold text-sm">
                      {demoState.current_verdict}
                    </p>
                  </div>

                  {/* Cumulative Evidence */}
                  <div className="space-y-2">
                    <span className="text-xs font-mono text-slate-400">Cumulative Evidence Collected:</span>
                    <div className="flex flex-wrap gap-2">
                      {demoState.cumulative_evidence.map((eid) => (
                        <span
                          key={eid}
                          className="px-2 py-1 rounded bg-slate-800 text-cyan-300 border border-slate-700 text-xs font-mono flex items-center gap-1.5"
                        >
                          <FileSearch className="w-3 h-3 text-cyan-400" />
                          {eid}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Real-time Telemetry Feed */}
                <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2 text-xs font-mono font-semibold text-slate-200 uppercase tracking-wider">
                      <Terminal className="w-4 h-4 text-emerald-400" />
                      <span>Live Telemetry Stream</span>
                    </div>
                    <span className="text-[10px] font-mono text-slate-400">
                      Deterministic multi-agent execution
                    </span>
                  </div>

                  <div className="p-4 rounded-xl bg-[#070A12] border border-slate-800/80 font-mono text-xs space-y-1.5 max-h-60 overflow-y-auto">
                    {demoState.latest_telemetry.map((log, idx) => (
                      <div key={idx} className="text-emerald-400 leading-relaxed">
                        {log}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Right Column: Execution History Ledger (4 Cols) */}
              <div className="lg:col-span-4 space-y-6">
                <div className="bg-[#0B0F19] border border-slate-800 rounded-xl p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-mono font-bold text-slate-200 uppercase tracking-wider">
                      Stage History
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">
                      {demoState.completed_steps.length} of 7 recorded
                    </span>
                  </div>

                  <div className="space-y-3">
                    {demoState.completed_steps.map((st) => (
                      <div
                        key={st.step_id}
                        className="p-3 rounded-lg bg-[#0E1526] border border-slate-800 text-xs font-mono space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-bold text-slate-200">{st.step_name}</span>
                          <span className="text-[10px] text-cyan-400 font-semibold">{st.agent_name}</span>
                        </div>
                        <p className="text-[11px] text-slate-400 leading-relaxed">{st.action_summary}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ============================================================== */}
      {/* 3. CASE JSON VIEWER TAB (Lines 388-410 of Spec)               */}
      {/* ============================================================== */}
      {activeTab === 'json' && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-mono font-bold text-emerald-400 uppercase tracking-wider">
                Canonical Complete Case Audit Object
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Formatted 14-field JSON viewer verifying tamper-evident investigation record (Module 3T)
              </p>
            </div>
          </div>

          {auditObject ? (
            <JsonViewer
              data={auditObject}
              title="CASE-2026-0042 — Complete Audit Object"
              filename="CASE-2026-0042_AUDIT_OBJECT.json"
              maxHeight="max-h-[650px]"
            />
          ) : (
            <div className="p-8 text-center bg-[#0B0F19] border border-slate-800 rounded-xl text-xs font-mono text-slate-400">
              Loading canonical Case Audit Object...
            </div>
          )}
        </div>
      )}
    </div>
  );
};
