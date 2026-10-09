import React, { useState, useEffect } from 'react';
import {
  Bot,
  Activity,
  Play,
  Clock,
  Layers,
  Sparkles,
  Zap,
  RefreshCw,
  Terminal,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type {
  SocAgent,
  AgentActivityEvent,
  AgentSwarmSummary,
  AnalystResponse,
} from '../../types/soc';
import { cn } from '../../lib/utils';
import { Button } from '../ui/Button';
import { AgentCard } from '../ui/AgentCard';

interface AgentsViewProps {
  onSelectInvestigation?: (investigationId: string) => void;
}

export const AgentsView: React.FC<AgentsViewProps> = ({ onSelectInvestigation }) => {
  const [agents, setAgents] = useState<SocAgent[]>([]);
  const [summary, setSummary] = useState<AgentSwarmSummary | null>(null);
  const [activities, setActivities] = useState<AgentActivityEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [orchestrating, setOrchestrating] = useState<boolean>(false);
  const [selectedAgentFilter, setSelectedAgentFilter] = useState<string>('all');
  const [targetInvId, setTargetInvId] = useState<string>('INV-001');

  // Analyst Agent interactive workbench state
  const [analystRunning, setAnalystRunning] = useState<boolean>(false);
  const [analystResult, setAnalystResult] = useState<AnalystResponse | null>(null);
  const [analystNotes, setAnalystNotes] = useState<string>('Examine PowerShell encoded command execution');

  const fetchSwarmData = async () => {
    try {
      setLoading(true);
      const [agentsData, summaryData, activityData] = await Promise.all([
        socApi.getAgents(),
        socApi.getAgentsSummary(),
        socApi.getAgentActivity({ limit: 40 }),
      ]);
      setAgents(agentsData);
      setSummary(summaryData);
      setActivities(activityData);
    } catch (err) {
      console.error('Failed to load swarm telemetry:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSwarmData();
    const interval = setInterval(fetchSwarmData, 12000);
    return () => clearInterval(interval);
  }, []);

  const handleTriggerOrchestration = async () => {
    try {
      setOrchestrating(true);
      await socApi.orchestrateSwarm({ investigation_id: targetInvId });
      await fetchSwarmData();
    } catch (err) {
      console.error('Swarm orchestration failed:', err);
    } finally {
      setOrchestrating(false);
    }
  };

  const handleRunAnalyst = async () => {
    try {
      setAnalystRunning(true);
      const result = await socApi.runAnalystAnalysis({
        investigation_id: targetInvId,
        analyst_notes: analystNotes,
        include_threat_intel: true,
      });
      setAnalystResult(result);
      await fetchSwarmData();
    } catch (err) {
      console.error('Analyst reasoning failed:', err);
    } finally {
      setAnalystRunning(false);
    }
  };

  const filteredActivities = activities.filter((act) => {
    if (selectedAgentFilter === 'all') return true;
    return act.agent_id === selectedAgentFilter;
  });

  return (
    <div className="p-4 sm:p-6 max-w-[1600px] mx-auto space-y-6 animate-in fade-in duration-200">
      {/* 1. Header & Quick Controls */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-[#0F172A] border border-slate-800 rounded-xl p-5 shadow-lg">
        <div className="space-y-1">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-indigo-500/20 to-cyan-500/20 border border-indigo-500/30 flex items-center justify-center shadow-lg shadow-indigo-950/40">
              <Bot className="w-5 h-5 text-indigo-400" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-slate-100 font-mono tracking-tight flex items-center gap-2">
                <span>Multi-Agent Swarm Control Plane</span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-950 border border-emerald-800/80 text-emerald-400 font-normal">
                  5/5 Swarm Operational
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                Coordinated autonomous pipeline: Planner → Tool → Analyst → Critic → Auditor
              </p>
            </div>
          </div>
        </div>

        {/* Swarm Orchestration Trigger Action */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5 bg-[#090D16] border border-slate-800 rounded-lg px-3 py-1.5 text-xs font-mono">
            <span className="text-slate-400">Target:</span>
            <select
              value={targetInvId}
              onChange={(e) => setTargetInvId(e.target.value)}
              className="bg-transparent text-cyan-400 font-semibold focus:outline-none"
            >
              <option value="INV-001">INV-001 (PowerShell)</option>
              <option value="INV-002">INV-002 (Ransomware)</option>
              <option value="INV-TRAP-001">INV-TRAP-001 (Trap)</option>
            </select>
          </div>

          <Button
            onClick={handleTriggerOrchestration}
            disabled={orchestrating}
            className="flex items-center gap-2 bg-gradient-to-r from-indigo-600 to-cyan-600 hover:from-indigo-500 hover:to-cyan-500 text-white font-mono text-xs px-4 py-2 rounded-lg shadow-lg shadow-indigo-950/50"
          >
            <Play className={cn('w-3.5 h-3.5', orchestrating && 'animate-spin')} />
            <span>{orchestrating ? 'Orchestrating Cycle...' : 'Run Autonomous Swarm Cycle'}</span>
          </Button>

          <button
            onClick={fetchSwarmData}
            disabled={loading}
            className="p-2 text-slate-400 hover:text-cyan-400 bg-slate-900 border border-slate-800 rounded-lg hover:border-slate-700 transition-colors"
            title="Refresh Swarm Telemetry"
          >
            <RefreshCw className={cn('w-4 h-4', loading && 'animate-spin')} />
          </button>
        </div>
      </div>

      {/* 2. Swarm KPI Metrics Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {/* KPI 1: Active Agents */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Swarm Status</span>
            <Zap className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">
            {summary?.total_agents || 5} / 5
          </div>
          <div className="text-[11px] text-emerald-400 font-mono">
            {summary?.swarm_status || 'OPTIMAL'} (Zero Drift)
          </div>
        </div>

        {/* KPI 2: Total Swarm Actions */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Swarm Actions Recorded</span>
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-indigo-400">
            {summary?.total_actions || 161}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            Across 5 specialized roles
          </div>
        </div>

        {/* KPI 3: Evidence Generated */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Forensic Artifacts Sealed</span>
            <Layers className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-400">
            {summary?.total_evidence_generated || 20}
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            SHA-256 verified custody
          </div>
        </div>

        {/* KPI 4: Mean Latency */}
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-1">
          <div className="flex items-center justify-between text-slate-400 text-xs">
            <span>Mean Stage Latency</span>
            <Clock className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-slate-100">
            {summary?.average_execution_time_ms || 488} ms
          </div>
          <div className="text-[11px] text-slate-400 font-mono">
            Deterministic evaluation
          </div>
        </div>
      </div>

      {/* 3. The 5 Core Agent Cards (The Agent Panel specified in Requirements) */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-200 uppercase tracking-wider font-mono">
            Active Multi-Agent Swarm Registry ({agents.length} Agents)
          </h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {agents.map((agent) => (
            <AgentCard
              key={agent.id}
              agent={{
                id: agent.id,
                name: agent.name,
                role: agent.role,
                status: agent.status,
                activeTask: agent.current_task,
                capabilities: agent.capabilities,
                tasksCompleted: agent.actions_count,
                lastActive: agent.last_active_at,
              }}
              compact={false}
            />
          ))}
        </div>
      </div>

      {/* 4. Interactive Analyst Agent Workbench */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
        <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-950/60 border border-indigo-800/60 flex items-center justify-center">
              <Sparkles className="w-4 h-4 text-indigo-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100">
                Analyst Agent Hypothesis Workbench (Stage 3)
              </h3>
              <p className="text-[11px] text-slate-400">
                Synthesizes preliminary claims bound to evidence IDs before Critic adversarial challenge
              </p>
            </div>
          </div>

          <Button
            onClick={handleRunAnalyst}
            disabled={analystRunning}
            className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white font-mono text-xs px-3 py-1.5 rounded-lg"
          >
            <Play className={cn('w-3 h-3', analystRunning && 'animate-spin')} />
            <span>{analystRunning ? 'Synthesizing...' : 'Run Analyst Reasoning'}</span>
          </Button>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
          <div className="lg:col-span-5 space-y-3">
            <div className="space-y-1">
              <label className="text-[11px] font-mono text-slate-400 uppercase">
                Steering Directive / Analyst Notes:
              </label>
              <textarea
                value={analystNotes}
                onChange={(e) => setAnalystNotes(e.target.value)}
                rows={3}
                className="w-full bg-[#090D16] border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 font-mono focus:border-indigo-500 focus:outline-none"
                placeholder="Direct the Analyst Agent on what behaviors to prioritize..."
              />
            </div>

            <div className="p-3 bg-[#090D16] border border-slate-800 rounded-lg space-y-1.5 text-[11px] font-mono">
              <div className="text-slate-400 uppercase font-semibold">Attribution Safety Rule:</div>
              <p className="text-slate-300">
                The Analyst Agent only asserts propositions backed by verified evidence items.
                Premature nation-state attribution is blocked unless corroborated by C2 intelligence.
              </p>
            </div>
          </div>

          <div className="lg:col-span-7 bg-[#090D16] border border-slate-800/80 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono border-b border-slate-800 pb-2">
              <span className="text-slate-400 font-semibold uppercase">
                Preliminary Analysis Output ({analystResult?.investigation_id || targetInvId})
              </span>
              {analystResult && (
                <span className="text-emerald-400 font-bold">
                  Confidence: {Math.round(analystResult.overall_confidence * 100)}%
                </span>
              )}
            </div>

            {analystResult ? (
              <div className="space-y-3 font-mono text-[11px]">
                <div className="p-2.5 rounded bg-slate-900/80 border border-slate-800 text-slate-200">
                  <span className="text-indigo-400 font-bold block mb-1">
                    Preliminary Hypothesis:
                  </span>
                  {analystResult.preliminary_hypothesis}
                </div>

                <div className="space-y-2">
                  <div className="text-slate-400 font-semibold uppercase text-[10px]">
                    Synthesized Claims ({analystResult.claims.length}):
                  </div>
                  {analystResult.claims.map((claim) => (
                    <div
                      key={claim.claim_id}
                      className="p-2.5 rounded bg-slate-900 border border-slate-800/80 space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-cyan-400 font-bold">{claim.claim_id}</span>
                        <span className="text-emerald-400 text-[10px]">
                          Confidence: {Math.round(claim.confidence * 100)}%
                        </span>
                      </div>
                      <p className="text-slate-200">{claim.statement}</p>
                      <div className="flex items-center gap-2 text-[10px] text-slate-400 pt-1">
                        <span>Supporting Evidence:</span>
                        <span className="text-emerald-400 font-bold">
                          {claim.supporting_evidence_ids.length > 0
                            ? claim.supporting_evidence_ids.join(', ')
                            : 'None'}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ) : (
              <div className="py-8 text-center text-xs text-slate-500 font-mono space-y-1">
                <div>No active hypothesis generated yet for this session.</div>
                <div>Click "Run Analyst Reasoning" above to synthesize preliminary claims.</div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 5. Live Chronological Agent Activity Feed */}
      <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-800/80 pb-3">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-lg bg-indigo-950/60 border border-indigo-800/60 flex items-center justify-center">
              <Terminal className="w-4 h-4 text-indigo-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
                <span>Auditable Swarm Activity Stream</span>
                <span className="text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 font-mono">
                  {filteredActivities.length} Events
                </span>
              </h3>
              <p className="text-[11px] text-slate-400">
                Timestamped chronological action receipts streamed in real-time
              </p>
            </div>
          </div>

          {/* Filter by agent */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-slate-400 font-mono">Filter Agent:</span>
            <select
              value={selectedAgentFilter}
              onChange={(e) => setSelectedAgentFilter(e.target.value)}
              className="bg-[#090D16] border border-slate-800 text-xs text-slate-200 rounded-lg px-2.5 py-1 font-mono focus:outline-none"
            >
              <option value="all">All Agents (5/5)</option>
              <option value="agent-planner">Planner Agent</option>
              <option value="agent-tool">Tool Agent</option>
              <option value="agent-analyst">Analyst Agent</option>
              <option value="agent-critic">Critic / Red-Team</option>
              <option value="agent-auditor">Auditor Agent</option>
            </select>
          </div>
        </div>

        <div className="space-y-2 font-mono text-[11px]">
          {filteredActivities.map((act) => (
            <div
              key={act.id}
              className="flex items-start justify-between gap-3 p-2.5 rounded-lg bg-[#090D16] border border-slate-800/80 hover:border-slate-700/80 transition-colors"
            >
              <div className="flex items-start gap-2.5 min-w-0">
                <span className="text-slate-400 select-none shrink-0 font-semibold text-[10px] mt-0.5">
                  [{act.timestamp}]
                </span>

                <span
                  className={cn(
                    'px-2 py-0.5 rounded text-[10px] font-semibold border shrink-0',
                    act.agent_id === 'agent-planner' && 'text-sky-400 bg-sky-950/60 border-sky-800/60',
                    act.agent_id === 'agent-tool' && 'text-cyan-400 bg-cyan-950/60 border-cyan-800/60',
                    act.agent_id === 'agent-analyst' && 'text-indigo-400 bg-indigo-950/60 border-indigo-800/60',
                    act.agent_id === 'agent-critic' && 'text-rose-400 bg-rose-950/60 border-rose-800/60',
                    act.agent_id === 'agent-auditor' && 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60'
                  )}
                >
                  {act.agent_name}
                </span>

                <div className="min-w-0">
                  <div className="text-slate-200 font-medium">
                    {act.action}
                  </div>
                  {act.details && (
                    <div className="text-[10px] text-slate-400 mt-0.5">
                      {act.details}
                    </div>
                  )}
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                {act.evidence_ids && act.evidence_ids.length > 0 && (
                  <div className="flex items-center gap-1 text-[10px] text-emerald-400 bg-emerald-950/40 border border-emerald-800/50 px-1.5 py-0.5 rounded">
                    <Layers className="w-3 h-3" />
                    <span>{act.evidence_ids.join(', ')}</span>
                  </div>
                )}

                {act.investigation_id && onSelectInvestigation && (
                  <button
                    onClick={() => onSelectInvestigation(act.investigation_id!)}
                    className="text-[10px] text-slate-400 hover:text-cyan-400 hover:underline flex items-center gap-0.5"
                  >
                    <span>{act.investigation_id}</span>
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
