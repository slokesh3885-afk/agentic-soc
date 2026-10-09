import React, { useState, useEffect } from 'react';
import {
  Play,
  Calendar,
  FileSearch,
  Brain,
  Swords,
  ShieldCheck,
  RotateCcw,
  CheckCircle2,
  Sparkles,
  Terminal,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type { InteractiveDemoSessionState } from '../../types/soc';

interface InteractiveDemoBarProps {
  onStepExecuted?: (stepId: string, state: InteractiveDemoSessionState) => void;
  showToast?: (message: string) => void;
}

const DEMO_STEPS = [
  {
    id: 'start_investigation',
    label: 'Start Investigation',
    icon: Play,
    agent: 'Intake Sensor',
    desc: 'Ingests PowerShell alert from workstation',
  },
  {
    id: 'run_planner',
    label: 'Run Planner',
    icon: Calendar,
    agent: 'Planner Agent',
    desc: 'Generates allow-listed investigative playbook',
  },
  {
    id: 'collect_evidence',
    label: 'Collect Evidence',
    icon: FileSearch,
    agent: 'Tool Agent',
    desc: 'Queries SIEM, EDR & Hash lookups',
  },
  {
    id: 'run_analysis',
    label: 'Run Analysis',
    icon: Brain,
    agent: 'Analyst Agent',
    desc: 'Corroborates claims and drafts hypothesis',
  },
  {
    id: 'challenge_conclusion',
    label: 'Challenge Conclusion',
    icon: Swords,
    agent: 'Critic / Red-Team',
    desc: 'Detects contradictions & enforces attribution policy',
  },
  {
    id: 'audit_case',
    label: 'Audit Case',
    icon: ShieldCheck,
    agent: 'Auditor Agent',
    desc: 'Seals evidence and assigns explainable trust score',
  },
  {
    id: 'replay_investigation',
    label: 'Replay Investigation',
    icon: RotateCcw,
    agent: 'Replay Engine',
    desc: 'Verifies 100% deterministic reproducibility',
  },
];

export const InteractiveDemoBar: React.FC<InteractiveDemoBarProps> = ({
  onStepExecuted,
  showToast,
}) => {
  const [sessionState, setSessionState] = useState<InteractiveDemoSessionState | null>(null);
  const [activeStepId, setActiveStepId] = useState<string>('start_investigation');
  const [isExecuting, setIsExecuting] = useState<string | null>(null);
  const [isResetting, setIsResetting] = useState(false);

  useEffect(() => {
    socApi
      .getDemoPipelineState()
      .then((state) => {
        if (state) {
          setSessionState(state);
          if (state.current_step_id) setActiveStepId(state.current_step_id);
        }
      })
      .catch(() => {});
  }, []);

  const handleExecuteStep = async (stepId: string) => {
    try {
      setIsExecuting(stepId);
      const res = await socApi.executeDemoStep(stepId);
      setSessionState(res);
      setActiveStepId(stepId);
      if (onStepExecuted) onStepExecuted(stepId, res);
      if (showToast) {
        showToast(`Interactive Demo: Executed stage '${stepId.replace('_', ' ')}'`);
      }
    } catch (err: any) {
      console.error(`Failed to execute step ${stepId}:`, err);
    } finally {
      setIsExecuting(null);
    }
  };

  const handleReset = async () => {
    try {
      setIsResetting(true);
      const res = await socApi.resetDemoPipeline();
      setSessionState(res);
      setActiveStepId('start_investigation');
      if (showToast) {
        showToast('Interactive Demo reset to Stage 1');
      }
    } catch (err: any) {
      console.error('Failed to reset demo:', err);
    } finally {
      setIsResetting(false);
    }
  };

  const latestTelemetry =
    sessionState?.latest_telemetry && sessionState.latest_telemetry.length > 0
      ? sessionState.latest_telemetry[sessionState.latest_telemetry.length - 1]
      : sessionState?.current_verdict;

  return (
    <div className="bg-[#0B0F19] border border-slate-800 rounded-2xl p-5 shadow-xl space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400">
            <Sparkles className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-slate-100 font-mono">
                Interactive Multi-Agent Demo Orchestrator
              </h3>
              <span className="text-[10px] font-mono px-2 py-0.2 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60 font-bold">
                SPEC LINES 411-428
              </span>
            </div>
            <p className="text-[11px] text-slate-400">
              Trigger autonomous agent lifecycle stages with deterministic reproducibility
            </p>
          </div>
        </div>

        <button
          onClick={handleReset}
          disabled={isResetting || !!isExecuting}
          className="px-2.5 py-1.5 rounded-lg bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-400 hover:text-slate-200 text-xs font-mono transition-colors flex items-center gap-1.5 shrink-0 self-start sm:self-auto"
        >
          <RotateCcw className={`w-3.5 h-3.5 ${isResetting ? 'animate-spin text-cyan-400' : ''}`} />
          Reset Pipeline
        </button>
      </div>

      {/* 7 Interactive Action Buttons */}
      <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-2.5">
        {DEMO_STEPS.map((step, idx) => {
          const Icon = step.icon;
          const isCurrent = activeStepId === step.id;
          const isDone =
            sessionState?.completed_steps?.some((s) => s.step_id === step.id) || false;
          const isStepExecuting = isExecuting === step.id;

          return (
            <button
              key={step.id}
              onClick={() => handleExecuteStep(step.id)}
              disabled={!!isExecuting}
              className={`p-3 rounded-xl border text-left transition-all flex flex-col justify-between gap-2 relative overflow-hidden group ${
                isCurrent
                  ? 'bg-cyan-950/70 border-cyan-500 shadow-lg shadow-cyan-950/50'
                  : isDone
                  ? 'bg-slate-900/80 border-slate-700/80 hover:border-cyan-800'
                  : 'bg-slate-950/50 border-slate-800/80 hover:border-slate-700'
              }`}
            >
              {isDone && (
                <div className="absolute top-1.5 right-1.5">
                  <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                </div>
              )}
              <div className="flex items-center gap-2">
                <span className="text-[10px] font-mono font-bold text-slate-500">
                  0{idx + 1}
                </span>
                <Icon
                  className={`w-4 h-4 ${
                    isCurrent
                      ? 'text-cyan-400'
                      : isDone
                      ? 'text-emerald-400'
                      : 'text-slate-400 group-hover:text-cyan-300'
                  } ${isStepExecuting ? 'animate-spin' : ''}`}
                />
              </div>

              <div>
                <div className="text-xs font-bold font-mono text-slate-200 group-hover:text-cyan-300 transition-colors leading-tight">
                  {step.label}
                </div>
                <div className="text-[10px] text-slate-500 font-mono mt-0.5 truncate">
                  {step.agent}
                </div>
              </div>
            </button>
          );
        })}
      </div>

      {/* Active Stage Context Bar */}
      {latestTelemetry && (
        <div className="p-3 rounded-xl bg-slate-900/60 border border-slate-800/80 flex items-center justify-between gap-4 text-xs font-mono">
          <div className="flex items-center gap-2 text-slate-300 truncate">
            <Terminal className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
            <span className="text-slate-400">Latest Event:</span>
            <span className="text-cyan-300 truncate">{latestTelemetry}</span>
          </div>
          <div className="flex items-center gap-3 shrink-0 text-[11px] text-slate-400">
            {sessionState?.cumulative_evidence && (
              <span>
                Evidence:{' '}
                <strong className="text-emerald-400">
                  {sessionState.cumulative_evidence.length}
                </strong>
              </span>
            )}
            {sessionState?.current_trust_score !== undefined && (
              <span>
                Trust:{' '}
                <strong className="text-cyan-400">
                  {sessionState.current_trust_score}/100
                </strong>
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
