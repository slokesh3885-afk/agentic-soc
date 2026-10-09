import React, { useState, useEffect, useCallback } from 'react';
import type { InvestigationPlan } from '../../types/soc';
import { socApi } from '../../lib/api';
import {
  BrainCircuit,
  Wrench,
  RefreshCw,
  Clock,
  ShieldAlert,
  Info,
} from 'lucide-react';
import { Button } from '../ui/Button';
import { cn } from '../../lib/utils';

interface PlannerSectionProps {
  investigationId: string;
  alertText?: string;
}

export const PlannerSection: React.FC<PlannerSectionProps> = ({
  investigationId,
  alertText,
}) => {
  const [plan, setPlan] = useState<InvestigationPlan | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isGenerating, setIsGenerating] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchPlan = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await socApi.getInvestigationPlan(investigationId);
      setPlan(data);
    } catch (err: any) {
      console.error('Failed to load investigation plan:', err);
      setError(err?.message || 'Failed to load plan');
    } finally {
      setIsLoading(false);
    }
  }, [investigationId]);

  useEffect(() => {
    fetchPlan();
  }, [fetchPlan]);

  const handleGeneratePlan = async () => {
    setIsGenerating(true);
    setError(null);
    try {
      const created = await socApi.createInvestigationPlan(investigationId, alertText);
      setPlan(created);
    } catch (err: any) {
      console.error('Failed to create/refresh plan:', err);
      setError(err?.message || 'Failed to generate investigation plan');
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="rounded-xl bg-[#090D16] border border-cyan-900/40 p-4 space-y-4 shadow-xl">
      {/* Header Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-lg bg-cyan-950/70 border border-cyan-700/50 text-cyan-400">
              <BrainCircuit className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="text-xs font-bold uppercase tracking-wider text-cyan-300 font-mono">
                  Planner Agent
                </span>
                <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-300 font-semibold">
                  Module 3C
                </span>
                {plan && (
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-amber-950/60 border border-amber-700/60 text-amber-300 font-bold uppercase">
                    Status: {plan.planner_status || plan.plannerStatus || 'PROPOSED'}
                  </span>
                )}
              </div>
            </div>
          </div>
          <p className="text-[11px] text-slate-400">
            Deterministic security triage planner creating safe, sequential investigation workflows.
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <Button
            size="sm"
            variant="outline"
            onClick={handleGeneratePlan}
            disabled={isGenerating || isLoading}
            className="h-8 text-xs font-mono border-cyan-800/60 hover:bg-cyan-950/40 text-cyan-300 gap-1.5"
            title="Deterministic plan generator referencing allow-listed security tools only"
          >
            <RefreshCw className={cn('w-3.5 h-3.5', isGenerating && 'animate-spin')} />
            {isGenerating ? 'Generating Plan...' : plan ? 'Re-plan' : 'Generate Plan'}
          </Button>
        </div>
      </div>

      {/* Target Investigation & Alert Context */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono bg-slate-950/70 p-3 rounded-lg border border-slate-800/80">
        <div>
          <span className="text-slate-400 text-[10px] uppercase font-semibold block mb-0.5">
            Target Investigation
          </span>
          <span className="text-slate-200 font-bold text-xs">{investigationId}</span>
        </div>
        <div>
          <span className="text-slate-400 text-[10px] uppercase font-semibold block mb-0.5">
            Threat Alert Context
          </span>
          <span className="text-slate-200 text-xs truncate block" title={plan?.alert || alertText || 'No alert specified'}>
            {plan?.alert || alertText || 'No alert specified'}
          </span>
        </div>
      </div>

      {/* Safety Boundary Notice */}
      <div className="flex items-start gap-2 p-2.5 rounded-lg bg-amber-950/20 border border-amber-800/40 text-[11px] text-amber-300/90 font-mono">
        <Info className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
        <span>
          <strong>Audit Boundary:</strong> Planner only proposes safe sequential steps using allow-listed tools. Tools are <em>not</em> automatically executed, and zero evidence artifacts are created during plan generation.
        </span>
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-800/60 text-xs font-mono text-rose-300 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* Content Area */}
      {isLoading ? (
        <div className="p-8 text-center text-xs font-mono text-slate-400 space-y-2">
          <RefreshCw className="w-5 h-5 animate-spin mx-auto text-cyan-400" />
          <div>Retrieving deterministic investigation plan...</div>
        </div>
      ) : !plan || !plan.plan || plan.plan.length === 0 ? (
        <div className="p-8 text-center rounded-xl bg-slate-950/40 border border-dashed border-slate-800 space-y-3">
          <BrainCircuit className="w-8 h-8 text-slate-600 mx-auto" />
          <div className="text-xs text-slate-300 font-mono">No investigation plan has been created yet.</div>
          <p className="text-[11px] text-slate-400 max-w-md mx-auto">
            Click &quot;Generate Plan&quot; to build a structured, allow-listed investigation workflow tailored to this alert context.
          </p>
          <Button
            size="sm"
            onClick={handleGeneratePlan}
            disabled={isGenerating}
            className="h-8 text-xs font-mono bg-cyan-700 hover:bg-cyan-600 text-white"
          >
            <BrainCircuit className="w-3.5 h-3.5 mr-1.5" />
            Generate Initial Plan
          </Button>
        </div>
      ) : (
        /* Sequential Plan Steps Display */
        <div className="space-y-3">
          <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 px-1">
            <span>PROPOSED STEPS ({plan.plan.length} SEQUENTIAL ACTIONS)</span>
            {plan.created_at && (
              <span className="flex items-center gap-1 text-slate-400">
                <Clock className="w-3 h-3" />
                Created: {new Date(plan.created_at).toLocaleTimeString()}
              </span>
            )}
          </div>

          <div className="space-y-2.5">
            {plan.plan.map((step) => {
              const toolName = step.tool_name || step.toolName;
              const stepStatus = step.status || 'PROPOSED';

              return (
                <div
                  key={step.step}
                  className="rounded-lg bg-slate-950/90 border border-slate-800/90 p-3.5 hover:border-slate-700/90 transition-colors space-y-2 font-mono"
                >
                  {/* Step Top Line: Step number & Status */}
                  <div className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-cyan-950/80 border border-cyan-800 text-cyan-300">
                        Step {step.step}
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/60 border border-amber-800/70 text-amber-300 uppercase tracking-wider">
                        {stepStatus}
                      </span>
                    </div>

                    {/* Tool Badge */}
                    <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-slate-900 border border-slate-700/80 text-[11px] text-cyan-300 font-mono">
                      <Wrench className="w-3 h-3 text-cyan-400" />
                      <span className="text-slate-400 text-[10px]">Tool:</span>
                      <span className="font-semibold text-cyan-200">{toolName}</span>
                    </div>
                  </div>

                  {/* Action Description */}
                  <div className="text-xs text-slate-100 font-sans font-medium leading-relaxed pl-0.5">
                    {step.action}
                  </div>

                  {/* Reason & Hypothesis */}
                  <div className="text-[11px] text-slate-400 pl-0.5 flex items-start gap-1.5 pt-1 border-t border-slate-900">
                    <span className="text-slate-400 font-mono text-[10px] uppercase shrink-0 mt-0.5">
                      Reason:
                    </span>
                    <span className="font-sans leading-relaxed text-slate-300">{step.reason}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};
