import React, { useState, useEffect } from 'react';
import {
  Activity,
  RefreshCw,
  Layers,
  ArrowRight,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type { AgentActivityEvent } from '../../types/soc';
import { cn } from '../../lib/utils';

interface LiveAgentActivityPanelProps {
  onSelectInvestigation?: (investigationId: string) => void;
  limit?: number;
}

export const LiveAgentActivityPanel: React.FC<LiveAgentActivityPanelProps> = ({
  onSelectInvestigation,
  limit = 8,
}) => {
  const [activities, setActivities] = useState<AgentActivityEvent[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchActivities = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await socApi.getAgentActivity({ limit });
      setActivities(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load agent activities');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchActivities();
    const interval = setInterval(() => {
      fetchActivities();
    }, 10000);
    return () => clearInterval(interval);
  }, [limit]);

  const getAgentColor = (agentId: string) => {
    switch (agentId) {
      case 'agent-planner':
        return 'text-sky-400 bg-sky-950/60 border-sky-800/60';
      case 'agent-tool':
        return 'text-cyan-400 bg-cyan-950/60 border-cyan-800/60';
      case 'agent-analyst':
        return 'text-indigo-400 bg-indigo-950/60 border-indigo-800/60';
      case 'agent-critic':
        return 'text-rose-400 bg-rose-950/60 border-rose-800/60';
      case 'agent-auditor':
        return 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60';
      default:
        return 'text-slate-400 bg-slate-900 border-slate-800';
    }
  };

  return (
    <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 space-y-4 shadow-lg">
      <div className="flex items-center justify-between border-b border-slate-800/80 pb-3">
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-lg bg-indigo-950/60 border border-indigo-800/60 flex items-center justify-center">
            <Activity className="w-4 h-4 text-indigo-400" />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-slate-100 flex items-center gap-2">
              <span>Live Agent Activity</span>
              <span className="flex h-2 w-2 relative">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </span>
            </h3>
            <p className="text-[11px] text-slate-400">
              Autonomous telemetry stream across Planner, Tool, Analyst, Critic, and Auditor agents
            </p>
          </div>
        </div>

        <button
          onClick={fetchActivities}
          disabled={loading}
          className="p-1.5 text-slate-400 hover:text-cyan-300 hover:bg-slate-800/80 rounded-lg transition-colors border border-transparent hover:border-slate-700"
          title="Refresh activity feed"
        >
          <RefreshCw className={cn('w-3.5 h-3.5', loading && 'animate-spin')} />
        </button>
      </div>

      {loading && activities.length === 0 ? (
        <div className="py-8 text-center space-y-2">
          <Activity className="w-6 h-6 text-indigo-400 animate-spin mx-auto" />
          <p className="text-xs text-slate-400">Streaming multi-agent telemetry...</p>
        </div>
      ) : error ? (
        <div className="p-3 bg-rose-950/30 border border-rose-800/50 rounded-lg text-xs text-rose-300">
          {error}
        </div>
      ) : activities.length === 0 ? (
        <div className="py-6 text-center text-xs text-slate-500">
          No agent activity events recorded yet.
        </div>
      ) : (
        <div className="space-y-2 font-mono text-[11px]">
          {activities.map((act) => (
            <div
              key={act.id}
              className="flex items-start justify-between gap-3 p-2.5 rounded-lg bg-[#090D16] border border-slate-800/80 hover:border-slate-700/80 transition-colors group"
            >
              <div className="flex items-start gap-2.5 min-w-0">
                <span className="text-slate-400 select-none shrink-0 font-semibold text-[10px] mt-0.5">
                  [{act.timestamp}]
                </span>

                <span
                  className={cn(
                    'px-2 py-0.5 rounded text-[10px] font-semibold border shrink-0',
                    getAgentColor(act.agent_id)
                  )}
                >
                  {act.agent_name}
                </span>

                <div className="min-w-0">
                  <div className="text-slate-200 font-medium truncate">
                    {act.action}
                  </div>
                  {act.details && (
                    <div className="text-[10px] text-slate-400 truncate mt-0.5">
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
                    title={`View investigation ${act.investigation_id}`}
                  >
                    <span>{act.investigation_id}</span>
                    <ArrowRight className="w-2.5 h-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
