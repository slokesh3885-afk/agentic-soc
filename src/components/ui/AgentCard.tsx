import React from 'react';
import {
  Bot,
  Cpu,
  Shield,
  Search,
  Crosshair,
  FileCheck,
  Zap,
  CheckCircle2,
  Clock,
  Sparkles,
} from 'lucide-react';
import { StatusBadge } from './StatusBadge';
import { cn } from '../../lib/utils';

export type AgentRole = 'Lead Investigator' | 'Planner' | 'Tool Executor' | 'Analyst' | 'Critic' | 'Auditor' | 'Remediation' | string;
export type AgentStatus = 'IDLE' | 'ACTIVE' | 'RUNNING' | 'ERROR' | 'PAUSED' | string;

export interface AgentCardData {
  id?: string;
  name: string;
  role: AgentRole;
  status: AgentStatus;
  description?: string;
  capabilities?: string[];
  activeTask?: string;
  active_task?: string;
  tasksCompleted?: number;
  tasks_completed?: number;
  successRate?: number;
  success_rate?: number;
  lastActive?: string;
  last_active?: string;
  model?: string;
}

export interface AgentCardProps {
  agent: AgentCardData;
  onSelect?: (agentId: string) => void;
  compact?: boolean;
  className?: string;
}

export const AgentCard: React.FC<AgentCardProps> = ({
  agent,
  onSelect,
  compact = false,
  className,
}) => {
  const agentId = agent.id || (agent as any).agent_id || agent.name.toLowerCase().replace(/\s+/g, '-');
  const roleName = agent.role || 'SOC Agent';
  const statusStr = agent.status || 'IDLE';
  const isActive = statusStr.toUpperCase() === 'ACTIVE' || statusStr.toUpperCase() === 'RUNNING';
  const activeTaskText = agent.activeTask || agent.active_task;
  const tasksCount = agent.tasksCompleted ?? agent.tasks_completed ?? 0;
  const successRatePct = agent.successRate ?? agent.success_rate ?? 100;
  const capabilities = agent.capabilities || [];

  const getAgentIcon = (role: string) => {
    const r = role.toLowerCase();
    if (r.includes('lead') || r.includes('coordinator')) return Shield;
    if (r.includes('planner')) return Cpu;
    if (r.includes('tool') || r.includes('executor')) return Zap;
    if (r.includes('evidence') || r.includes('telemetry')) return Search;
    if (r.includes('analyst') || r.includes('correlation')) return Sparkles;
    if (r.includes('critic') || r.includes('redteam')) return Crosshair;
    if (r.includes('auditor')) return FileCheck;
    return Bot;
  };

  const IconComp = getAgentIcon(roleName);

  if (compact) {
    return (
      <div
        onClick={() => onSelect && onSelect(agentId)}
        className={cn(
          'p-2.5 rounded-lg border bg-[#0B0F19] transition-all font-mono text-xs flex items-center justify-between gap-3',
          isActive
            ? 'border-cyan-600/70 shadow-sm shadow-cyan-950/40 bg-[#0E1526]'
            : 'border-slate-800 hover:border-slate-700',
          onSelect && 'cursor-pointer hover:bg-slate-900/60',
          className
        )}
      >
        <div className="flex items-center gap-2.5 truncate">
          <div
            className={cn(
              'p-1.5 rounded-md border shrink-0',
              isActive
                ? 'bg-cyan-950/80 border-cyan-700 text-cyan-400'
                : 'bg-slate-900 border-slate-800 text-slate-400'
            )}
          >
            <IconComp className="w-3.5 h-3.5" />
          </div>
          <div className="truncate">
            <span className="font-bold text-slate-200 block truncate">{agent.name}</span>
            <span className="text-[10px] text-slate-400 block truncate">{roleName}</span>
          </div>
        </div>

        <div className="shrink-0 flex items-center gap-2">
          <StatusBadge status={statusStr} size="xs" />
        </div>
      </div>
    );
  }

  return (
    <div
      onClick={() => onSelect && onSelect(agentId)}
      className={cn(
        'rounded-xl border bg-[#0B0F19] p-4 font-mono transition-all relative flex flex-col justify-between overflow-hidden',
        isActive
          ? 'border-cyan-500/70 shadow-lg shadow-cyan-950/30 ring-1 ring-cyan-500/30'
          : 'border-slate-800/90 hover:border-slate-700/80 shadow-md',
        onSelect && 'cursor-pointer hover:bg-slate-900/40',
        className
      )}
    >
      {/* Top Banner & Status */}
      <div className="flex items-start justify-between gap-3 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-3">
          <div
            className={cn(
              'p-2.5 rounded-lg border relative',
              isActive
                ? 'bg-cyan-950/90 border-cyan-500/80 text-cyan-400'
                : 'bg-slate-900 border-slate-800 text-slate-400'
            )}
          >
            <IconComp className="w-5 h-5" />
            {isActive && (
              <span className="absolute -top-1 -right-1 w-2.5 h-2.5 bg-cyan-400 rounded-full animate-ping" />
            )}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-slate-100">{agent.name}</span>
            </div>
            <span className="text-[11px] font-medium text-cyan-400 block mt-0.5">
              {roleName}
            </span>
          </div>
        </div>

        <StatusBadge status={statusStr} size="sm" pulse={isActive} />
      </div>

      {/* Description or Current Task */}
      <div className="py-3 flex-1 space-y-2.5">
        {activeTaskText ? (
          <div className="p-2.5 rounded-lg bg-cyan-950/30 border border-cyan-800/40 text-xs">
            <span className="text-[10px] uppercase font-bold text-cyan-400 block mb-0.5 flex items-center gap-1">
              <Clock className="w-3 h-3 animate-spin" />
              Active Execution Task
            </span>
            <p className="text-slate-300 text-[11px] leading-relaxed line-clamp-2">
              {activeTaskText}
            </p>
          </div>
        ) : agent.description ? (
          <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
            {agent.description}
          </p>
        ) : (
          <p className="text-[11px] text-slate-500 italic">
            Standing by for autonomous multi-agent pipeline orchestration.
          </p>
        )}

        {/* Capabilities Pills */}
        {capabilities.length > 0 && (
          <div className="flex flex-wrap gap-1 pt-1">
            {capabilities.slice(0, 3).map((cap: string, idx: number) => (
              <span
                key={idx}
                className="text-[9px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400 truncate max-w-[140px]"
                title={cap}
              >
                {cap}
              </span>
            ))}
            {capabilities.length > 3 && (
              <span className="text-[9px] px-1.5 py-0.5 rounded bg-slate-900 text-slate-500">
                +{capabilities.length - 3}
              </span>
            )}
          </div>
        )}
      </div>

      {/* Footer Stats */}
      <div className="pt-2.5 border-t border-slate-800/80 flex items-center justify-between text-[11px] text-slate-400">
        <div className="flex items-center gap-1.5">
          <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
          <span>{tasksCount} tasks</span>
          <span className="text-slate-600">•</span>
          <span className="text-emerald-400 font-semibold">{successRatePct}%</span>
        </div>

        {agent.last_active || agent.lastActive ? (
          <span className="text-[10px] text-slate-500">
            {agent.last_active || agent.lastActive}
          </span>
        ) : (
          <span className="text-[10px] text-slate-600">Deterministic</span>
        )}
      </div>
    </div>
  );
};
