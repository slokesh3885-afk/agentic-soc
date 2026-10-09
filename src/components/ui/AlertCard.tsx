import React from 'react';
import type { SecurityAlert, AlertStatus } from '../../types/soc';
import {
  Server,
  Crosshair,
  ArrowRight,
  Clock,
} from 'lucide-react';
import { StatusBadge } from './StatusBadge';
import { Button } from './Button';
import { cn } from '../../lib/utils';

export type AlertSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;

export interface AlertCardData {
  id: string;
  title: string;
  severity: AlertSeverity;
  source?: string;
  timestamp?: string;
  created_at?: string;
  status?: AlertStatus | string;
  target_host?: string;
  targetHost?: string;
  host?: string;
  mitre_tactic?: string;
  mitreTactic?: string;
  description?: string;
}

export interface AlertCardProps {
  alert: AlertCardData | SecurityAlert | any;
  onInvestigate?: (alertId: string) => void;
  compact?: boolean;
  className?: string;
}

export const AlertCard: React.FC<AlertCardProps> = ({
  alert,
  onInvestigate,
  compact = false,
  className,
}) => {
  const alertId = alert.id || 'ALT-000';
  const title = alert.title || alert.name || 'Security Anomaly Detected';
  const severity = (alert.severity || 'MEDIUM').toUpperCase();
  const source = alert.source || 'EDR Sensor';
  const timestamp = alert.timestamp || alert.created_at || 'Recent';
  const status = alert.status || 'NEW';
  const host = alert.target_host || alert.targetHost || alert.host;
  const mitreTactic = alert.mitre_tactic || alert.mitreTactic;
  const description = alert.description || alert.rawEventSnippet;

  const getSeverityStyle = () => {
    switch (severity) {
      case 'CRITICAL':
        return 'border-rose-900/80 bg-rose-950/15 hover:border-rose-600/80 shadow-rose-950/20';
      case 'HIGH':
        return 'border-orange-900/80 bg-orange-950/15 hover:border-orange-600/80 shadow-orange-950/20';
      case 'MEDIUM':
        return 'border-amber-900/80 bg-amber-950/15 hover:border-amber-600/80 shadow-amber-950/20';
      case 'LOW':
      default:
        return 'border-slate-800 bg-slate-900/30 hover:border-slate-700 shadow-slate-950/20';
    }
  };

  if (compact) {
    return (
      <div
        className={cn(
          'p-3 rounded-lg border font-mono text-xs flex items-center justify-between gap-3 transition-all',
          getSeverityStyle(),
          className
        )}
      >
        <div className="flex items-center gap-2.5 truncate">
          <StatusBadge status={severity} size="xs" />
          <div className="truncate">
            <span className="font-bold text-slate-200 block truncate">{title}</span>
            <span className="text-[10px] text-slate-400 block truncate font-mono">
              {alertId} • {source}
            </span>
          </div>
        </div>

        {onInvestigate && (
          <Button
            size="sm"
            variant="ghost"
            onClick={() => onInvestigate(alertId)}
            className="h-6 px-2 text-[10px] text-cyan-300 hover:text-cyan-200 hover:bg-cyan-950/60 shrink-0 gap-1"
          >
            <span>Investigate</span>
            <ArrowRight className="w-3 h-3" />
          </Button>
        )}
      </div>
    );
  }

  return (
    <div
      className={cn(
        'rounded-xl border p-4 font-mono text-xs shadow-lg transition-all flex flex-col justify-between gap-3',
        getSeverityStyle(),
        className
      )}
    >
      {/* Header Bar */}
      <div className="flex items-start justify-between gap-3 pb-2.5 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <StatusBadge status={severity} size="sm" pulse={severity === 'CRITICAL'} />
          <span className="font-bold text-cyan-400 text-xs tracking-wide">
            {alertId}
          </span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-900 border border-slate-800 text-slate-400">
            {source}
          </span>
        </div>

        <StatusBadge status={status} size="xs" />
      </div>

      {/* Alert Title & Description */}
      <div className="space-y-1">
        <h4 className="font-bold text-slate-100 text-sm leading-snug">
          {title}
        </h4>
        {description && (
          <p className="text-[11px] text-slate-400 leading-relaxed line-clamp-2">
            {description}
          </p>
        )}
      </div>

      {/* Telemetry Tags (Host, MITRE, Time) */}
      <div className="pt-2 border-t border-slate-800/70 flex flex-wrap items-center justify-between gap-2 text-[11px] text-slate-400">
        <div className="flex flex-wrap items-center gap-3">
          {host && (
            <span className="flex items-center gap-1 text-slate-300" title="Target Asset Host">
              <Server className="w-3.5 h-3.5 text-cyan-400" />
              <span>{host}</span>
            </span>
          )}
          {mitreTactic && (
            <span className="flex items-center gap-1 text-purple-300" title="MITRE ATT&CK Tactic">
              <Crosshair className="w-3.5 h-3.5 text-purple-400" />
              <span>{mitreTactic}</span>
            </span>
          )}
          <span className="flex items-center gap-1 text-slate-500">
            <Clock className="w-3 h-3" />
            <span>{timestamp}</span>
          </span>
        </div>

        {onInvestigate && (
          <Button
            size="sm"
            onClick={() => onInvestigate(alertId)}
            className="h-7 text-xs bg-cyan-950/80 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 gap-1.5 font-bold"
          >
            <span>Launch Case</span>
            <ArrowRight className="w-3 h-3" />
          </Button>
        )}
      </div>
    </div>
  );
};
