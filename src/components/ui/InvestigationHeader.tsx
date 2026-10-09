import React, { useState } from 'react';
import type { Investigation, InvestigationStatus } from '../../types/soc';
import {
  Server,
  Clock,
  User,
  Copy,
  Check,
  RefreshCw,
  X,
} from 'lucide-react';
import { StatusBadge } from './StatusBadge';
import { Button } from './Button';
import { cn } from '../../lib/utils';

export type InvestigationPriority = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | string;

export interface InvestigationHeaderData {
  id: string;
  title: string;
  status: InvestigationStatus | string;
  priority?: InvestigationPriority;
  target_host?: string;
  targetHost?: string;
  lead_agent?: string;
  leadAgent?: string;
  created_at?: string;
  createdAt?: string;
  description?: string;
}

export interface InvestigationHeaderProps {
  investigation: InvestigationHeaderData | Investigation | any;
  onClose?: () => void;
  onRefresh?: () => void;
  isRefreshing?: boolean;
  actions?: React.ReactNode;
  className?: string;
}

export const InvestigationHeader: React.FC<InvestigationHeaderProps> = ({
  investigation,
  onClose,
  onRefresh,
  isRefreshing = false,
  actions,
  className,
}) => {
  const [copied, setCopied] = useState(false);

  const id = investigation.id || 'INV-000';
  const title = investigation.title || 'Security Investigation';
  const status = investigation.status || 'INVESTIGATING';
  const priority = investigation.priority || 'HIGH';
  const targetHost = investigation.target_host || investigation.targetHost;
  const leadAgent = investigation.lead_agent || investigation.leadAgent || 'Lead Investigator';
  const createdAt = investigation.created_at || investigation.createdAt || 'Recent';

  const handleCopyId = () => {
    navigator.clipboard.writeText(id);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  return (
    <div
      className={cn(
        'p-4 sm:p-5 bg-[#0B0F19] border-b border-slate-800 font-mono shadow-md flex flex-col gap-3',
        className
      )}
    >
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        {/* Case ID & Badges */}
        <div className="flex flex-wrap items-center gap-2.5">
          <button
            onClick={handleCopyId}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-cyan-950/80 border border-cyan-800/70 text-cyan-300 hover:bg-cyan-900/90 text-xs font-bold transition-colors"
            title="Copy Case ID"
          >
            <span>{id}</span>
            {copied ? (
              <Check className="w-3 h-3 text-emerald-400" />
            ) : (
              <Copy className="w-3 h-3 opacity-70" />
            )}
          </button>

          <StatusBadge status={status} size="sm" pulse={status === 'INVESTIGATING'} />
          <StatusBadge status={priority} size="sm" />
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2 self-start sm:self-auto">
          {onRefresh && (
            <Button
              size="sm"
              variant="outline"
              onClick={onRefresh}
              disabled={isRefreshing}
              className="h-8 px-2.5 text-xs text-slate-300 border-slate-700 hover:bg-slate-800 gap-1.5"
              title="Refresh Case Telemetry"
            >
              <RefreshCw className={cn('w-3.5 h-3.5', isRefreshing && 'animate-spin')} />
              <span className="hidden sm:inline">Refresh</span>
            </Button>
          )}

          {actions}

          {onClose && (
            <Button
              size="sm"
              variant="ghost"
              onClick={onClose}
              className="h-8 w-8 p-0 text-slate-400 hover:text-slate-100 hover:bg-slate-800"
              title="Close Case"
            >
              <X className="w-4 h-4" />
            </Button>
          )}
        </div>
      </div>

      {/* Title */}
      <div>
        <h2 className="text-base sm:text-lg font-bold text-slate-100 leading-snug">
          {title}
        </h2>
      </div>

      {/* Metadata Pill Bar */}
      <div className="flex flex-wrap items-center gap-3 pt-1 text-xs text-slate-400">
        {targetHost && (
          <span className="flex items-center gap-1.5 text-slate-300 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
            <Server className="w-3.5 h-3.5 text-cyan-400" />
            <span>Host: {targetHost}</span>
          </span>
        )}

        <span className="flex items-center gap-1.5 text-slate-300 bg-slate-900/80 px-2 py-0.5 rounded border border-slate-800">
          <User className="w-3.5 h-3.5 text-purple-400" />
          <span>Lead: {leadAgent}</span>
        </span>

        <span className="flex items-center gap-1.5 text-slate-500">
          <Clock className="w-3.5 h-3.5" />
          <span>Created: {createdAt}</span>
        </span>
      </div>
    </div>
  );
};
