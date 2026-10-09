import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';
import type { SeverityLevel, InvestigationStatus, AlertStatus } from '../types/soc';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function getSeverityBadgeClass(severity: SeverityLevel): string {
  switch (severity) {
    case 'Critical':
      return 'bg-rose-950/80 text-rose-300 border-rose-700/60 shadow-[0_0_10px_rgba(244,63,94,0.15)]';
    case 'High':
      return 'bg-amber-950/70 text-amber-300 border-amber-700/60 shadow-[0_0_10px_rgba(245,158,11,0.1)]';
    case 'Medium':
      return 'bg-yellow-950/60 text-yellow-300 border-yellow-700/50';
    case 'Low':
      return 'bg-blue-950/60 text-blue-300 border-blue-700/50';
    default:
      return 'bg-slate-800 text-slate-300 border-slate-700';
  }
}

export function getSeverityDotClass(severity: SeverityLevel): string {
  switch (severity) {
    case 'Critical':
      return 'bg-rose-500 shadow-[0_0_6px_#f43f5e]';
    case 'High':
      return 'bg-amber-500';
    case 'Medium':
      return 'bg-yellow-400';
    case 'Low':
      return 'bg-blue-400';
    default:
      return 'bg-slate-400';
  }
}

export function getStatusBadgeClass(status: InvestigationStatus): string {
  switch (status) {
    case 'Investigating':
      return 'bg-sky-950/70 text-sky-300 border-sky-600/60 animate-pulse';
    case 'Awaiting Review':
      return 'bg-amber-950/60 text-amber-300 border-amber-600/50';
    case 'Completed':
      return 'bg-emerald-950/60 text-emerald-300 border-emerald-600/50';
    case 'Inconclusive':
      return 'bg-purple-950/60 text-purple-300 border-purple-600/50';
    default:
      return 'bg-slate-800 text-slate-300 border-slate-700';
  }
}

export function getAlertStatusBadgeClass(status: AlertStatus): string {
  switch (status) {
    case 'Open':
      return 'bg-red-950/50 text-red-300 border-red-800/40';
    case 'Triaged':
      return 'bg-cyan-950/50 text-cyan-300 border-cyan-800/40';
    case 'Escalated':
      return 'bg-purple-950/50 text-purple-300 border-purple-800/40';
    case 'Resolved':
      return 'bg-emerald-950/50 text-emerald-300 border-emerald-800/40';
    case 'Suppressed':
      return 'bg-slate-800/80 text-slate-400 border-slate-700/40';
    default:
      return 'bg-slate-800 text-slate-300 border-slate-700';
  }
}

export function getTrustScoreColor(score: number): {
  textColor: string;
  bgColor: string;
  borderColor: string;
  barColor: string;
  label: string;
} {
  if (score >= 85) {
    return {
      textColor: 'text-emerald-400',
      bgColor: 'bg-emerald-950/50',
      borderColor: 'border-emerald-700/60',
      barColor: 'bg-emerald-500',
      label: 'High Corroboration',
    };
  } else if (score >= 65) {
    return {
      textColor: 'text-cyan-400',
      bgColor: 'bg-cyan-950/50',
      borderColor: 'border-cyan-700/60',
      barColor: 'bg-cyan-500',
      label: 'Moderate Corroboration',
    };
  } else {
    return {
      textColor: 'text-amber-400',
      bgColor: 'bg-amber-950/50',
      borderColor: 'border-amber-700/60',
      barColor: 'bg-amber-500',
      label: 'Low / Divergent Telemetry',
    };
  }
}
