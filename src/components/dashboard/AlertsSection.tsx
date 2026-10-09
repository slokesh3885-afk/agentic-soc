import React, { useState } from 'react';
import type { SecurityAlert } from '../../types/soc';
import { BellRing } from 'lucide-react';
import { cn } from '../../lib/utils';
import { AlertCard } from '../ui/AlertCard';

interface AlertsSectionProps {
  alerts: SecurityAlert[];
  onInvestigateAlert?: (alert: SecurityAlert) => void;
}

export const AlertsSection: React.FC<AlertsSectionProps> = ({
  alerts,
  onInvestigateAlert,
}) => {
  const [severityFilter, setSeverityFilter] = useState<string>('All');

  const severityFilters = ['All', 'Critical', 'High', 'Medium', 'Low'];

  const filteredAlerts = alerts.filter((alert) => {
    if (severityFilter === 'All') return true;
    return alert.severity === severityFilter;
  });

  return (
    <div className="bg-[#0F172A]/90 border border-slate-800/80 rounded-xl overflow-hidden shadow-lg backdrop-blur-sm">
      {/* Header */}
      <div className="p-4 sm:p-5 border-b border-slate-800/80 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <BellRing className="w-5 h-5 text-rose-400" />
            <h2 className="text-base font-bold text-slate-100">Security Alerts Stream</h2>
            <span className="font-mono text-xs px-2 py-0.5 rounded-full bg-rose-950/70 text-rose-300 border border-rose-800/50">
              {alerts.length} Ingested
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Real-time SIEM, EDR, and Cloud IDS normalized event queue
          </p>
        </div>

        {/* Severity Filter Buttons */}
        <div className="flex items-center gap-1.5 overflow-x-auto pb-1 sm:pb-0">
          <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mr-1 hidden md:inline">
            Severity:
          </span>
          {severityFilters.map((sev) => {
            const isActive = severityFilter === sev;
            return (
              <button
                key={sev}
                onClick={() => setSeverityFilter(sev)}
                className={cn(
                  'px-2.5 py-1 rounded text-xs font-semibold transition-all',
                  isActive
                    ? 'bg-slate-800 text-cyan-300 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                )}
              >
                {sev}
              </button>
            );
          })}
        </div>
      </div>

      {/* Alerts Stream using Reusable Canonical AlertCard */}
      <div className="p-4 space-y-3 max-h-[500px] overflow-y-auto divide-y divide-transparent">
        {filteredAlerts.length === 0 ? (
          <div className="py-12 text-center text-slate-400 text-xs font-mono">
            No alerts found for severity level "{severityFilter}".
          </div>
        ) : (
          filteredAlerts.map((alert) => (
            <AlertCard
              key={alert.id}
              alert={alert}
              onInvestigate={() => onInvestigateAlert?.(alert)}
            />
          ))
        )}
      </div>
    </div>
  );
};

