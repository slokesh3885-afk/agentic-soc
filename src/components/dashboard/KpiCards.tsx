import type { DashboardKpi } from '../../types/soc';
import {
  SearchCode,
  BellRing,
  ShieldAlert,
  HelpCircle,
  ShieldCheck,
  Info,
} from 'lucide-react';
import { cn } from '../../lib/utils';

interface KpiCardsProps {
  kpis: DashboardKpi | null;
}

export const KpiCards: React.FC<KpiCardsProps> = ({ kpis }) => {
  if (!kpis) return null;

  const cards = [
    {
      title: 'Active Investigations',
      value: kpis.activeInvestigations,
      delta: kpis.investigationsDelta || '+2 active',
      deltaType: 'neutral',
      icon: SearchCode,
      color: 'text-sky-400',
      bgColor: 'bg-sky-950/40',
      borderColor: 'border-sky-800/50',
      subtext: 'Autonomous & analyst triage',
    },
    {
      title: 'Open Alerts',
      value: kpis.openAlerts,
      delta: kpis.alertsDelta || '-14% vs 24h avg',
      deltaType: 'good',
      icon: BellRing,
      color: 'text-rose-400',
      bgColor: 'bg-rose-950/30',
      borderColor: 'border-rose-800/50',
      subtext: '4 Critical • 7 High • 8 Medium/Low',
    },
    {
      title: 'Confirmed Threats',
      value: kpis.confirmedThreats,
      delta: kpis.threatsDelta || '+3 verified today',
      deltaType: 'warning',
      icon: ShieldAlert,
      color: 'text-amber-400',
      bgColor: 'bg-amber-950/30',
      borderColor: 'border-amber-800/50',
      subtext: 'Requires containment action',
    },
    {
      title: 'Inconclusive Cases',
      value: kpis.inconclusiveCases,
      delta: kpis.inconclusiveDelta || 'Pending memory dump',
      deltaType: 'neutral',
      icon: HelpCircle,
      color: 'text-purple-400',
      bgColor: 'bg-purple-950/30',
      borderColor: 'border-purple-800/50',
      subtext: 'Insufficient telemetry signals',
    },
    {
      title: 'Average Trust Score',
      value: `${kpis.averageTrustScore}%`,
      delta: kpis.trustScoreDelta || '+4.1% cross-validated',
      deltaType: 'good',
      icon: ShieldCheck,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-950/30',
      borderColor: 'border-emerald-800/50',
      subtext: 'Evidence Trust Score',
      isTrustScore: true,
    },
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
      {cards.map((card, idx) => {
        const Icon = card.icon;

        return (
          <div
            key={idx}
            className={cn(
              'relative rounded-xl p-4 transition-all duration-200',
              'bg-[#0F172A]/80 border backdrop-blur-sm',
              'hover:border-slate-700/80 hover:bg-[#111C33]',
              card.borderColor
            )}
          >
            {/* Top row: Title and Icon */}
            <div className="flex items-start justify-between">
              <span className="text-xs font-medium text-slate-400">
                {card.title}
              </span>
              <div
                className={cn(
                  'w-8 h-8 rounded-lg flex items-center justify-center border',
                  card.bgColor,
                  card.borderColor
                )}
              >
                <Icon className={cn('w-4 h-4', card.color)} />
              </div>
            </div>

            {/* Metric Value */}
            <div className="mt-2 flex items-baseline gap-2">
              <span className="text-2xl font-bold font-mono tracking-tight text-white">
                {card.value}
              </span>
              {card.isTrustScore && (
                <span className="text-[10px] uppercase font-bold tracking-wider px-1.5 py-0.5 rounded bg-emerald-950/80 border border-emerald-700/60 text-emerald-300">
                  HIGH
                </span>
              )}
            </div>

            {/* Subtext and Delta */}
            <div className="mt-2.5 pt-2 border-t border-slate-800/80 flex items-center justify-between text-xs">
              <span className="text-slate-400 text-[11px] truncate" title={card.subtext}>
                {card.subtext}
              </span>
              <span
                className={cn(
                  'font-mono text-[10px] font-medium shrink-0',
                  card.deltaType === 'good'
                    ? 'text-emerald-400'
                    : card.deltaType === 'warning'
                    ? 'text-amber-400'
                    : 'text-slate-400'
                )}
              >
                {card.delta}
              </span>
            </div>

            {card.isTrustScore && (
              <div className="mt-1 text-[10px] text-cyan-400/90 font-mono flex items-center gap-1">
                <Info className="w-3 h-3 shrink-0" />
                <span>Not LLM confidence</span>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
};
