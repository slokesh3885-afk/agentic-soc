import {
  ResponsiveContainer,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid,
  Legend,
} from 'recharts';
import type { ThreatOverviewPoint } from '../../types/soc';
import { Activity } from 'lucide-react';

interface ThreatOverviewChartProps {
  data: ThreatOverviewPoint[];
}

export const ThreatOverviewChart: React.FC<ThreatOverviewChartProps> = ({ data }) => {
  return (
    <div className="bg-[#0F172A]/90 border border-slate-800/80 rounded-xl p-5 backdrop-blur-sm flex flex-col h-full shadow-lg">
      {/* Header */}
      <div className="flex items-center justify-between pb-3 border-b border-slate-800/80 mb-4">
        <div>
          <h2 className="text-sm font-bold text-slate-100 flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            Threat Overview
          </h2>
          <p className="text-xs text-slate-400">
            Alert volume, confirmed adversarial threats, and inconclusive cases over the last 12h
          </p>
        </div>
        <div className="flex items-center gap-2 text-[11px] font-mono text-slate-400">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-pulse" />
          <span>Real-time stream</span>
        </div>
      </div>

      {/* Chart */}
      <div className="flex-1 w-full min-h-[220px]">
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
            <defs>
              {/* Alerts Gradient */}
              <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#38BDF8" stopOpacity={0.35} />
                <stop offset="95%" stopColor="#38BDF8" stopOpacity={0.0} />
              </linearGradient>
              {/* Confirmed Threats Gradient */}
              <linearGradient id="threatGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#F43F5E" stopOpacity={0.4} />
                <stop offset="95%" stopColor="#F43F5E" stopOpacity={0.0} />
              </linearGradient>
              {/* Inconclusive Gradient */}
              <linearGradient id="inconclusiveGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#A855F7" stopOpacity={0.3} />
                <stop offset="95%" stopColor="#A855F7" stopOpacity={0.0} />
              </linearGradient>
            </defs>

            <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />

            <XAxis
              dataKey="time"
              stroke="#64748B"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: '#1E293B' }}
            />
            <YAxis
              stroke="#64748B"
              fontSize={11}
              tickLine={false}
              axisLine={{ stroke: '#1E293B' }}
              allowDecimals={false}
            />

            <Tooltip
              content={({ active, payload, label }) => {
                if (active && payload && payload.length) {
                  return (
                    <div className="bg-[#090D16] border border-slate-700/80 p-3 rounded-lg shadow-xl text-xs font-mono">
                      <div className="text-slate-400 font-semibold mb-2 pb-1 border-b border-slate-800">
                        Timestamp: {label}
                      </div>
                      <div className="space-y-1">
                        <div className="flex items-center justify-between gap-4 text-sky-400">
                          <span>Alerts:</span>
                          <span className="font-bold">{payload[0]?.value}</span>
                        </div>
                        <div className="flex items-center justify-between gap-4 text-rose-400">
                          <span>Confirmed Threats:</span>
                          <span className="font-bold">{payload[1]?.value}</span>
                        </div>
                        <div className="flex items-center justify-between gap-4 text-purple-400">
                          <span>Inconclusive:</span>
                          <span className="font-bold">{payload[2]?.value}</span>
                        </div>
                      </div>
                    </div>
                  );
                }
                return null;
              }}
            />

            <Legend
              verticalAlign="top"
              align="right"
              iconType="circle"
              wrapperStyle={{ paddingBottom: '10px', fontSize: '11px' }}
              formatter={(value) => {
                const labels: Record<string, string> = {
                  alerts: 'Alerts over time',
                  confirmedThreats: 'Confirmed threats',
                  inconclusive: 'Inconclusive investigations',
                };
                return <span className="text-slate-300 ml-1">{labels[value] || value}</span>;
              }}
            />

            <Area
              type="monotone"
              dataKey="alerts"
              name="alerts"
              stroke="#38BDF8"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#alertGrad)"
            />
            <Area
              type="monotone"
              dataKey="confirmedThreats"
              name="confirmedThreats"
              stroke="#F43F5E"
              strokeWidth={2}
              fillOpacity={1}
              fill="url(#threatGrad)"
            />
            <Area
              type="monotone"
              dataKey="inconclusive"
              name="inconclusive"
              stroke="#A855F7"
              strokeWidth={1.5}
              strokeDasharray="4 4"
              fillOpacity={1}
              fill="url(#inconclusiveGrad)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
};
