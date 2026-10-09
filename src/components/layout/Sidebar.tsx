import {
  LayoutDashboard,
  SearchCode,
  BellRing,
  FolderArchive,
  FileCheck2,
  History,
  RotateCcw,
  FileText,
  Settings,
  Shield,
  Activity,
  ChevronRight,
  Bot,
  Swords,
  BarChart3,
} from 'lucide-react';
import { cn } from '../../lib/utils';

interface SidebarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  investigationCount?: number;
  alertCount?: number;
  agentCount?: number;
  evidenceCount?: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  setActiveTab,
  investigationCount = 4,
  alertCount = 19,
  agentCount = 5,
  evidenceCount = 37,
}) => {
  const navItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'investigations',
      label: 'Investigations',
      icon: SearchCode,
      badge: investigationCount,
      badgeColor: 'bg-sky-950 text-sky-400 border border-sky-800/60',
    },
    {
      id: 'alerts',
      label: 'Alerts',
      icon: BellRing,
      badge: alertCount,
      badgeColor: 'bg-rose-950 text-rose-400 border border-rose-800/60',
    },
    {
      id: 'evidence',
      label: 'Evidence',
      icon: FileCheck2,
      badge: evidenceCount,
      badgeColor: 'bg-emerald-950 text-emerald-400 border border-emerald-800/60',
    },
    {
      id: 'agents',
      label: 'Agents',
      icon: Bot,
      badge: agentCount,
      badgeColor: 'bg-indigo-950 text-indigo-400 border border-indigo-800/60',
    },
    {
      id: 'critic-redteam',
      label: 'Critic / Red-Team',
      icon: Swords,
      badge: 'Red-Team',
      badgeColor: 'bg-rose-950 text-rose-300 border border-rose-800/60',
    },
    {
      id: 'cases',
      label: 'Cases',
      icon: FolderArchive,
      badge: null,
    },
    {
      id: 'audit-trail',
      label: 'Audit Trail',
      icon: History,
      badge: null,
    },
    {
      id: 'replay',
      label: 'Replay',
      icon: RotateCcw,
      badge: null,
    },
    {
      id: 'reports',
      label: 'Reports',
      icon: FileText,
      badge: null,
    },
    {
      id: 'analytics',
      label: 'Analytics & Posture',
      icon: BarChart3,
      badge: '3V',
      badgeColor: 'bg-cyan-950 text-cyan-400 border border-cyan-800/60',
    },
    {
      id: 'settings',
      label: 'Settings',
      icon: Settings,
      badge: null,
    },
  ];

  return (
    <aside className="w-64 bg-[#0B0F19] border-r border-slate-800/80 flex flex-col h-screen shrink-0 select-none">
      {/* Brand Header */}
      <div className="p-5 border-b border-slate-800/80">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500/20 via-blue-600/20 to-indigo-600/30 border border-cyan-500/30 flex items-center justify-center shadow-lg shadow-cyan-950/40">
            <Shield className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <div className="flex items-center gap-1.5">
              <span className="font-bold text-base tracking-tight text-white font-mono">Agentic</span>
              <span className="font-extrabold text-base tracking-tight bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">SOC</span>
            </div>
            <div className="text-[10px] font-semibold tracking-wider uppercase text-slate-400/90">
              Auditable AI SOC
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 p-3 space-y-1 overflow-y-auto">
        <div className="px-3 pt-2 pb-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
          Core Operations
        </div>
        {navItems.map((item) => {
          const Icon = item.icon;
          const isActive = activeTab === item.id;

          return (
            <button
              key={item.id}
              onClick={() => setActiveTab(item.id)}
              className={cn(
                'w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all group',
                isActive
                  ? 'bg-slate-800/90 text-cyan-300 shadow-sm border border-cyan-500/30'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/80 border border-transparent'
              )}
            >
              <div className="flex items-center gap-3">
                <Icon
                  className={cn(
                    'w-4 h-4 transition-colors',
                    isActive ? 'text-cyan-400' : 'text-slate-400 group-hover:text-slate-300'
                  )}
                />
                <span>{item.label}</span>
              </div>

              <div className="flex items-center gap-1.5">
                {item.badge !== null && (
                  <span
                    className={cn(
                      'text-[11px] font-mono px-2 py-0.5 rounded-full font-semibold',
                      item.badgeColor
                    )}
                  >
                    {item.badge}
                  </span>
                )}
                {isActive && <ChevronRight className="w-3.5 h-3.5 text-cyan-400" />}
              </div>
            </button>
          );
        })}
      </nav>

      {/* Engine Status / Telemetry Footer */}
      <div className="p-3.5 border-t border-slate-800/80 bg-slate-950/40">
        <div className="p-3 rounded-lg bg-slate-900/60 border border-slate-800/80 text-xs">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-slate-400 text-[11px] font-medium flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-emerald-400" />
              SOC Telemetry Bus
            </span>
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-ping" />
          </div>
          <div className="font-mono text-[11px] text-slate-300 flex justify-between">
            <span>Cluster:</span>
            <span className="text-slate-400">US-EAST-01</span>
          </div>
          <div className="font-mono text-[11px] text-slate-300 flex justify-between mt-0.5">
            <span>Ingestion:</span>
            <span className="text-emerald-400 font-medium">9.4k eps (Active)</span>
          </div>
        </div>
      </div>
    </aside>
  );
};
