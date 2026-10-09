import React, { useState, useEffect } from 'react';
import {
  Clock,
  ChevronDown,
  RefreshCw,
  Search,
  Bell,
} from 'lucide-react';
import { cn } from '../../lib/utils';
import { NotificationCenterDropdown } from './NotificationCenterDropdown';
import { socApi } from '../../lib/api';

interface TopBarProps {
  onRefresh?: () => void;
  isLoading?: boolean;
  isBackendConnected?: boolean;
  connectionMessage?: string;
  isWebSocketConnected?: boolean;
  wsEventCount?: number;
  onSelectInvestigation?: (id: string) => void;
  onOpenOmnibar?: () => void;
}

export const TopBar: React.FC<TopBarProps> = ({
  onRefresh,
  isLoading = false,
  isBackendConnected = true,
  connectionMessage,
  isWebSocketConnected = true,
  wsEventCount,
  onSelectInvestigation,
  onOpenOmnibar,
}) => {
  const [currentTime, setCurrentTime] = useState({
    utc: '',
    local: '',
    date: '',
  });
  const [isNotificationsOpen, setIsNotificationsOpen] = useState(false);
  const [unreadCount, setUnreadCount] = useState(3);

  // Fetch initial unread count
  useEffect(() => {
    socApi
      .getNotifications()
      .then((res) => {
        if (res && res.unread_count !== undefined) {
          setUnreadCount(res.unread_count);
        }
      })
      .catch(() => {});
  }, [isNotificationsOpen]);

  useEffect(() => {
    const updateTimes = () => {
      const now = new Date();

      const utcTime = now.toISOString().slice(11, 19) + ' UTC';
      const localTime = now.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
      });
      const dateStr = now.toLocaleDateString('en-US', {
        weekday: 'short',
        month: 'short',
        day: 'numeric',
        year: 'numeric',
      });

      setCurrentTime({ utc: utcTime, local: localTime, date: dateStr });
    };

    updateTimes();
    const interval = setInterval(updateTimes, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <header className="h-16 bg-[#0B0F19]/95 border-b border-slate-800/80 px-4 sm:px-6 flex items-center justify-between sticky top-0 z-30 backdrop-blur-md">
      {/* Left: Product Name & Active Investigation Indicator */}
      <div className="flex items-center gap-3 md:gap-4 shrink-0">
        <div>
          <div className="flex items-center gap-2">
            <span className="text-base font-bold text-slate-100 font-mono tracking-tight">
              Agentic SOC
            </span>
            <span className="text-[10px] font-mono font-bold text-cyan-400 bg-cyan-950/70 border border-cyan-800/60 px-1.5 py-0.5 rounded">
              ENTERPRISE
            </span>
          </div>
          <p className="text-[11px] text-slate-400 hidden xl:block">
            Autonomous Cyber Investigation Platform
          </p>
        </div>

        {/* Active Investigation Indicator Badge (Spec Line 57) */}
        <div
          onClick={() => onSelectInvestigation && onSelectInvestigation('INV-001')}
          title="Click to inspect active high-priority investigation INV-001"
          className="hidden md:flex items-center gap-2 px-2.5 py-1 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-cyan-800/80 hover:bg-slate-900 cursor-pointer transition-all group"
        >
          <span className="relative flex h-2 w-2 shrink-0">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-rose-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-rose-500"></span>
          </span>
          <div className="flex items-center gap-1.5 text-xs font-mono">
            <span className="text-slate-400 group-hover:text-slate-200 transition-colors">Active:</span>
            <span className="text-cyan-300 font-bold group-hover:underline">INV-001</span>
            <span className="text-slate-500">|</span>
            <span className="text-slate-300 hidden lg:inline">WORKSTATION-89</span>
            <span className="text-[10px] font-bold px-1.5 py-0.2 bg-rose-950/90 text-rose-300 border border-rose-800/80 rounded">
              HIGH
            </span>
          </div>
        </div>
      </div>

      {/* Middle: Universal Omnibar Trigger & System Status */}
      <div className="flex items-center gap-3 md:gap-4">
        {/* Omnibar Search Trigger Button (Spec Line 58) */}
        <button
          onClick={onOpenOmnibar}
          title="Open Universal Omnibar Search (Ctrl+K or /)"
          className="flex items-center gap-2.5 px-3 py-1.5 rounded-xl bg-slate-900/80 hover:bg-slate-900 border border-slate-800 hover:border-cyan-800/80 text-slate-400 hover:text-slate-200 transition-all text-xs font-mono group max-w-[280px] sm:max-w-[340px]"
        >
          <Search className="w-3.5 h-3.5 text-cyan-400 group-hover:scale-110 transition-transform shrink-0" />
          <span className="truncate hidden sm:inline">Search investigations, evidence, agents...</span>
          <span className="truncate sm:hidden">Search...</span>
          <kbd className="hidden lg:inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded bg-slate-950 border border-slate-800 text-[10px] text-slate-400 font-mono">
            Ctrl K
          </kbd>
        </button>

        {/* System & Backend Status Indicator (Spec Line 56) */}
        <div
          className={cn(
            'hidden lg:flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs transition-colors shrink-0',
            isBackendConnected
              ? 'bg-slate-900/80 border-slate-800'
              : 'bg-amber-950/40 border-amber-800/60 text-amber-300'
          )}
          title={connectionMessage || (isBackendConnected ? 'FastAPI + SQLite Online' : 'FastAPI Offline')}
        >
          <span className="relative flex h-2 w-2">
            {isBackendConnected ? (
              <>
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
              </>
            ) : (
              <>
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-amber-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500"></span>
              </>
            )}
          </span>
          <span className="font-medium text-slate-200 text-xs">
            {isBackendConnected ? 'All Systems Operational' : 'Backend Reconnecting'}
          </span>
        </div>

        {/* Live Telemetry WebSocket Indicator */}
        <div
          className={cn(
            'hidden 2xl:flex items-center gap-2 px-2.5 py-1 rounded-full border text-[11px] font-mono transition-colors shrink-0',
            isWebSocketConnected
              ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-400'
              : 'bg-slate-900/60 border-slate-800 text-slate-400'
          )}
          title={isWebSocketConnected ? 'Real-time WebSocket Live Telemetry Active' : 'WebSocket Standby'}
        >
          <span className="relative flex h-1.5 w-1.5">
            {isWebSocketConnected && (
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            )}
            <span
              className={cn(
                'relative inline-flex rounded-full h-1.5 w-1.5',
                isWebSocketConnected ? 'bg-emerald-500' : 'bg-slate-500'
              )}
            ></span>
          </span>
          <span>{isWebSocketConnected ? 'WS: Live' : 'WS: Idle'}</span>
          {wsEventCount !== undefined && wsEventCount > 0 && (
            <span className="text-[10px] text-emerald-300 font-bold bg-emerald-900/60 px-1 py-0.2 rounded-full border border-emerald-700/60">
              {wsEventCount}
            </span>
          )}
        </div>
      </div>

      {/* Right: Notifications, Refresh, Clock, User Profile */}
      <div className="flex items-center gap-2.5 sm:gap-3 shrink-0">
        {/* Live Date & Time Clock */}
        <div className="hidden xl:flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-slate-900/50 border border-slate-800/80 font-mono text-xs text-slate-300 shrink-0">
          <Clock className="w-3.5 h-3.5 text-cyan-400" />
          <span className="text-slate-400">{currentTime.date}</span>
          <span className="text-slate-600">|</span>
          <span className="text-cyan-300 font-semibold">{currentTime.utc}</span>
        </div>

        {/* Notifications Button & Dropdown (Spec Line 59) */}
        <div className="relative">
          <button
            onClick={() => setIsNotificationsOpen((prev) => !prev)}
            title="Real-Time SOC Notifications"
            className={cn(
              'p-2 rounded-lg border transition-all relative',
              isNotificationsOpen
                ? 'bg-cyan-950/60 border-cyan-700 text-cyan-300'
                : 'bg-slate-900/80 border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700'
            )}
          >
            <Bell className="w-4 h-4" />
            {unreadCount > 0 && (
              <span className="absolute -top-1 -right-1 flex h-4 min-w-[16px] px-1 items-center justify-center rounded-full bg-rose-600 text-[10px] font-bold font-mono text-white shadow-md animate-pulse">
                {unreadCount}
              </span>
            )}
          </button>

          <NotificationCenterDropdown
            isOpen={isNotificationsOpen}
            onClose={() => setIsNotificationsOpen(false)}
            onSelectInvestigation={onSelectInvestigation}
          />
        </div>

        {/* Refresh button */}
        {onRefresh && (
          <button
            onClick={onRefresh}
            title="Refresh SOC data"
            className="p-2 rounded-lg bg-slate-900/80 border border-slate-800 text-slate-400 hover:text-slate-200 hover:border-slate-700 transition-colors"
          >
            <RefreshCw className={cn('w-4 h-4', isLoading && 'animate-spin text-cyan-400')} />
          </button>
        )}

        {/* User Profile (Spec Line 60) */}
        <div className="flex items-center gap-2 p-1 pl-2 rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-colors cursor-pointer group">
          <div className="text-right hidden sm:block">
            <div className="text-xs font-semibold text-slate-200 group-hover:text-cyan-300 transition-colors">
              Analyst S. Loke
            </div>
            <div className="text-[10px] text-slate-400 font-mono">SecOps Lead</div>
          </div>
          <div className="relative">
            <div className="w-7 h-7 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center text-cyan-400 font-bold text-xs shadow-inner">
              SL
            </div>
            <span className="absolute bottom-0 right-0 w-2 h-2 rounded-full bg-emerald-500 border border-[#0B0F19]" />
          </div>
          <ChevronDown className="w-3.5 h-3.5 text-slate-400 group-hover:text-slate-300 hidden sm:block" />
        </div>
      </div>
    </header>
  );
};
