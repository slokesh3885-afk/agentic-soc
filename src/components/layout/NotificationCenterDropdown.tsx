import React, { useState, useEffect, useRef } from 'react';
import {
  Bell,
  Check,
  CheckCheck,
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle2,
  RefreshCw,
  X,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type { SocNotificationItem } from '../../types/soc';

interface NotificationCenterDropdownProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectInvestigation?: (id: string) => void;
}

export const NotificationCenterDropdown: React.FC<NotificationCenterDropdownProps> = ({
  isOpen,
  onClose,
  onSelectInvestigation,
}) => {
  const [notifications, setNotifications] = useState<SocNotificationItem[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [filter, setFilter] = useState<'all' | 'unread'>('all');
  const [isLoading, setIsLoading] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const fetchNotifications = async () => {
    try {
      setIsLoading(true);
      const res = await socApi.getNotifications();
      setNotifications(res.notifications || []);
      setUnreadCount(res.unread_count || 0);
    } catch (err) {
      console.error('Failed to fetch notifications:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchNotifications();
    }
  }, [isOpen]);

  // Click outside listener
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    if (isOpen) {
      document.addEventListener('mousedown', handleClickOutside);
    }
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const handleMarkRead = async (id: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      await socApi.markNotificationRead(id);
      setNotifications((prev) =>
        prev.map((n) => (n.id === id ? { ...n, read: true } : n))
      );
      setUnreadCount((prev) => Math.max(0, prev - 1));
    } catch (err) {
      console.error('Failed to mark notification read:', err);
    }
  };

  const handleMarkAllRead = async () => {
    try {
      await socApi.markAllNotificationsRead();
      setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
      setUnreadCount(0);
    } catch (err) {
      console.error('Failed to mark all read:', err);
    }
  };

  const handleItemClick = (n: SocNotificationItem) => {
    if (n.reference_id && onSelectInvestigation) {
      if (n.reference_id.startsWith('INV-') || n.reference_id.startsWith('CASE-')) {
        onSelectInvestigation(n.reference_id);
        onClose();
      }
    }
  };

  const displayedNotifications =
    filter === 'unread' ? notifications.filter((n) => !n.read) : notifications;

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0" />;
      case 'warning':
        return <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0" />;
      case 'success':
        return <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />;
      default:
        return <Info className="w-4 h-4 text-cyan-400 shrink-0" />;
    }
  };

  return (
    <div
      ref={dropdownRef}
      className="absolute right-0 top-14 w-96 max-w-[90vw] bg-[#0B0F19] border border-slate-800 rounded-xl shadow-2xl z-50 overflow-hidden flex flex-col font-sans animate-in fade-in slide-in-from-top-2 duration-150"
    >
      {/* Header */}
      <div className="p-3.5 border-b border-slate-800 bg-[#090D16] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bell className="w-4 h-4 text-cyan-400" />
          <span className="text-xs font-bold text-slate-100 font-mono">
            SOC Notification Center
          </span>
          {unreadCount > 0 && (
            <span className="text-[10px] font-bold font-mono bg-rose-950 text-rose-400 border border-rose-800/60 px-1.5 py-0.5 rounded-full">
              {unreadCount} unread
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5">
          <button
            onClick={fetchNotifications}
            title="Refresh notifications"
            className="p-1 rounded text-slate-400 hover:text-slate-200 transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          </button>
          <button
            onClick={onClose}
            className="p-1 rounded text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Filter and Actions Bar */}
      <div className="px-3.5 py-2 border-b border-slate-800/80 bg-[#070A10] flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2">
          <button
            onClick={() => setFilter('all')}
            className={`px-2 py-0.5 rounded transition-colors ${
              filter === 'all'
                ? 'bg-slate-800 text-slate-200 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All ({notifications.length})
          </button>
          <button
            onClick={() => setFilter('unread')}
            className={`px-2 py-0.5 rounded transition-colors ${
              filter === 'unread'
                ? 'bg-slate-800 text-slate-200 font-bold'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Unread ({unreadCount})
          </button>
        </div>
        {unreadCount > 0 && (
          <button
            onClick={handleMarkAllRead}
            className="text-[11px] text-cyan-400 hover:text-cyan-300 flex items-center gap-1 transition-colors"
          >
            <CheckCheck className="w-3 h-3" />
            Mark all read
          </button>
        )}
      </div>

      {/* Notification List */}
      <div className="max-h-[380px] overflow-y-auto divide-y divide-slate-800/60 p-1">
        {displayedNotifications.length === 0 ? (
          <div className="py-10 text-center text-slate-500 text-xs font-mono">
            No {filter === 'unread' ? 'unread' : ''} notifications.
          </div>
        ) : (
          displayedNotifications.map((n) => (
            <div
              key={n.id}
              onClick={() => handleItemClick(n)}
              className={`p-3 rounded-lg transition-colors flex items-start gap-2.5 cursor-pointer ${
                n.read
                  ? 'bg-transparent hover:bg-slate-900/50 opacity-75'
                  : 'bg-slate-900/40 hover:bg-slate-900 border-l-2 border-cyan-400'
              }`}
            >
              <div className="mt-0.5">{getSeverityIcon(n.severity)}</div>
              <div className="flex-1 min-w-0 space-y-1">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold text-slate-200 truncate">
                    {n.title}
                  </span>
                  {!n.read && (
                    <button
                      onClick={(e) => handleMarkRead(n.id, e)}
                      title="Mark as read"
                      className="p-1 rounded text-slate-400 hover:text-cyan-400 transition-colors"
                    >
                      <Check className="w-3.5 h-3.5" />
                    </button>
                  )}
                </div>
                <p className="text-[11px] text-slate-400 leading-relaxed">
                  {n.message}
                </p>
                <div className="flex items-center gap-2 pt-0.5 text-[10px] font-mono text-slate-500">
                  <span className="uppercase text-slate-400">{n.category}</span>
                  {n.reference_id && (
                    <span className="text-cyan-400 bg-cyan-950/60 px-1 rounded border border-cyan-900/60">
                      {n.reference_id}
                    </span>
                  )}
                  <span>•</span>
                  <span>{new Date(n.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Footer */}
      <div className="p-2.5 border-t border-slate-800 bg-[#090D16] text-center text-[10px] text-slate-500 font-mono">
        Real-time telemetry event feed powered by FastAPI WebSockets
      </div>
    </div>
  );
};
