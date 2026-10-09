import React, { useState, useEffect, useRef } from 'react';
import {
  Search,
  X,
  SearchCode,
  BellRing,
  FileCheck2,
  Bot,
  History,
  FolderArchive,
  ArrowRight,
  Sparkles,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type { UniversalSearchResponse, SearchResultItem } from '../../types/soc';

interface UniversalOmnibarModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSelectInvestigation?: (id: string) => void;
  onNavigateTab?: (tab: string) => void;
}

const CATEGORY_TABS = [
  { id: 'all', label: 'All Results' },
  { id: 'investigations', label: 'Investigations' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'agents', label: 'Agents' },
  { id: 'audit_trail', label: 'Audit Trail' },
];

export const UniversalOmnibarModal: React.FC<UniversalOmnibarModalProps> = ({
  isOpen,
  onClose,
  onSelectInvestigation,
  onNavigateTab,
}) => {
  const [query, setQuery] = useState('');
  const [activeCategory, setActiveCategory] = useState('all');
  const [isLoading, setIsLoading] = useState(false);
  const [searchResults, setSearchResults] = useState<UniversalSearchResponse | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Focus input when modal opens
  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery('');
      setSearchResults(null);
    }
  }, [isOpen]);

  // Handle escape key
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && isOpen) {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  // Execute search with debounce
  useEffect(() => {
    const trimmed = query.trim();
    if (!trimmed) {
      setSearchResults(null);
      setIsLoading(false);
      return;
    }

    const timer = setTimeout(async () => {
      setIsLoading(true);
      try {
        const res = await socApi.searchUniversal(trimmed);
        setSearchResults(res);
      } catch (err) {
        console.error('Universal omnibar search error:', err);
      } finally {
        setIsLoading(false);
      }
    }, 200);

    return () => clearTimeout(timer);
  }, [query]);

  if (!isOpen) return null;

  const results = searchResults?.results || [];
  const filteredResults =
    activeCategory === 'all'
      ? results
      : results.filter((r) => r.category.toLowerCase() === activeCategory.toLowerCase());

  const handleItemClick = (item: SearchResultItem) => {
    onClose();
    if (item.category === 'investigations') {
      if (onSelectInvestigation) onSelectInvestigation(item.id);
      else if (onNavigateTab) onNavigateTab('investigations');
    } else if (item.category === 'evidence') {
      if (onNavigateTab) onNavigateTab('evidence');
    } else if (item.category === 'agents') {
      if (onNavigateTab) onNavigateTab('agents');
    } else if (item.category === 'audit_trail') {
      if (onNavigateTab) onNavigateTab('audit-trail');
    } else if (item.category === 'alerts') {
      if (onNavigateTab) onNavigateTab('alerts');
    } else if (item.category === 'cases') {
      if (onNavigateTab) onNavigateTab('cases');
    } else {
      if (onNavigateTab) onNavigateTab('dashboard');
    }
  };

  const getCategoryIcon = (category: string) => {
    switch (category.toLowerCase()) {
      case 'investigations':
        return <SearchCode className="w-4 h-4 text-cyan-400" />;
      case 'evidence':
        return <FileCheck2 className="w-4 h-4 text-emerald-400" />;
      case 'alerts':
        return <BellRing className="w-4 h-4 text-rose-400" />;
      case 'agents':
        return <Bot className="w-4 h-4 text-indigo-400" />;
      case 'audit_trail':
        return <History className="w-4 h-4 text-amber-400" />;
      default:
        return <FolderArchive className="w-4 h-4 text-slate-400" />;
    }
  };

  const getSeverityBadgeClass = (severity?: string | null) => {
    if (!severity) return 'bg-slate-800 text-slate-400 border-slate-700';
    const s = severity.toUpperCase();
    if (s.includes('CRIT') || s.includes('HIGH')) {
      return 'bg-rose-950/80 text-rose-300 border-rose-800/60';
    }
    if (s.includes('MED') || s.includes('WARN')) {
      return 'bg-amber-950/80 text-amber-300 border-amber-800/60';
    }
    if (s.includes('VERIF') || s.includes('LOW') || s.includes('SUCC')) {
      return 'bg-emerald-950/80 text-emerald-300 border-emerald-800/60';
    }
    return 'bg-cyan-950/80 text-cyan-300 border-cyan-800/60';
  };

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-16 sm:pt-24 px-4 bg-black/80 backdrop-blur-md animate-in fade-in duration-150">
      <div className="w-full max-w-3xl bg-[#0B0F19] border border-slate-800 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[80vh]">
        {/* Search Input Bar */}
        <div className="p-4 border-b border-slate-800 flex items-center gap-3 bg-[#090D16]">
          <Search className="w-5 h-5 text-cyan-400 shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Universal search: investigations, evidence IDs, agents, alerts, audit trail..."
            className="flex-1 bg-transparent text-sm text-slate-100 placeholder-slate-500 outline-none font-mono"
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              className="p-1 rounded text-slate-400 hover:text-slate-200 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          <button
            onClick={onClose}
            className="text-xs font-mono text-slate-400 hover:text-slate-200 border border-slate-700 px-2 py-1 rounded bg-slate-900 transition-colors"
          >
            ESC
          </button>
        </div>

        {/* Category Filter Chips */}
        <div className="px-4 py-2.5 border-b border-slate-800/80 bg-[#070A10] flex items-center gap-2 overflow-x-auto text-xs">
          {CATEGORY_TABS.map((tab) => {
            const count =
              tab.id === 'all'
                ? searchResults?.total_matches
                : searchResults?.categories?.[tab.id];
            const isActive = activeCategory === tab.id;

            return (
              <button
                key={tab.id}
                onClick={() => setActiveCategory(tab.id)}
                className={`px-3 py-1 rounded-full text-xs font-mono whitespace-nowrap transition-colors flex items-center gap-1.5 ${
                  isActive
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-bold'
                    : 'bg-slate-900/60 text-slate-400 border border-slate-800 hover:border-slate-700 hover:text-slate-200'
                }`}
              >
                <span>{tab.label}</span>
                {count !== undefined && count > 0 && (
                  <span
                    className={`text-[10px] px-1.5 py-0.2 rounded-full ${
                      isActive ? 'bg-cyan-800/60 text-cyan-200' : 'bg-slate-800 text-slate-400'
                    }`}
                  >
                    {count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Results Area */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2">
          {isLoading ? (
            <div className="py-12 text-center text-slate-400 text-xs font-mono flex items-center justify-center gap-2">
              <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
              Executing universal query across SOC telemetry database...
            </div>
          ) : !query.trim() ? (
            <div className="py-10 text-center space-y-4">
              <div className="w-12 h-12 rounded-2xl bg-cyan-950/40 border border-cyan-800/40 text-cyan-400 flex items-center justify-center mx-auto">
                <Sparkles className="w-6 h-6" />
              </div>
              <div className="space-y-1">
                <h4 className="text-sm font-bold text-slate-200 font-mono">
                  Universal Omnibar Navigation
                </h4>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Type any entity identifier, alert keyword, evidence hash, or agent action to instantly navigate the platform.
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
                {['powershell', 'INV-001', 'EV-001', 'mimikatz', 'critic', 'APT-29'].map((preset) => (
                  <button
                    key={preset}
                    onClick={() => setQuery(preset)}
                    className="px-2.5 py-1 rounded bg-slate-900 border border-slate-800 hover:border-cyan-800 text-slate-300 hover:text-cyan-300 text-xs font-mono transition-colors"
                  >
                    {preset}
                  </button>
                ))}
              </div>
            </div>
          ) : filteredResults.length === 0 ? (
            <div className="py-12 text-center text-slate-400 text-xs font-mono">
              No matching records found for "{query}" in {activeCategory}.
            </div>
          ) : (
            filteredResults.map((item) => (
              <div
                key={`${item.category}-${item.id}`}
                onClick={() => handleItemClick(item)}
                className="p-3 rounded-xl bg-slate-900/50 hover:bg-slate-900 border border-slate-800/80 hover:border-cyan-800/60 transition-all cursor-pointer group flex items-start justify-between gap-3"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <div className="mt-0.5 p-2 rounded-lg bg-slate-950 border border-slate-800 shrink-0">
                    {getCategoryIcon(item.category)}
                  </div>
                  <div className="min-w-0 space-y-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-xs font-bold text-slate-200 group-hover:text-cyan-300 transition-colors font-mono truncate">
                        {item.title}
                      </span>
                      {item.severity_or_status && (
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded border uppercase ${getSeverityBadgeClass(
                            item.severity_or_status
                          )}`}
                        >
                          {item.severity_or_status}
                        </span>
                      )}
                      <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">
                        {item.category}
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 line-clamp-2 leading-relaxed">
                      {item.description}
                    </p>
                    {item.timestamp && (
                      <div className="text-[10px] font-mono text-slate-500">
                        {item.timestamp}
                      </div>
                    )}
                  </div>
                </div>
                <div className="shrink-0 pt-1 text-slate-600 group-hover:text-cyan-400 transition-colors">
                  <ArrowRight className="w-4 h-4" />
                </div>
              </div>
            ))
          )}
        </div>

        {/* Footer info */}
        <div className="p-3 border-t border-slate-800/80 bg-[#070A10] flex items-center justify-between text-[11px] text-slate-500 font-mono">
          <span>Navigate with click or arrow keys</span>
          <span>Press ESC to dismiss</span>
        </div>
      </div>
    </div>
  );
};
