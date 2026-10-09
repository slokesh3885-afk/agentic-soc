import type { Investigation } from '../../types/soc';
import {
  SearchCode,
  Server,
  Eye,
  Search,
  Filter,
  ExternalLink,
} from 'lucide-react';
import {
  getSeverityBadgeClass,
  getStatusBadgeClass,
  cn,
} from '../../lib/utils';
import { TrustScoreBar } from '../ui/TrustScoreBar';
import { Button } from '../ui/Button';

interface InvestigationsTableProps {
  investigations: Investigation[];
  statusFilter: string;
  setStatusFilter: (status: string) => void;
  searchQuery: string;
  setSearchQuery: (query: string) => void;
  onViewInvestigation: (inv: Investigation) => void;
  onOpenNewModal: () => void;
}

export const InvestigationsTable: React.FC<InvestigationsTableProps> = ({
  investigations,
  statusFilter,
  setStatusFilter,
  searchQuery,
  setSearchQuery,
  onViewInvestigation,
  onOpenNewModal,
}) => {
  const statusTabs: { label: string; value: string }[] = [
    { label: 'All', value: 'All' },
    { label: 'Investigating', value: 'Investigating' },
    { label: 'Awaiting Review', value: 'Awaiting Review' },
    { label: 'Completed', value: 'Completed' },
    { label: 'Inconclusive', value: 'Inconclusive' },
  ];

  return (
    <div className="bg-[#0F172A]/90 border border-slate-800/80 rounded-xl overflow-hidden shadow-lg backdrop-blur-sm">
      {/* Top Header / Bar */}
      <div className="p-4 sm:p-5 border-b border-slate-800/80 flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <SearchCode className="w-5 h-5 text-cyan-400" />
            <h2 className="text-base font-bold text-slate-100">Active Investigations</h2>
            <span className="font-mono text-xs px-2 py-0.5 rounded-full bg-slate-800 text-slate-300 border border-slate-700">
              {investigations.length} items
            </span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Automated hypothesis testing, evidence correlation, and human-in-the-loop review
          </p>
        </div>

        {/* Search & Actions */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="relative min-w-[220px]">
            <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter by ID, host, alert..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-9 pr-3 py-1.5 bg-[#0B0F19] border border-slate-700/80 rounded-lg text-xs text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500/80 focus:ring-1 focus:ring-cyan-500/50"
            />
          </div>

          <Button
            variant="primary"
            size="sm"
            onClick={onOpenNewModal}
            className="shadow-sm"
          >
            + New Investigation
          </Button>
        </div>
      </div>

      {/* Filter Tabs */}
      <div className="px-5 py-2.5 bg-[#0B0F19]/60 border-b border-slate-800/80 flex items-center gap-2 overflow-x-auto">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5 mr-2">
          <Filter className="w-3 h-3" /> Status:
        </span>
        {statusTabs.map((tab) => {
          const isActive = statusFilter === tab.value;
          return (
            <button
              key={tab.value}
              onClick={() => setStatusFilter(tab.value)}
              className={cn(
                'px-3 py-1 rounded-md text-xs font-medium transition-all whitespace-nowrap',
                isActive
                  ? 'bg-slate-800 text-cyan-300 border border-cyan-500/40 shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
              )}
            >
              {tab.label}
            </button>
          );
        })}
      </div>

      {/* Table Container */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-slate-800/80 bg-slate-950/40 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              <th className="py-3 px-4">Investigation ID</th>
              <th className="py-3 px-4">Alert</th>
              <th className="py-3 px-4">Host</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4 min-w-[160px]">Evidence Trust Score</th>
              <th className="py-3 px-4">Started</th>
              <th className="py-3 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60 text-xs">
            {investigations.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-12 text-center text-slate-400">
                  <div className="flex flex-col items-center justify-center gap-2">
                    <SearchCode className="w-8 h-8 text-slate-400" />
                    <span className="text-sm font-medium">No investigations found matching your filter</span>
                    <button
                      onClick={() => {
                        setStatusFilter('All');
                        setSearchQuery('');
                      }}
                      className="text-xs text-cyan-400 hover:underline mt-1"
                    >
                      Reset filters
                    </button>
                  </div>
                </td>
              </tr>
            ) : (
              investigations.map((inv) => (
                <tr
                  key={inv.id}
                  className="hover:bg-slate-800/40 transition-colors group"
                >
                  {/* ID - Clickable button opening investigation details */}
                  <td className="py-3.5 px-4 font-mono font-bold whitespace-nowrap">
                    <button
                      type="button"
                      onClick={() => onViewInvestigation(inv)}
                      className="inline-flex items-center gap-1.5 text-cyan-400 hover:text-cyan-300 hover:underline cursor-pointer group/id focus:outline-none focus:ring-1 focus:ring-cyan-500 rounded px-2 py-1 -mx-1 transition-all bg-cyan-950/30 hover:bg-cyan-900/50 border border-cyan-800/40 hover:border-cyan-600/70 text-xs"
                      title={`Open investigation details for ${inv.id}`}
                    >
                      <span>{inv.id}</span>
                      <ExternalLink className="w-3 h-3 opacity-60 group-hover/id:opacity-100 transition-opacity" />
                    </button>
                  </td>

                  {/* Alert */}
                  <td className="py-3.5 px-4">
                    <div className="font-semibold text-slate-100 max-w-xs md:max-w-md truncate">
                      {inv.alert}
                    </div>
                    {inv.mitreTechnique && (
                      <div className="font-mono text-[10px] text-slate-400 mt-0.5 truncate max-w-xs">
                        {inv.mitreTechnique}
                      </div>
                    )}
                  </td>

                  {/* Host */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <div className="flex items-center gap-1.5 font-mono text-slate-300">
                      <Server className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                      <span>{inv.host}</span>
                    </div>
                  </td>

                  {/* Severity */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={cn(
                        'inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border',
                        getSeverityBadgeClass(inv.severity)
                      )}
                    >
                      <span className="w-1.5 h-1.5 rounded-full bg-current" />
                      {inv.severity}
                    </span>
                  </td>

                  {/* Status */}
                  <td className="py-3.5 px-4 whitespace-nowrap">
                    <span
                      className={cn(
                        'inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-medium border',
                        getStatusBadgeClass(inv.status)
                      )}
                    >
                      {inv.status}
                    </span>
                  </td>

                  {/* Trust Score */}
                  <td className="py-3.5 px-4">
                    <div className="w-full">
                      <TrustScoreBar
                        score={inv.evidenceTrustScore}
                        showLabel={false}
                        size="sm"
                      />
                    </div>
                  </td>

                  {/* Started */}
                  <td className="py-3.5 px-4 font-mono text-slate-400 whitespace-nowrap">
                    {inv.started}
                  </td>

                  {/* View Button */}
                  <td className="py-3.5 px-4 text-right whitespace-nowrap">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => onViewInvestigation(inv)}
                      icon={<Eye className="w-3.5 h-3.5 text-cyan-400" />}
                      className="border-slate-700/80 hover:border-cyan-500/50 hover:bg-cyan-950/30 text-slate-200"
                    >
                      View
                    </Button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
