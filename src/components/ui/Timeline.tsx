import React, { useState } from 'react';
import type { TimelineEvent } from '../../types/soc';
import {
  Clock,
  ChevronDown,
  ChevronRight,
} from 'lucide-react';
import { cn } from '../../lib/utils';

export interface TimelineItem {
  id?: string;
  step_index?: number;
  stepIndex?: number;
  timestamp: string;
  title: string;
  stage?: string;
  actor?: string;
  agent?: string;
  type?: string;
  description?: string;
  details?: string;
  metadata?: any;
  status?: string;
}

export interface TimelineProps {
  events: Array<TimelineItem | TimelineEvent | any>;
  activeEventId?: string;
  onSelectEvent?: (id: string) => void;
  maxHeight?: string;
  className?: string;
  title?: string;
}

export const Timeline: React.FC<TimelineProps> = ({
  events = [],
  activeEventId,
  onSelectEvent,
  maxHeight = 'max-h-[500px]',
  className,
  title = 'Investigation Event Timeline',
}) => {
  const [expandedItems, setExpandedItems] = useState<Record<string, boolean>>({});

  const toggleExpand = (id: string) => {
    setExpandedItems((prev) => ({ ...prev, [id]: !prev[id] }));
  };

  const getActorBadgeColor = (actor: string = '') => {
    const a = actor.toLowerCase();
    if (a.includes('planner')) return 'text-purple-400 bg-purple-950/60 border-purple-800/60';
    if (a.includes('tool') || a.includes('executor')) return 'text-amber-400 bg-amber-950/60 border-amber-800/60';
    if (a.includes('analyst') || a.includes('evidence')) return 'text-cyan-400 bg-cyan-950/60 border-cyan-800/60';
    if (a.includes('critic') || a.includes('redteam')) return 'text-rose-400 bg-rose-950/60 border-rose-800/60';
    if (a.includes('auditor')) return 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60';
    return 'text-slate-300 bg-slate-900 border-slate-800';
  };

  return (
    <div
      className={cn(
        'rounded-xl border border-slate-800 bg-[#0B0F19] overflow-hidden shadow-xl font-mono text-xs flex flex-col',
        className
      )}
    >
      {/* Header Bar */}
      <div className="flex items-center justify-between p-3.5 bg-[#0E1526] border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Clock className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-slate-200 text-xs uppercase tracking-wide">
            {title}
          </span>
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-cyan-950/70 border border-cyan-800/60 text-cyan-300 font-semibold">
            {events.length} step{events.length !== 1 ? 's' : ''}
          </span>
        </div>
      </div>

      {/* Timeline Scroll Area */}
      <div className={cn('p-4 overflow-y-auto space-y-4', maxHeight)}>
        {events.length === 0 ? (
          <div className="py-8 text-center text-slate-500 italic">
            No chronological timeline events logged yet.
          </div>
        ) : (
          events.map((evt, idx) => {
            const id = evt.id || `evt-${idx + 1}`;
            const stepNum = evt.step_index ?? evt.stepIndex ?? idx + 1;
            const actor = evt.actor || evt.agent || evt.stage || 'System';
            const eventTitle = evt.title || evt.action || `Step ${stepNum}`;
            const desc = evt.description || evt.details || '';
            const timestamp = evt.timestamp || '00:00:00';
            const isExpanded = !!expandedItems[id];
            const isCurrent = activeEventId === id;
            const hasMetadata = evt.metadata && Object.keys(evt.metadata).length > 0;

            return (
              <div
                key={id}
                className={cn(
                  'relative pl-6 pb-2 transition-all group',
                  idx !== events.length - 1 && 'border-l-2 border-slate-800/80 ml-2'
                )}
              >
                {/* Timeline node icon */}
                <div
                  className={cn(
                    'absolute -left-[9px] top-0 w-4 h-4 rounded-full border-2 flex items-center justify-center transition-all',
                    isCurrent
                      ? 'bg-cyan-500 border-cyan-300 shadow-md shadow-cyan-500/50'
                      : 'bg-slate-900 border-slate-700 group-hover:border-cyan-500'
                  )}
                >
                  <div
                    className={cn(
                      'w-1.5 h-1.5 rounded-full',
                      isCurrent ? 'bg-white' : 'bg-slate-400'
                    )}
                  />
                </div>

                {/* Event Card Content */}
                <div
                  className={cn(
                    'p-3 rounded-lg border bg-[#080C14]/80 transition-all space-y-1.5',
                    isCurrent
                      ? 'border-cyan-600/80 shadow-md shadow-cyan-950/40'
                      : 'border-slate-800/90 hover:border-slate-700/80',
                    onSelectEvent && 'cursor-pointer hover:bg-slate-900/40'
                  )}
                  onClick={() => onSelectEvent && onSelectEvent(id)}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-bold text-slate-500">
                        #{stepNum}
                      </span>
                      <span
                        className={cn(
                          'text-[10px] px-1.5 py-0.5 rounded border font-semibold uppercase',
                          getActorBadgeColor(actor)
                        )}
                      >
                        {actor}
                      </span>
                      <span className="font-bold text-slate-200 text-xs">
                        {eventTitle}
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-[10px] text-slate-400">
                      <span>{timestamp}</span>
                      {hasMetadata && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            toggleExpand(id);
                          }}
                          className="p-1 hover:text-cyan-300 transition-colors"
                          title="Toggle details"
                        >
                          {isExpanded ? (
                            <ChevronDown className="w-3 h-3 text-cyan-400" />
                          ) : (
                            <ChevronRight className="w-3 h-3 text-slate-400" />
                          )}
                        </button>
                      )}
                    </div>
                  </div>

                  {desc && (
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      {desc}
                    </p>
                  )}

                  {/* Collapsible Metadata Drawer */}
                  {hasMetadata && isExpanded && (
                    <div className="mt-2 p-2 rounded bg-slate-950 border border-slate-800 text-[10px] font-mono text-cyan-300/90 overflow-x-auto whitespace-pre-wrap">
                      {typeof evt.metadata === 'string'
                        ? evt.metadata
                        : JSON.stringify(evt.metadata, null, 2)}
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
