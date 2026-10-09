import React, { useState, useEffect } from 'react';
import {
  RotateCcw,
  CheckCircle2,
  Play,
  Pause,
  SkipForward,
  SkipBack,
  Sliders,
  History,
  RefreshCw,
} from 'lucide-react';
import { socApi } from '../../lib/api';
import type { TimelineEvent, ReplaySession } from '../../types/soc';

interface InvestigationTimelineSectionProps {
  investigationId: string;
}

export const InvestigationTimelineSection: React.FC<InvestigationTimelineSectionProps> = ({
  investigationId,
}) => {
  const [timeline, setTimeline] = useState<TimelineEvent[]>([]);
  const [currentStepIndex, setCurrentStepIndex] = useState<number>(1);
  const [isPlaying, setIsPlaying] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isReplaying, setIsReplaying] = useState<boolean>(false);
  const [latestReplay, setLatestReplay] = useState<ReplaySession | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const loadTimeline = async () => {
    setIsLoading(true);
    setErrorMsg(null);
    try {
      const [tl, replays] = await Promise.all([
        socApi.getInvestigationTimeline(investigationId),
        socApi.getInvestigationReplays(investigationId),
      ]);
      setTimeline(tl);
      if (replays.length > 0) {
        setLatestReplay(replays[0]);
      }
      if (tl.length > 0) {
        setCurrentStepIndex(1);
      }
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to load timeline.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadTimeline();
  }, [investigationId]);

  // Playback timer
  useEffect(() => {
    let timer: NodeJS.Timeout;
    if (isPlaying && timeline.length > 0) {
      timer = setTimeout(() => {
        if (currentStepIndex < timeline.length) {
          setCurrentStepIndex((prev) => prev + 1);
        } else {
          setIsPlaying(false);
        }
      }, 1200);
    }
    return () => clearTimeout(timer);
  }, [isPlaying, currentStepIndex, timeline.length]);

  const handleRunReplay = async () => {
    setIsReplaying(true);
    setErrorMsg(null);
    try {
      const rep = await socApi.executeReplay({
        investigation_id: investigationId,
        notes: `Modal-triggered verification for ${investigationId}`,
      });
      setLatestReplay(rep);
      setTimeline(rep.timeline);
      setCurrentStepIndex(1);
      setIsPlaying(false);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to execute replay.');
    } finally {
      setIsReplaying(false);
    }
  };

  const currentEvent: TimelineEvent | undefined =
    timeline.length > 0 ? timeline[currentStepIndex - 1] : undefined;

  const getActorBadgeColor = (actor: string) => {
    const a = actor.toLowerCase();
    if (a.includes('planner')) return 'bg-sky-950/70 text-sky-300 border-sky-800/60';
    if (a.includes('critic')) return 'bg-amber-950/70 text-amber-300 border-amber-800/60';
    if (a.includes('auditor')) return 'bg-purple-950/70 text-purple-300 border-purple-800/60';
    if (a.includes('tool')) return 'bg-indigo-950/70 text-indigo-300 border-indigo-800/60';
    if (a.includes('evidence')) return 'bg-emerald-950/70 text-emerald-300 border-emerald-800/60';
    if (a.includes('containment')) return 'bg-rose-950/70 text-rose-300 border-rose-800/60';
    return 'bg-slate-800/70 text-slate-300 border-slate-700/60';
  };

  return (
    <div className="p-4 rounded-xl bg-[#090D16] border border-slate-800/90 space-y-4">
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-cyan-400" />
          <span className="font-bold text-xs text-slate-100 font-mono">
            Forensic Timeline Replay & Time-Travel Debugger (Module 3O)
          </span>
        </div>
        <div className="flex items-center gap-2">
          {latestReplay && (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800/60 font-semibold flex items-center gap-1">
              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
              {latestReplay.consistency_score}% VERIFIED
            </span>
          )}
          <button
            onClick={handleRunReplay}
            disabled={isReplaying}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 border border-cyan-700/60 text-cyan-300 text-xs font-mono disabled:opacity-50 transition-colors"
          >
            <RotateCcw className={`w-3 h-3 ${isReplaying ? 'animate-spin' : ''}`} />
            <span>{isReplaying ? 'Replaying...' : 'Replay Case'}</span>
          </button>
        </div>
      </div>

      {errorMsg && (
        <div className="p-2.5 rounded bg-rose-950/30 border border-rose-800/40 text-rose-300 text-xs font-mono">
          {errorMsg}
        </div>
      )}

      {isLoading ? (
        <div className="p-4 text-center text-xs font-mono text-slate-400 flex items-center justify-center gap-2">
          <RefreshCw className="w-3.5 h-3.5 animate-spin text-cyan-400" />
          <span>Reconstructing forensic timeline...</span>
        </div>
      ) : timeline.length > 0 ? (
        <div className="space-y-4">
          {/* Scrubber & Playback Controls */}
          <div className="p-3 rounded-lg bg-slate-950/80 border border-slate-800/80 space-y-3">
            <div className="flex items-center justify-between text-xs font-mono">
              <div className="flex items-center gap-1.5">
                <button
                  onClick={() => setCurrentStepIndex(1)}
                  disabled={currentStepIndex <= 1}
                  className="p-1.5 rounded bg-slate-800/60 hover:bg-slate-700 text-slate-300 disabled:opacity-40"
                  title="First Step"
                >
                  <SkipBack className="w-3 h-3" />
                </button>
                <button
                  onClick={() => setCurrentStepIndex((prev) => Math.max(1, prev - 1))}
                  disabled={currentStepIndex <= 1}
                  className="p-1.5 rounded bg-slate-800/60 hover:bg-slate-700 text-slate-300 disabled:opacity-40"
                  title="Step Backward"
                >
                  <Sliders className="w-3 h-3 rotate-180" />
                </button>
                <button
                  onClick={() => setIsPlaying(!isPlaying)}
                  className="p-1.5 px-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white flex items-center gap-1 text-[11px]"
                >
                  {isPlaying ? <Pause className="w-3 h-3" /> : <Play className="w-3 h-3" />}
                  <span>{isPlaying ? 'Pause' : 'Play'}</span>
                </button>
                <button
                  onClick={() => setCurrentStepIndex((prev) => Math.min(timeline.length, prev + 1))}
                  disabled={currentStepIndex >= timeline.length}
                  className="p-1.5 rounded bg-slate-800/60 hover:bg-slate-700 text-slate-300 disabled:opacity-40"
                  title="Step Forward"
                >
                  <Sliders className="w-3 h-3" />
                </button>
                <button
                  onClick={() => setCurrentStepIndex(timeline.length)}
                  disabled={currentStepIndex >= timeline.length}
                  className="p-1.5 rounded bg-slate-800/60 hover:bg-slate-700 text-slate-300 disabled:opacity-40"
                  title="Last Step"
                >
                  <SkipForward className="w-3 h-3" />
                </button>
              </div>

              <div className="text-slate-400 text-[11px]">
                Milestone <span className="text-cyan-400 font-bold">{currentStepIndex}</span> of{' '}
                <span className="text-slate-200">{timeline.length}</span>
              </div>
            </div>

            <input
              type="range"
              min={1}
              max={timeline.length}
              value={currentStepIndex}
              onChange={(e) => {
                setCurrentStepIndex(Number(e.target.value));
                setIsPlaying(false);
              }}
              className="w-full h-1 bg-slate-800 rounded appearance-none cursor-pointer accent-cyan-400"
            />
          </div>

          {/* Current Event Detail */}
          {currentEvent && (
            <div className="p-3.5 rounded-lg bg-slate-900/60 border border-slate-800/90 space-y-2.5">
              <div className="flex items-center justify-between text-xs font-mono">
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 font-bold text-[10px] border border-cyan-800/60">
                    Step #{currentEvent.step_index}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${getActorBadgeColor(
                      currentEvent.actor
                    )}`}
                  >
                    {currentEvent.actor}
                  </span>
                  <span className="text-[10px] text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
                    {currentEvent.event_type}
                  </span>
                </div>
                <span className="text-[10px] text-slate-400">{currentEvent.timestamp}</span>
              </div>

              <div className="text-xs font-semibold text-slate-200 font-mono">
                {currentEvent.title}
              </div>
              <p className="text-xs text-slate-400 font-sans leading-relaxed">
                {currentEvent.description}
              </p>

              {currentEvent.state_snapshot && (
                <div className="pt-2 border-t border-slate-800/80 grid grid-cols-3 gap-2 text-[10px] font-mono text-slate-400">
                  <div>
                    Evidence: <span className="text-emerald-400 font-bold">{currentEvent.state_snapshot.cumulative_evidence_count}</span>
                  </div>
                  <div>
                    Tools: <span className="text-indigo-400 font-bold">{currentEvent.state_snapshot.cumulative_tool_executions}</span>
                  </div>
                  <div>
                    Trust Score: <span className="text-cyan-400 font-bold">{currentEvent.state_snapshot.evidence_trust_score}%</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      ) : (
        <div className="p-4 text-center text-xs font-mono text-slate-500">
          No chronological timeline events recorded for this case.
        </div>
      )}
    </div>
  );
};
