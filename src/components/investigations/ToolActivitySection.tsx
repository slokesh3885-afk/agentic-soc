import React, { useState, useEffect, useCallback } from 'react';
import type { ToolExecution } from '../../types/soc';
import { socApi } from '../../lib/api';
import {
  Wrench,
  CheckCircle2,
  XCircle,
  ChevronDown,
  ChevronRight,
  Terminal,
  RefreshCw,
  Play,
  ShieldAlert,
  ShieldCheck,
  FileCode,
  Layers,
  Fingerprint,
} from 'lucide-react';
import { Button } from '../ui/Button';
import { cn } from '../../lib/utils';

interface ToolActivitySectionProps {
  investigationId: string;
  onEvidenceCreated?: (newEvidenceId: string) => void;
}

const TOOL_PRESETS: Record<string, { name: string; defaultInput: Record<string, any> }> = {
  siem_search: {
    name: 'SIEM Search',
    defaultInput: { query: 'host=PC-DB-TEST powershell' },
  },
  edr_process_search: {
    name: 'EDR Process Search',
    defaultInput: { host: 'PC-DB-TEST' },
  },
  hash_lookup: {
    name: 'Hash Lookup',
    defaultInput: { hash: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' },
  },
  sandbox_summary: {
    name: 'Sandbox Summary',
    defaultInput: { sample_id: 'sample-001' },
  },
  whois_lookup: {
    name: 'WHOIS Lookup',
    defaultInput: { domain: 'example.test' },
  },
  yara_scan: {
    name: 'YARA Scan',
    defaultInput: { sample_id: 'sample-001' },
  },
};

function formatToolName(toolName: string): string {
  if (TOOL_PRESETS[toolName]) {
    return TOOL_PRESETS[toolName].name;
  }
  return toolName
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

export const ToolActivitySection: React.FC<ToolActivitySectionProps> = ({
  investigationId,
  onEvidenceCreated,
}) => {
  const [executions, setExecutions] = useState<ToolExecution[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [isDispatchOpen, setIsDispatchOpen] = useState<boolean>(false);

  // Dispatch Tool Form State
  const [selectedTool, setSelectedTool] = useState<string>('siem_search');
  const [inputJson, setInputJson] = useState<string>(
    JSON.stringify(TOOL_PRESETS['siem_search'].defaultInput, null, 2)
  );
  const [isExecuting, setIsExecuting] = useState<boolean>(false);
  const [executionFeedback, setExecutionFeedback] = useState<{
    success: boolean;
    message: string;
    evidenceId?: string;
  } | null>(null);

  const [evidenceIntegrity, setEvidenceIntegrity] = useState<
    Record<string, { valid: boolean; timestamp: string }>
  >({});

  const fetchExecutions = useCallback(async () => {
    setIsLoading(true);
    try {
      const items = await socApi.getInvestigationToolExecutions(investigationId);
      setExecutions(items);
      if (items.length > 0 && !expandedId) {
        setExpandedId(items[0].id);
      }
    } catch (err) {
      console.error('Failed to load tool executions:', err);
    } finally {
      setIsLoading(false);
    }
  }, [investigationId, expandedId]);

  useEffect(() => {
    fetchExecutions();
  }, [investigationId]);

  // Handle preset change in dispatch form
  const handleToolChange = (toolKey: string) => {
    setSelectedTool(toolKey);
    if (TOOL_PRESETS[toolKey]) {
      setInputJson(JSON.stringify(TOOL_PRESETS[toolKey].defaultInput, null, 2));
    } else if (toolKey === 'CUSTOM_INVALID') {
      setInputJson(JSON.stringify({ command: 'whoami' }, null, 2));
    }
    setExecutionFeedback(null);
  };

  const handleVerifyEvidence = async (evidenceId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    try {
      const res = await socApi.verifyEvidenceIntegrity(evidenceId);
      setEvidenceIntegrity((prev) => ({
        ...prev,
        [evidenceId]: {
          valid: res.valid,
          timestamp: res.timestampVerified,
        },
      }));
    } catch (err) {
      console.error('Verification error:', err);
    }
  };

  const handleExecuteTool = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsExecuting(true);
    setExecutionFeedback(null);

    let parsedInput = {};
    try {
      parsedInput = JSON.parse(inputJson);
    } catch (err) {
      setExecutionFeedback({
        success: false,
        message: 'Invalid JSON payload. Please verify syntax.',
      });
      setIsExecuting(false);
      return;
    }

    const actualToolName = selectedTool === 'CUSTOM_INVALID' ? 'run_powershell' : selectedTool;

    try {
      const result = await socApi.executeSecurityTool(actualToolName, parsedInput, investigationId);

      if (result.success) {
        setExecutionFeedback({
          success: true,
          message: `Tool executed successfully! Evidence object ${result.evidence_id} created and sealed with SHA-256.`,
          evidenceId: result.evidence_id,
        });

        if (result.evidence_id && onEvidenceCreated) {
          onEvidenceCreated(result.evidence_id);
        }

        // Refresh tool execution list
        fetchExecutions();
      } else {
        setExecutionFeedback({
          success: false,
          message: `Security Boundary Block: ${result.error || 'Execution not permitted'}`,
        });
        fetchExecutions();
      }
    } catch (err: any) {
      setExecutionFeedback({
        success: false,
        message: err.message || 'Execution failed.',
      });
    } finally {
      setIsExecuting(false);
    }
  };

  return (
    <div className="space-y-3 rounded-xl bg-slate-950/70 border border-slate-800 p-4">
      {/* Section Header */}
      <div className="flex items-center justify-between border-b border-slate-800 pb-3">
        <div className="flex items-center gap-2">
          <Wrench className="w-4 h-4 text-cyan-400" />
          <h3 className="text-xs font-bold text-slate-100 uppercase tracking-wider font-mono">
            Allow-listed Security Tool Activity
          </h3>
          <span className="text-[10px] bg-slate-800 border border-slate-700 text-slate-300 font-mono px-2 py-0.5 rounded-full font-semibold">
            {executions.length} Call{executions.length === 1 ? '' : 's'}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            onClick={fetchExecutions}
            disabled={isLoading}
            className="h-7 px-2 text-[11px] text-slate-400 hover:text-slate-200"
            title="Refresh tool activity"
          >
            <RefreshCw className={cn('w-3 h-3', isLoading && 'animate-spin')} />
          </Button>

          <Button
            variant={isDispatchOpen ? 'secondary' : 'outline'}
            size="sm"
            onClick={() => setIsDispatchOpen(!isDispatchOpen)}
            className="h-7 text-xs border-cyan-700/60 text-cyan-300 hover:bg-cyan-950/50"
          >
            <Play className="w-3 h-3 mr-1" />
            {isDispatchOpen ? 'Hide Dispatcher' : 'Dispatch Tool'}
          </Button>
        </div>
      </div>

      {/* Dispatch Tool Interactive Drawer */}
      {isDispatchOpen && (
        <form
          onSubmit={handleExecuteTool}
          className="p-3.5 bg-[#090D16] border border-cyan-900/60 rounded-xl space-y-3 animate-in fade-in duration-150 text-xs font-mono"
        >
          <div className="flex items-center justify-between">
            <span className="text-cyan-400 font-bold flex items-center gap-1.5 text-[11px]">
              <Terminal className="w-3.5 h-3.5" />
              Dispatch Security Tool (Allow-listed Sandboxed Layer)
            </span>
            <span className="text-[10px] text-slate-500 font-sans">
              Auto-generates Evidence with SHA-256
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            <div>
              <label className="block text-[10px] text-slate-400 mb-1">
                Select Allow-listed Tool
              </label>
              <select
                value={selectedTool}
                onChange={(e) => handleToolChange(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500"
              >
                <option value="siem_search">siem_search (SIEM Event Logs)</option>
                <option value="edr_process_search">edr_process_search (Process Lineage)</option>
                <option value="hash_lookup">hash_lookup (Threat Intel Reputation)</option>
                <option value="sandbox_summary">sandbox_summary (Detonation Telemetry)</option>
                <option value="whois_lookup">whois_lookup (Domain WHOIS)</option>
                <option value="yara_scan">yara_scan (YARA Rule Matching)</option>
                <option value="CUSTOM_INVALID" className="text-rose-400 font-bold">
                  ⚠️ [Security Test] run_powershell (Blocked)
                </option>
              </select>
            </div>

            <div>
              <label className="block text-[10px] text-slate-400 mb-1">
                Investigation Target Binding
              </label>
              <div className="bg-slate-900/90 border border-slate-800 px-2.5 py-1.5 rounded-lg text-slate-300 font-bold text-xs">
                {investigationId}
              </div>
            </div>
          </div>

          <div>
            <label className="block text-[10px] text-slate-400 mb-1">
              Input Parameters (JSON Schema)
            </label>
            <textarea
              rows={3}
              value={inputJson}
              onChange={(e) => setInputJson(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 font-mono text-[11px]"
            />
          </div>

          {executionFeedback && (
            <div
              className={cn(
                'p-2.5 rounded-lg border text-[11px] flex items-start gap-2',
                executionFeedback.success
                  ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-800/60 text-rose-300'
              )}
            >
              {executionFeedback.success ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <ShieldAlert className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              )}
              <div className="min-w-0">
                <span className="font-semibold block">{executionFeedback.message}</span>
                {executionFeedback.evidenceId && (
                  <span className="text-[10px] text-emerald-400/80 block mt-0.5">
                    Evidence ID: {executionFeedback.evidenceId} (Inspect below in Evidence Engine)
                  </span>
                )}
              </div>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-1">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={() => setIsDispatchOpen(false)}
              className="text-xs text-slate-400"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={isExecuting}
              className="text-xs bg-cyan-600 hover:bg-cyan-500 text-white"
            >
              {isExecuting ? 'Executing...' : 'Execute Tool & Bind Evidence'}
            </Button>
          </div>
        </form>
      )}

      {/* Loading State */}
      {isLoading && (
        <div className="py-6 text-center text-slate-400 font-mono text-xs flex items-center justify-center gap-2">
          <RefreshCw className="w-4 h-4 animate-spin text-cyan-400" />
          <span>Loading tool activity audit log...</span>
        </div>
      )}

      {/* Empty State */}
      {!isLoading && executions.length === 0 && (
        <div className="py-6 text-center bg-[#090D16] border border-dashed border-slate-800 rounded-xl space-y-1.5 font-mono text-xs text-slate-400">
          <Wrench className="w-6 h-6 text-slate-500 mx-auto" />
          <div>No tool executions recorded yet for this case.</div>
          <div className="text-[10px] text-slate-500 font-sans">
            Click "Dispatch Tool" above to trigger an allow-listed security tool.
          </div>
        </div>
      )}

      {/* Tool Executions List */}
      {!isLoading && executions.length > 0 && (
        <div className="space-y-2 font-mono text-xs">
          {executions.map((item) => {
            const isExpanded = expandedId === item.id;
            const evidenceCheck = item.evidenceId ? evidenceIntegrity[item.evidenceId] : null;

            return (
              <div
                key={item.id}
                className={cn(
                  'rounded-xl border transition-all overflow-hidden',
                  isExpanded
                    ? 'bg-[#0B101D] border-cyan-800/80 shadow-md'
                    : 'bg-[#090D16] border-slate-800/90 hover:border-slate-700'
                )}
              >
                {/* Row Header (Matching user specification: Tool Name | Status | Timestamp | Evidence ID) */}
                <div
                  onClick={() => setExpandedId(isExpanded ? null : item.id)}
                  className="p-3 cursor-pointer flex flex-wrap items-center justify-between gap-2 select-none"
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    {isExpanded ? (
                      <ChevronDown className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                    ) : (
                      <ChevronRight className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                    )}

                    {/* Tool Name */}
                    <span className="font-bold text-slate-100 text-xs">
                      {formatToolName(item.toolName)}
                    </span>

                    <span className="text-[10px] text-slate-500 font-mono">
                      ({item.toolName})
                    </span>
                  </div>

                  <div className="flex items-center gap-3 ml-auto text-[11px]">
                    {/* Status Indicator */}
                    {item.success ? (
                      <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-bold bg-emerald-950/40 border border-emerald-800/60 px-2 py-0.5 rounded">
                        <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                        ✓ Success
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[11px] text-rose-400 font-bold bg-rose-950/40 border border-rose-800/60 px-2 py-0.5 rounded">
                        <XCircle className="w-3 h-3 text-rose-400" />
                        ✗ Blocked
                      </span>
                    )}

                    {/* Timestamp */}
                    <span className="text-slate-400 text-[10px] hidden sm:inline">
                      {item.timestamp}
                    </span>

                    {/* Bound Evidence ID Badge */}
                    {item.evidenceId ? (
                      <span
                        className="font-bold text-cyan-400 bg-cyan-950/90 border border-cyan-800/80 px-2 py-0.5 rounded text-[11px] flex items-center gap-1"
                        title={`Bound to persistent Evidence item ${item.evidenceId}`}
                      >
                        <Fingerprint className="w-3 h-3 text-cyan-400" />
                        {item.evidenceId}
                      </span>
                    ) : (
                      <span className="text-slate-500 text-[10px] bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">
                        No Evidence
                      </span>
                    )}
                  </div>
                </div>

                {/* Expanded Details Drawer */}
                {isExpanded && (
                  <div className="px-4 pb-4 pt-1 border-t border-slate-800/70 space-y-3 bg-[#070A11]/60">
                    {/* Input Block */}
                    <div>
                      <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase font-semibold mb-1">
                        <Terminal className="w-3 h-3 text-cyan-400" />
                        <span>Input Arguments</span>
                      </div>
                      <div className="p-2.5 rounded-lg bg-black/80 border border-slate-800 text-cyan-300 font-mono text-[11px] overflow-x-auto">
                        <pre>{JSON.stringify(item.input, null, 2)}</pre>
                      </div>
                    </div>

                    {/* Output Block */}
                    <div>
                      <div className="flex items-center gap-1.5 text-slate-400 text-[10px] uppercase font-semibold mb-1">
                        <FileCode className="w-3 h-3 text-amber-400" />
                        <span>Structured Output Payload</span>
                      </div>
                      <div className="p-3 rounded-lg bg-black/90 border border-slate-800 text-slate-200 font-mono text-[11px] overflow-x-auto max-h-48">
                        <pre>{JSON.stringify(item.output, null, 2)}</pre>
                      </div>
                    </div>

                    {/* Evidence & Integrity Verification Footer */}
                    <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-3 text-[11px]">
                      <div className="flex items-center gap-2">
                        <Layers className="w-3.5 h-3.5 text-cyan-400" />
                        <span className="text-slate-300">
                          {item.evidenceId ? (
                            <>
                              Bound Evidence Artifact:{' '}
                              <strong className="text-cyan-300 font-bold">{item.evidenceId}</strong>
                            </>
                          ) : (
                            <span className="text-rose-400">
                              No evidence generated: {item.error || 'Execution blocked by security policy'}
                            </span>
                          )}
                        </span>
                      </div>

                      {item.evidenceId && (
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={(e) => handleVerifyEvidence(item.evidenceId!, e)}
                            className="h-6 text-[10px] border-cyan-800 text-cyan-300 hover:bg-cyan-950/40"
                          >
                            <ShieldCheck className="w-3 h-3 mr-1 text-emerald-400" />
                            Verify Evidence Hash
                          </Button>

                          {evidenceCheck && (
                            <span className="inline-flex items-center gap-1 text-[10px] text-emerald-400 font-bold bg-emerald-950/60 border border-emerald-800/80 px-2 py-0.5 rounded">
                              <CheckCircle2 className="w-3 h-3 text-emerald-400" />
                              INTEGRITY VERIFIED ✓
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};
