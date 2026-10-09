import React, { useState } from 'react';
import { Copy, Check, Download, ChevronDown, ChevronRight } from 'lucide-react';

interface JsonViewerProps {
  data: any;
  title?: string;
  filename?: string;
  maxHeight?: string;
}

export const JsonViewer: React.FC<JsonViewerProps> = ({
  data,
  title = 'Case Audit Object JSON',
  filename = 'audit_object.json',
  maxHeight = 'max-h-[550px]',
}) => {
  const [copied, setCopied] = useState(false);
  const [isExpanded, setIsExpanded] = useState(true);

  const jsonString = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

  const handleCopy = () => {
    navigator.clipboard.writeText(jsonString);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([jsonString], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="bg-[#0B0F19] border border-slate-800 rounded-xl overflow-hidden shadow-xl">
      {/* Header Bar */}
      <div className="flex items-center justify-between px-4 py-3 bg-[#0E1526] border-b border-slate-800">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="flex items-center gap-2 text-xs font-mono font-semibold text-slate-200 hover:text-cyan-400 transition-colors"
        >
          {isExpanded ? (
            <ChevronDown className="w-4 h-4 text-cyan-400" />
          ) : (
            <ChevronRight className="w-4 h-4 text-slate-400" />
          )}
          <span>{title}</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 font-normal">
            JSON v1.0
          </span>
        </button>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-lg bg-slate-800/80 hover:bg-slate-700 text-slate-300 hover:text-white border border-slate-700/60 transition-colors"
            title="Copy formatted JSON to clipboard"
          >
            {copied ? (
              <>
                <Check className="w-3.5 h-3.5 text-emerald-400" />
                <span className="text-emerald-400 font-mono text-[11px]">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3.5 h-3.5 text-slate-400" />
                <span className="text-[11px]">Copy JSON</span>
              </>
            )}
          </button>

          <button
            onClick={handleDownload}
            className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-lg bg-cyan-950/70 hover:bg-cyan-900/80 text-cyan-300 hover:text-cyan-100 border border-cyan-800/60 transition-colors"
            title="Download JSON file"
          >
            <Download className="w-3.5 h-3.5 text-cyan-400" />
            <span className="text-[11px]">Export JSON</span>
          </button>
        </div>
      </div>

      {/* Code Display */}
      {isExpanded && (
        <div className={`p-4 overflow-auto font-mono text-xs leading-relaxed ${maxHeight} bg-[#070A12]`}>
          <pre className="text-emerald-400 selection:bg-cyan-900/50 selection:text-white whitespace-pre">
            {jsonString}
          </pre>
        </div>
      )}
    </div>
  );
};
