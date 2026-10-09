import React, { useState, useEffect } from 'react';
import type { NewInvestigationPayload, SeverityLevel } from '../../types/soc';
import {
  X,
  ShieldPlus,
  Server,
  Clock,
  FileText,
  AlertCircle,
  Play,
  ShieldAlert,
} from 'lucide-react';
import { Button } from '../ui/Button';

interface NewInvestigationModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (payload: NewInvestigationPayload) => Promise<unknown>;
  initialData?: Partial<NewInvestigationPayload> | null;
}

export const NewInvestigationModal: React.FC<NewInvestigationModalProps> = ({
  isOpen,
  onClose,
  onSubmit,
  initialData,
}) => {
  const [alertName, setAlertName] = useState('');
  const [host, setHost] = useState('');
  const [timestamp, setTimestamp] = useState('');
  const [description, setDescription] = useState('');
  const [severity, setSeverity] = useState<SeverityLevel>('High');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Initialize form fields when opened
  useEffect(() => {
    if (isOpen) {
      const now = new Date();
      const formattedTimestamp = now.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

      setAlertName(initialData?.alertName || '');
      setHost(initialData?.host || '');
      setTimestamp(initialData?.timestamp || formattedTimestamp);
      setDescription(
        initialData?.description ||
          'Automated host telemetry corroboration initiated. Gathering Sysmon, Zeek, and memory artifacts for hypothesis validation.'
      );
      setSeverity(initialData?.severity || 'High');
      setError(null);
    }
  }, [isOpen, initialData]);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!alertName.trim()) {
      setError('Please provide an Alert name.');
      return;
    }
    if (!host.trim()) {
      setError('Please provide a target Host name or IP.');
      return;
    }

    try {
      setIsSubmitting(true);
      setError(null);
      await onSubmit({
        alertName: alertName.trim(),
        host: host.trim(),
        timestamp: timestamp.trim(),
        description: description.trim(),
        severity,
      });
    } catch (err) {
      setError('An error occurred while creating the investigation.');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/75 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-[#0F172A] border border-slate-700 rounded-2xl w-full max-w-lg shadow-2xl overflow-hidden flex flex-col">
        {/* Header */}
        <div className="p-5 border-b border-slate-800 flex items-center justify-between bg-slate-900/50">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-950/70 border border-cyan-700/60 flex items-center justify-center text-cyan-400">
              <ShieldPlus className="w-5 h-5" />
            </div>
            <div>
              <h3 className="text-base font-bold text-slate-100">Start New Investigation</h3>
              <p className="text-xs text-slate-400">
                Initialize evidence correlation workflow for unmanaged anomaly
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 p-1.5 rounded-lg hover:bg-slate-800 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} className="p-5 space-y-4">
          {error && (
            <div className="p-3 bg-rose-950/60 border border-rose-800/80 rounded-lg text-rose-300 text-xs flex items-center gap-2">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Alert Name */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5">
              Alert Name <span className="text-rose-400">*</span>
            </label>
            <div className="relative">
              <input
                type="text"
                required
                placeholder="e.g. Suspicious PowerShell Execution, Ransomware Canary..."
                value={alertName}
                onChange={(e) => setAlertName(e.target.value)}
                className="w-full px-3 py-2 bg-[#090D16] border border-slate-700 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
              />
            </div>
          </div>

          {/* Host & Severity Grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Host */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 flex items-center gap-1.5">
                <Server className="w-3.5 h-3.5 text-slate-400" />
                Target Host <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                required
                placeholder="e.g. DC-PROD-01.corp.internal"
                value={host}
                onChange={(e) => setHost(e.target.value)}
                className="w-full px-3 py-2 bg-[#090D16] border border-slate-700 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono"
              />
            </div>

            {/* Severity */}
            <div>
              <label className="block text-xs font-semibold text-slate-300 mb-1.5 flex items-center gap-1.5">
                <ShieldAlert className="w-3.5 h-3.5 text-slate-400" />
                Severity
              </label>
              <select
                value={severity}
                onChange={(e) => setSeverity(e.target.value as SeverityLevel)}
                className="w-full px-3 py-2 bg-[#090D16] border border-slate-700 rounded-lg text-sm text-slate-100 focus:outline-none focus:border-cyan-500 font-mono"
              >
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>

          {/* Timestamp */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-slate-400" />
              Event Timestamp
            </label>
            <input
              type="text"
              value={timestamp}
              onChange={(e) => setTimestamp(e.target.value)}
              placeholder="YYYY-MM-DD HH:MM:SS UTC"
              className="w-full px-3 py-2 bg-[#090D16] border border-slate-700 rounded-lg text-sm text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-mono text-xs"
            />
          </div>

          {/* Description */}
          <div>
            <label className="block text-xs font-semibold text-slate-300 mb-1.5 flex items-center gap-1.5">
              <FileText className="w-3.5 h-3.5 text-slate-400" />
              Investigation Description & Hypotheses
            </label>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe trigger condition, observed behaviors, initial memory flags..."
              className="w-full px-3 py-2 bg-[#090D16] border border-slate-700 rounded-lg text-xs text-slate-100 placeholder:text-slate-400 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 leading-relaxed resize-none"
            />
          </div>

          {/* Footer Controls */}
          <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={onClose}
              disabled={isSubmitting}
            >
              Cancel
            </Button>
            <Button
              type="submit"
              variant="primary"
              size="sm"
              disabled={isSubmitting}
              icon={<Play className="w-3.5 h-3.5" />}
            >
              {isSubmitting ? 'Starting...' : 'Start Investigation'}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
};
