import React, { useState, useEffect } from 'react';
import {
  FileText,
  Download,
  ExternalLink,
  ShieldCheck,
  CheckCircle2,
  Printer,
  Copy,
  Check,
  Sparkles,
  Lock,
  Scale,
  FileCode,
  Search,
} from 'lucide-react';
import { socApi as api } from '../../lib/api';
import type { IncidentReport, ReportSummary } from '../../types/soc';

interface ReportsViewProps {
  onSelectInvestigation?: (investigationId: string) => void;
}

export const ReportsView: React.FC<ReportsViewProps> = ({ onSelectInvestigation }) => {
  const [reports, setReports] = useState<IncidentReport[]>([]);
  const [summary, setSummary] = useState<ReportSummary | null>(null);
  const [selectedReport, setSelectedReport] = useState<IncidentReport | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [generating, setGenerating] = useState<boolean>(false);
  const [searchTerm, setSearchTerm] = useState<string>('');
  const [selectedFramework, setSelectedFramework] = useState<string>('NIST SP 800-61 Rev. 2');
  const [copiedHash, setCopiedHash] = useState<boolean>(false);

  // Generation form state
  const [selectedInvId, setSelectedInvId] = useState<string>('INV-001');
  const [selectedType, setSelectedType] = useState<string>('EXECUTIVE');
  const [selectedClass, setSelectedClass] = useState<string>('CONFIDENTIAL');

  const loadData = async () => {
    try {
      setLoading(true);
      const [reportsData, summaryData] = await Promise.all([
        api.getReports(),
        api.getReportsSummary(),
      ]);
      setReports(reportsData);
      setSummary(summaryData);
      if (reportsData.length > 0 && !selectedReport) {
        setSelectedReport(reportsData[0]);
      }
    } catch (err) {
      console.error('Failed to load reports:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const handleGenerate = async () => {
    try {
      setGenerating(true);
      const newRep = await api.generateReport({
        investigation_id: selectedInvId,
        report_type: selectedType,
        classification: selectedClass,
        author: 'Lead Forensic Investigator',
      });
      await loadData();
      setSelectedReport(newRep);
    } catch (err) {
      console.error('Failed to generate report:', err);
    } finally {
      setGenerating(false);
    }
  };

  const handleCopyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const filteredReports = reports.filter((r) =>
    r.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
    r.id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    r.investigation_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    r.verdict.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="p-4 sm:p-6 max-w-[1700px] mx-auto space-y-6 animate-fadeIn">
      {/* Top Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="w-10 h-10 rounded-xl bg-cyan-950/80 border border-cyan-800/60 flex items-center justify-center text-cyan-400 shadow-inner">
              <FileText className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl sm:text-2xl font-bold text-slate-100 font-mono tracking-tight flex items-center gap-2">
                Executive Security Reports & Compliance
                <span className="text-[11px] font-semibold uppercase px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/80">
                  Module 3P
                </span>
              </h1>
              <p className="text-xs text-slate-400">
                Audit-ready incident reports, regulatory compliance attestations, and cryptographic export packages
              </p>
            </div>
          </div>
        </div>

        {/* Report Generator Controls */}
        <div className="flex flex-wrap items-center gap-2.5 bg-[#090D16] p-2 rounded-xl border border-slate-800">
          <select
            value={selectedInvId}
            onChange={(e) => setSelectedInvId(e.target.value)}
            className="bg-slate-900 border border-slate-700/80 rounded-lg px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="INV-001">INV-001 (PowerShell)</option>
            <option value="INV-002">INV-002 (DNS Exfil)</option>
            <option value="INV-003">INV-003 (Ransomware)</option>
            <option value="INV-004">INV-004 (Lateral SMB)</option>
          </select>

          <select
            value={selectedType}
            onChange={(e) => setSelectedType(e.target.value)}
            className="bg-slate-900 border border-slate-700/80 rounded-lg px-2 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="EXECUTIVE">Executive</option>
            <option value="TECHNICAL">Technical</option>
            <option value="REGULATORY_COMPLIANCE">Regulatory</option>
            <option value="FORENSIC">Forensic</option>
          </select>

          <select
            value={selectedClass}
            onChange={(e) => setSelectedClass(e.target.value)}
            className="bg-slate-900 border border-slate-700/80 rounded-lg px-2 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
          >
            <option value="CONFIDENTIAL">Confidential</option>
            <option value="RESTRICTED">Restricted</option>
            <option value="INTERNAL">Internal</option>
            <option value="PUBLIC">Public</option>
          </select>

          <button
            onClick={handleGenerate}
            disabled={generating}
            className="px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-semibold flex items-center gap-1.5 transition-all shadow-md shadow-cyan-950/40 disabled:opacity-50"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>{generating ? 'Generating...' : 'Generate Report'}</span>
          </button>
        </div>
      </div>

      {/* 4 Summary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Total Incident Reports
            </div>
            <div className="text-2xl font-bold text-slate-100 font-mono mt-1">
              {summary ? summary.total_reports : reports.length}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Across all active investigations</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-cyan-950/50 border border-cyan-800/40 flex items-center justify-center text-cyan-400">
            <FileText className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Published Reports
            </div>
            <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">
              {summary ? summary.published_count : reports.length}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">100% cryptographic audit sealed</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-emerald-950/50 border border-emerald-800/40 flex items-center justify-center text-emerald-400">
            <CheckCircle2 className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Avg Evidence Trust Score
            </div>
            <div className="text-2xl font-bold text-cyan-400 font-mono mt-1">
              {summary ? `${summary.average_trust_score}/100` : '84.0/100'}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">Explainable evidentiary basis</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-cyan-950/50 border border-cyan-800/40 flex items-center justify-center text-cyan-400">
            <ShieldCheck className="w-5 h-5" />
          </div>
        </div>

        <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 flex items-center justify-between">
          <div>
            <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Compliance Adherence
            </div>
            <div className="text-2xl font-bold text-indigo-400 font-mono mt-1">
              {summary ? `${summary.average_compliance_score}%` : '97.5%'}
            </div>
            <div className="text-[10px] text-slate-500 mt-0.5">NIST, ISO, SOC 2, GDPR, HIPAA</div>
          </div>
          <div className="w-10 h-10 rounded-lg bg-indigo-950/50 border border-indigo-800/40 flex items-center justify-center text-indigo-400">
            <Scale className="w-5 h-5" />
          </div>
        </div>
      </div>

      {/* Main Split Layout: Left List + Right Detail */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Column: Report Selection & Historical List */}
        <div className="lg:col-span-4 space-y-4">
          <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-4 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-200 uppercase tracking-wider">
                Reports Repository ({reports.length})
              </span>
            </div>

            {/* Search filter */}
            <div className="relative">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                placeholder="Search reports by ID, alert, verdict..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full bg-[#090D16] border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-cyan-500 placeholder-slate-500"
              />
            </div>
          </div>

          <div className="space-y-2.5 max-h-[800px] overflow-y-auto pr-1">
            {loading && reports.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">Loading reports...</div>
            ) : filteredReports.length === 0 ? (
              <div className="p-8 text-center text-xs text-slate-500">No reports found</div>
            ) : (
              filteredReports.map((r) => {
                const isSelected = selectedReport?.id === r.id;
                const isConfirmed = r.verdict.toLowerCase().includes('confirmed') || r.verdict.toLowerCase().includes('malicious');
                const isTrap = r.verdict.toLowerCase().includes('false positive');

                return (
                  <div
                    key={r.id}
                    onClick={() => setSelectedReport(r)}
                    className={`p-3.5 rounded-xl border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-cyan-950/30 border-cyan-500/80 shadow-lg shadow-cyan-950/30 ring-1 ring-cyan-500/50'
                        : 'bg-[#0F172A] border-slate-800 hover:border-slate-700 hover:bg-slate-800/40'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-1.5">
                        <span className="font-mono font-bold text-xs text-cyan-400">{r.id}</span>
                        <span className="text-[10px] text-slate-400 font-mono">({r.investigation_id})</span>
                      </div>
                      <span
                        className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${
                          isConfirmed
                            ? 'bg-rose-950/80 text-rose-300 border-rose-800/60'
                            : isTrap
                            ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800/60'
                            : 'bg-amber-950/80 text-amber-300 border-amber-800/60'
                        }`}
                      >
                        {r.verdict}
                      </span>
                    </div>

                    <div className="text-xs font-semibold text-slate-200 mt-1 line-clamp-1">
                      {r.title}
                    </div>

                    <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2.5 pt-2 border-t border-slate-800/60 font-mono">
                      <div className="flex items-center gap-2">
                        <span className="text-cyan-300 font-bold">Trust: {r.trust_score}</span>
                        <span className="text-slate-600">•</span>
                        <span className="text-indigo-300">Comp: {r.compliance_score}%</span>
                      </div>
                      <span className="text-slate-500 text-[10px]">{r.classification}</span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Selected Report Document */}
        <div className="lg:col-span-8">
          {selectedReport ? (
            <div className="bg-[#0F172A] border border-slate-800 rounded-xl p-5 sm:p-6 space-y-6 shadow-2xl">
              {/* Document Header Bar */}
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-5 border-b border-slate-800">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-cyan-400 bg-cyan-950/80 px-2 py-0.5 rounded border border-cyan-800/60">
                      {selectedReport.id}
                    </span>
                    <span className="text-xs font-mono text-slate-400">
                      Target: {selectedReport.investigation_id}
                    </span>
                    <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-slate-800 text-slate-300 border border-slate-700">
                      {selectedReport.classification}
                    </span>
                    <span className="text-[10px] uppercase font-semibold px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800">
                      {selectedReport.report_type}
                    </span>
                  </div>
                  <h2 className="text-lg font-bold text-slate-100 mt-2 font-mono">
                    {selectedReport.title}
                  </h2>
                  <div className="text-xs text-slate-400 mt-0.5">
                    Authored by <span className="text-slate-300 font-medium">{selectedReport.author}</span> • {selectedReport.created_at}
                  </div>
                </div>

                {/* Export Action Buttons */}
                <div className="flex flex-wrap items-center gap-2">
                  <a
                    href={api.getReportJsonUrl(selectedReport.id)}
                    download
                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition-all shadow-sm"
                  >
                    <FileCode className="w-3.5 h-3.5 text-cyan-400" />
                    <span>Case JSON</span>
                  </a>

                  <a
                    href={api.getReportMarkdownUrl(selectedReport.id)}
                    download
                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition-all shadow-sm"
                  >
                    <Download className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Markdown</span>
                  </a>

                  <a
                    href={api.getReportHtmlUrl(selectedReport.id)}
                    target="_blank"
                    rel="noreferrer"
                    className="px-2.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium border border-slate-700 flex items-center gap-1.5 transition-all shadow-sm"
                  >
                    <Printer className="w-3.5 h-3.5 text-indigo-400" />
                    <span>Print / HTML</span>
                  </a>

                  {onSelectInvestigation && (
                    <button
                      onClick={() => onSelectInvestigation(selectedReport.investigation_id)}
                      className="px-2.5 py-1.5 rounded-lg bg-cyan-950 hover:bg-cyan-900 text-cyan-300 text-xs font-medium border border-cyan-800/80 flex items-center gap-1.5 transition-all shadow-sm"
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      <span>Investigation</span>
                    </button>
                  )}
                </div>
              </div>

              {/* Adjudicated Verdict & Trust Card */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 bg-[#090D16] border border-slate-800 p-4 rounded-xl">
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                    Adjudicated Verdict
                  </span>
                  <div className="text-base font-bold text-slate-100 font-mono mt-1">
                    {selectedReport.verdict}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                    Evidence Trust Score
                  </span>
                  <div className="text-base font-bold text-cyan-400 font-mono mt-1">
                    {selectedReport.trust_score}/100
                  </div>
                </div>
                <div>
                  <span className="text-[10px] uppercase font-bold text-slate-400 tracking-wider">
                    Compliance Adherence
                  </span>
                  <div className="text-base font-bold text-indigo-400 font-mono mt-1">
                    {selectedReport.compliance_score}%
                  </div>
                </div>
              </div>

              {/* 1. Executive Summary */}
              <div className="space-y-2">
                <h3 className="text-xs uppercase font-bold text-cyan-400 tracking-wider flex items-center gap-1.5">
                  <FileText className="w-4 h-4" />
                  <span>1. Executive Summary</span>
                </h3>
                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 text-xs text-slate-300 leading-relaxed font-sans">
                  {selectedReport.executive_summary}
                </div>
              </div>

              {/* 2. Threat Actor Attribution Policy Guard */}
              <div className="space-y-2">
                <h3 className="text-xs uppercase font-bold text-cyan-400 tracking-wider flex items-center gap-1.5">
                  <Lock className="w-4 h-4 text-amber-400" />
                  <span>2. Threat Actor Attribution Policy & Guard</span>
                </h3>
                <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-200">
                      Attribution Status:{' '}
                      <span className="font-mono text-amber-400">
                        {selectedReport.threat_attribution.status}
                      </span>
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                      Policy Rule Enforced
                    </span>
                  </div>
                  <p className="text-xs text-slate-400">
                    <strong className="text-slate-300">Policy:</strong>{' '}
                    {selectedReport.threat_attribution.policy_note ||
                      'The system cannot assert a specific threat actor unless sufficient evidence supports the attribution. Attribution blocked.'}
                  </p>
                </div>
              </div>

              {/* 3. Regulatory Compliance Frameworks */}
              <div className="space-y-3">
                <h3 className="text-xs uppercase font-bold text-cyan-400 tracking-wider flex items-center gap-1.5">
                  <Scale className="w-4 h-4 text-indigo-400" />
                  <span>3. Regulatory Compliance Frameworks</span>
                </h3>

                {/* Framework Tabs */}
                <div className="flex flex-wrap gap-1.5 border-b border-slate-800 pb-2">
                  {Object.keys(selectedReport.compliance_mappings || {}).map((fw) => (
                    <button
                      key={fw}
                      onClick={() => setSelectedFramework(fw)}
                      className={`px-3 py-1.5 rounded-lg text-xs font-mono transition-all ${
                        selectedFramework === fw
                          ? 'bg-indigo-950 text-indigo-300 border border-indigo-700/80 font-bold'
                          : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-slate-200'
                      }`}
                    >
                      {fw}
                    </button>
                  ))}
                </div>

                {/* Active Framework Controls */}
                {selectedReport.compliance_mappings?.[selectedFramework] && (
                  <div className="p-4 rounded-xl bg-slate-900/60 border border-slate-800 space-y-3">
                    <div className="flex items-center justify-between pb-2 border-b border-slate-800/80">
                      <span className="text-xs font-bold text-slate-200 font-mono">
                        {selectedFramework}
                      </span>
                      <span className="text-xs font-mono font-bold text-emerald-400 bg-emerald-950/80 px-2.5 py-0.5 rounded border border-emerald-800/60">
                        Adherence:{' '}
                        {selectedReport.compliance_mappings[selectedFramework].adherence_score}%
                      </span>
                    </div>

                    <div className="space-y-2">
                      {selectedReport.compliance_mappings[selectedFramework].controls.map((ctrl) => (
                        <div
                          key={ctrl.control_id}
                          className="p-2.5 bg-[#090D16] border border-slate-800 rounded-lg flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                        >
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="font-mono font-bold text-cyan-400 text-[11px]">
                                [{ctrl.control_id}]
                              </span>
                              <span className="font-semibold text-slate-200 text-xs">
                                {ctrl.control_name}
                              </span>
                            </div>
                            <p className="text-[11px] text-slate-400 mt-1">{ctrl.description}</p>
                          </div>
                          <span
                            className={`px-2 py-0.5 text-[10px] font-bold rounded border shrink-0 ${
                              ctrl.status === 'COMPLIANT'
                                ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                                : 'bg-amber-950 text-amber-300 border-amber-800'
                            }`}
                          >
                            {ctrl.status}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* 4. Claims & Evidence Corroboration */}
              <div className="space-y-2">
                <h3 className="text-xs uppercase font-bold text-cyan-400 tracking-wider flex items-center gap-1.5">
                  <ShieldCheck className="w-4 h-4 text-emerald-400" />
                  <span>4. Adjudicated Claims & Supporting Evidence</span>
                </h3>
                <div className="overflow-x-auto rounded-xl border border-slate-800">
                  <table className="w-full text-xs text-left">
                    <thead className="bg-slate-900/90 text-slate-400 text-[10px] uppercase font-mono border-b border-slate-800">
                      <tr>
                        <th className="p-3">Claim ID</th>
                        <th className="p-3">Statement</th>
                        <th className="p-3">Status</th>
                        <th className="p-3">Evidence IDs</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800 bg-[#090D16]/60">
                      {selectedReport.claims.map((c) => (
                        <tr key={c.claim_id} className="hover:bg-slate-800/30">
                          <td className="p-3 font-mono font-bold text-cyan-400">{c.claim_id}</td>
                          <td className="p-3 text-slate-200">{c.statement}</td>
                          <td className="p-3">
                            <span
                              className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                                c.status === 'SUPPORTED'
                                  ? 'bg-emerald-950 text-emerald-300 border-emerald-800'
                                  : 'bg-rose-950 text-rose-300 border-rose-800'
                              }`}
                            >
                              {c.status}
                            </span>
                          </td>
                          <td className="p-3 font-mono text-slate-400">
                            {c.evidence_ids.length > 0 ? c.evidence_ids.join(', ') : 'None'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* 5. Cryptographic Attestation & Audit Seal */}
              <div className="p-4 rounded-xl bg-gradient-to-br from-teal-950/40 via-cyan-950/30 to-slate-900 border border-teal-800/50 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold text-teal-300 flex items-center gap-1.5 font-mono">
                    <ShieldCheck className="w-4 h-4 text-teal-400" />
                    Cryptographic Audit Attestation & Chain of Custody
                  </span>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-teal-950 text-teal-300 border border-teal-800">
                    Block {selectedReport.audit_entry_id || 'AUD-GENESIS'}
                  </span>
                </div>
                <p className="text-[11px] text-slate-400">
                  This report is cryptographically bound into the append-only audit trail ledger.
                  Any modification to findings or evidence invalidates the SHA-256 digital fingerprint.
                </p>
                <div className="flex items-center justify-between p-2.5 rounded-lg bg-[#090D16] border border-teal-900/60 font-mono text-xs">
                  <div className="truncate text-teal-400 pr-2">
                    <span className="text-slate-500 mr-2">SHA-256:</span>
                    {selectedReport.report_hash}
                  </div>
                  <button
                    onClick={() => handleCopyHash(selectedReport.report_hash)}
                    className="p-1 rounded hover:bg-slate-800 text-slate-400 hover:text-white transition-all shrink-0"
                    title="Copy SHA-256 fingerprint"
                  >
                    {copiedHash ? (
                      <Check className="w-3.5 h-3.5 text-emerald-400" />
                    ) : (
                      <Copy className="w-3.5 h-3.5" />
                    )}
                  </button>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center text-slate-500 bg-[#0F172A] border border-slate-800 rounded-xl text-xs">
              Select an incident report from the list to view its full compliance evaluation and export options.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
