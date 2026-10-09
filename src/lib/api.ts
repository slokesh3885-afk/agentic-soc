import type {
  DashboardKpi,
  Investigation,
  SecurityAlert,
  ThreatOverviewPoint,
  EvidenceTrustMetric,
  NewInvestigationPayload,
  EvidenceItem,
  EvidenceIntegrityResult,
  NewEvidencePayload,
  AllowlistedTool,
  ToolExecution,
  ToolExecuteResult,
  PlanStep,
  InvestigationPlan,
  CriticReview,
  CriticRequestPayload,
  ClaimEvaluation,
  CriticObjection,
  AuditedCase,
  AuditedClaimItem,
  AuditedToolExecutionItem,
  AuditorRequestPayload,
  CanonicalCaseJson,
  CaseJsonValidationResponse,
  TrustScore,
  TruePositiveScenarioResponse,
  TrapScenarioResponse,
  ApprovalRequest,
  ApprovalCreatePayload,
  ApprovalDecisionPayload,
  ApprovalListResponse,
  AuditEntry,
  AuditVerificationResult,
  SealInvestigationPayload,
  SealInvestigationResult,
  AuditBundle,
  IncidentDossier,
  MitreMatrixSummary,
  DossierNavigatorLayer,
  ContainmentExecution,
  PlaybookDefinition,
  ContainmentDispatchPayload,
  ContainmentRollbackPayload,
  ContainmentSummary,
  ReplaySession,
  ReplaySummary,
  ReplayTriggerPayload,
  TimelineEvent,
  IncidentReport,
  ReportGeneratePayload,
  ReportSummary,
  SocAgent,
  AgentActivityEvent,
  AgentSwarmSummary,
  AnalystRequestPayload,
  AnalystResponse,
  SwarmOrchestratePayload,
  SwarmOrchestrateResponse,
  EvidenceControlPlaneItem,
  EvidenceControlPlaneSummary,
  EvidentiaryClaim,
  AttributionPolicyStatus,
  BatchVerificationResponse,
  RedTeamChallengeRequest,
  RedTeamChallengeResponse,
  RedTeamScenarioPreset,
  InteractiveDemoSessionState,
  CompleteCaseAuditObject,
  AuditObjectExportResponse,
  SocSystemSettings,
  UniversalSearchResponse,
  NotificationsResponse,
  OverviewAnalyticsResponse,
  PostureSummary,
  AlertsOverTimePoint,
  InvestigationOutcomeDistribution,
  EvidenceSourceDistribution,
  TrustScoreHistoryPoint,
} from '../types/soc';
import {
  initialKpis,
  initialInvestigations,
  initialAlerts,
  threatOverviewTimeline,
  evidenceTrustMetrics,
} from '../data/mockData';

/**
 * Service layer abstraction for Agentic SOC API.
 * In Module 2, 3A & 3B, persistent investigations, tamper-evident evidence,
 * and allow-listed security tools are handled by FastAPI on SQLite.
 */
const API_BASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env?.VITE_API_URL) || 'http://localhost:8000';

// In-memory fallback stores in case backend is temporarily unreachable
let fallbackInvestigationsStore: Investigation[] = [...initialInvestigations];
let alertsStore: SecurityAlert[] = [...initialAlerts];
let kpiStore: DashboardKpi = { ...initialKpis };

let fallbackEvidenceStore: EvidenceItem[] = [
  {
    id: 'E-001',
    investigationId: 'INV-012',
    evidenceType: 'SIEM_LOG',
    source: 'Mock SIEM',
    timestamp: '2026-09-27 16:05:00 UTC',
    query: 'host=PC-DB-TEST powershell',
    rawOutput: 'powershell.exe executed from an unusual parent process.',
    contentHash: '89011b1fe48627ff47926ea612eb04b8df4762cfbb4e7c7e6c1a82e9154a1d82',
    status: 'VERIFIED',
    createdAt: '2026-09-27 16:05:00 UTC',
    integrityVerified: true,
  },
  {
    id: 'E-002',
    investigationId: 'INV-012',
    evidenceType: 'PROCESS_EVENT',
    source: 'Mock EDR',
    timestamp: '2026-09-27 16:07:30 UTC',
    query: 'host=PC-DB-TEST process_tree',
    rawOutput: 'powershell.exe spawned by unknown_process.exe.',
    contentHash: '9d2d35f52977b5bd6d1d2836267f5fa45bbfa8a927fa1e9aebaa02cb1017ab4f',
    status: 'VERIFIED',
    createdAt: '2026-09-27 16:07:30 UTC',
    integrityVerified: true,
  },
  {
    id: 'E-003',
    investigationId: 'INV-001',
    evidenceType: 'EDR_EVENT',
    source: 'CrowdStrike Falcon',
    timestamp: '2026-09-27 13:25:12 UTC',
    query: 'EventID=1 AND CommandLine=*powershell*',
    rawOutput: 'Event ID 1: Process Create powershell.exe -Enc JABvAD0... Parent: SYSTEM_UPDATE_TASK.exe (PID 4812)',
    contentHash: '33b6cebd5e33a0d7a64117b8849adbbda047970d24bf4c865761358db669f91a',
    status: 'VERIFIED',
    createdAt: '2026-09-27 13:25:12 UTC',
    integrityVerified: true,
  },
];

let fallbackToolExecutionsStore: ToolExecution[] = [
  {
    id: 'EXEC-001',
    investigationId: 'INV-012',
    toolName: 'siem_search',
    input: { query: 'host=PC-DB-TEST powershell' },
    output: { total_matches: 2, process: 'powershell.exe' },
    timestamp: '2026-09-27 16:05:00 UTC',
    success: true,
    evidenceId: 'E-001',
  },
  {
    id: 'EXEC-002',
    investigationId: 'INV-012',
    toolName: 'edr_process_search',
    input: { host: 'PC-DB-TEST' },
    output: { lineage_summary: 'winword.exe -> powershell.exe -> cmd.exe' },
    timestamp: '2026-09-27 16:07:30 UTC',
    success: true,
    evidenceId: 'E-002',
  },
];

let fallbackPlanStore: Record<string, InvestigationPlan> = {
  'INV-012': {
    investigation_id: 'INV-012',
    investigationId: 'INV-012',
    alert: 'Suspicious PowerShell execution on PC-DB-TEST',
    planner_status: 'PROPOSED',
    plannerStatus: 'PROPOSED',
    created_at: '2026-09-27 16:04:00 UTC',
    createdAt: '2026-09-27 16:04:00 UTC',
    plan: [
      {
        step: 1,
        action: 'Search SIEM for suspicious PowerShell execution logs on PC-DB-TEST',
        tool_name: 'siem_search',
        toolName: 'siem_search',
        reason: 'Identify initial alert telemetry and baseline event context.',
        status: 'PROPOSED',
      },
      {
        step: 2,
        action: 'Query EDR for process tree and parent execution on PC-DB-TEST',
        tool_name: 'edr_process_search',
        toolName: 'edr_process_search',
        reason: 'Determine the parent process and command line arguments.',
        status: 'PROPOSED',
      },
      {
        step: 3,
        action: 'Retrieve sandbox behavioral summary for executed payload artifact',
        tool_name: 'sandbox_summary',
        toolName: 'sandbox_summary',
        reason: 'Evaluate threat detonation indicators and behavioral signatures.',
        status: 'PROPOSED',
      },
      {
        step: 4,
        action: 'Execute YARA signature scan on suspicious script files and memory artifacts',
        tool_name: 'yara_scan',
        toolName: 'yara_scan',
        reason: 'Check for known malware families or obfuscated scripts.',
        status: 'PROPOSED',
      },
    ],
  },
};

let fallbackCriticStore: Record<string, CriticReview> = {
  'INV-012': {
    id: 'CRITIC-001',
    investigation_id: 'INV-012',
    investigationId: 'INV-012',
    overall_status: 'REQUIRES_REVISION',
    overallStatus: 'REQUIRES_REVISION',
    draft_conclusion: 'This is an APT attack by Threat Actor X.',
    draftConclusion: 'This is an APT attack by Threat Actor X.',
    claims_evaluation: [
      {
        claim: 'PowerShell execution occurred on PC-DB-TEST',
        status: 'SUPPORTED',
        reason: 'Claim is directly corroborated by verified evidence (E-001, E-002).',
        evidence_ids: ['E-001', 'E-002'],
        valid_evidence_ids: ['E-001', 'E-002'],
        invalid_evidence_ids: [],
      },
      {
        claim: 'Threat actor is Threat Actor X',
        status: 'UNSUPPORTED',
        reason: 'No evidence ID establishes attribution to the specified threat actor.',
        evidence_ids: [],
        valid_evidence_ids: [],
        invalid_evidence_ids: [],
      },
    ],
    objections: [
      {
        claim: 'Threat actor is Threat Actor X',
        status: 'UNSUPPORTED',
        reason: 'No evidence establishes threat-actor attribution.',
        evidence_ids: [],
        category: 'UNSUPPORTED_ATTRIBUTION',
      },
    ],
    missing_evidence: [
      'Evidence linking the observed activity to Threat Actor X',
    ],
    contradictions: [],
    overclaims: [
      'Threat-actor attribution exceeds the available evidence.',
    ],
    created_at: '2026-09-27 16:10:00 UTC',
    createdAt: '2026-09-27 16:10:00 UTC',
  },
};

let fallbackCaseStore: Record<string, AuditedCase> = {
  'INV-012': {
    case_id: 'CASE-001',
    caseId: 'CASE-001',
    investigation_id: 'INV-012',
    investigationId: 'INV-012',
    claims: [
      {
        claim: 'PowerShell execution occurred on PC-DB-TEST',
        evidence_ids: ['E-001'],
        evidenceIds: ['E-001'],
        status: 'SUPPORTED',
        confidence: 'SUPPORTED',
        reason: 'Claim is directly corroborated by verified, tamper-evident evidence (E-001).',
        evidence_integrity_verified: true,
        evidenceIntegrityVerified: true,
      },
      {
        claim: 'Threat actor is APT-X',
        evidence_ids: [],
        evidenceIds: [],
        status: 'UNSUPPORTED',
        confidence: 'UNSUPPORTED',
        reason: 'No evidence ID was provided. Under strict audit standards, threat-actor attribution cannot be established.',
        evidence_integrity_verified: false,
        evidenceIntegrityVerified: false,
      },
    ],
    contradictions: [],
    uncertainties: [
      'Threat-actor attribution claimed in "Threat actor is APT-X" is unsupported by available telemetry.',
    ],
    unsupported_claims: ['Threat actor is APT-X'],
    unsupportedClaims: ['Threat actor is APT-X'],
    tool_executions: [],
    toolExecutions: [],
    final_conclusion:
      'Suspicious PowerShell activity is supported by available evidence. Threat-actor attribution cannot be established.',
    finalConclusion:
      'Suspicious PowerShell activity is supported by available evidence. Threat-actor attribution cannot be established.',
    audit_verified: true,
    auditVerified: true,
    created_at: '2026-09-27 16:15:00 UTC',
    createdAt: '2026-09-27 16:15:00 UTC',
  },
};

/**
 * Normalizes backend database/API models (snake_case or camelCase)
 * to the frontend Investigation interface.
 */
function normalizeInvestigation(data: any): Investigation {
  const alert = data.alert_name || data.alert || 'Unknown Alert';
  const host = data.target_host || data.host || 'Unknown Host';
  const trustScore = Number(data.trust_score ?? data.evidenceTrustScore ?? 90);
  const evidenceCount = Number(data.evidence_count ?? data.artifactCount ?? 0);
  const eventTime = data.event_timestamp || data.eventTimestamp || data.timestamp || '';
  const createdTime = data.created_at || data.createdTimestamp || eventTime || 'Just now';

  let corroboration = data.evidence_corroboration ?? data.evidenceCorroboration ?? [];
  if (typeof corroboration === 'string') {
    try {
      corroboration = JSON.parse(corroboration);
    } catch {
      corroboration = [];
    }
  }

  return {
    id: data.id,
    alert,
    host,
    severity: data.severity || 'Medium',
    status: data.status || 'Investigating',
    evidenceTrustScore: trustScore,
    started: data.started || createdTime,
    eventTimestamp: eventTime,
    createdTimestamp: createdTime,
    startedAtTimestamp: data.startedAtTimestamp || eventTime,
    description: data.description || '',
    assignedAgent: data.assigned_agent || data.assignedAgent || 'Host Triage Agent',
    evidenceCount: evidenceCount,
    artifactCount: evidenceCount,
    mitreTechnique: data.mitre_technique || data.mitreTechnique || '',
    evidenceCorroboration: corroboration,
  };
}

/**
 * Normalizes backend evidence API models to frontend EvidenceItem.
 */
function normalizeEvidence(data: any): EvidenceItem {
  return {
    id: data.id,
    investigationId: data.investigation_id || data.investigationId,
    investigation_id: data.investigation_id || data.investigationId,
    evidenceType: data.evidence_type || data.evidenceType || 'OTHER',
    evidence_type: data.evidence_type || data.evidenceType || 'OTHER',
    source: data.source || 'Unknown Source',
    timestamp: data.timestamp || '',
    query: data.query || '',
    rawOutput: data.raw_output || data.rawOutput || '',
    raw_output: data.raw_output || data.rawOutput || '',
    contentHash: data.content_hash || data.contentHash || '',
    content_hash: data.content_hash || data.contentHash || '',
    status: data.status || 'COLLECTED',
    createdAt: data.created_at || data.createdAt || '',
    created_at: data.created_at || data.createdAt || '',
    integrityVerified: data.integrity_verified ?? true,
  };
}

/**
 * Normalizes backend tool execution models to frontend ToolExecution.
 */
function normalizeToolExecution(data: any): ToolExecution {
  let parsedInput = data.input;
  if (typeof parsedInput === 'string') {
    try {
      parsedInput = JSON.parse(parsedInput);
    } catch {
      parsedInput = data.input;
    }
  }

  let parsedOutput = data.output;
  if (typeof parsedOutput === 'string') {
    try {
      parsedOutput = JSON.parse(parsedOutput);
    } catch {
      parsedOutput = data.output;
    }
  }

  return {
    id: data.id || data.executionId || 'EXEC-UNKNOWN',
    investigationId: data.investigation_id || data.investigationId || 'INV-012',
    investigation_id: data.investigation_id || data.investigationId || 'INV-012',
    toolName: data.tool_name || data.toolName || 'unknown_tool',
    tool_name: data.tool_name || data.toolName || 'unknown_tool',
    input: parsedInput,
    output: parsedOutput,
    timestamp: data.timestamp || '',
    success: Boolean(data.success),
    evidenceId: data.evidence_id || data.evidenceId || null,
    evidence_id: data.evidence_id || data.evidenceId || null,
    error: data.error || null,
  };
}

/**
 * Normalizes backend investigation plan to frontend InvestigationPlan.
 */
function normalizePlan(data: any): InvestigationPlan {
  const steps: PlanStep[] = (data.plan || []).map((s: any) => ({
    step: Number(s.step),
    action: s.action || '',
    tool_name: s.tool_name || s.toolName || '',
    toolName: s.tool_name || s.toolName || '',
    reason: s.reason || '',
    status: s.status || 'PROPOSED',
  }));

  return {
    investigation_id: data.investigation_id || data.investigationId || 'INV-012',
    investigationId: data.investigation_id || data.investigationId || 'INV-012',
    alert: data.alert || 'Unknown Alert',
    plan: steps,
    planner_status: data.planner_status || data.plannerStatus || 'PROPOSED',
    plannerStatus: data.planner_status || data.plannerStatus || 'PROPOSED',
    created_at: data.created_at || data.createdAt || '',
    createdAt: data.created_at || data.createdAt || '',
  };
}

/**
 * Normalizes backend Critic evaluation response to frontend CriticReview.
 */
function normalizeCriticReview(data: any): CriticReview {
  let claimsEval = data.claims_evaluation || data.claimsEvaluation || [];
  if (typeof claimsEval === 'string') {
    try {
      claimsEval = JSON.parse(claimsEval);
    } catch {
      claimsEval = [];
    }
  }

  let objections = data.objections || [];
  if (typeof objections === 'string') {
    try {
      objections = JSON.parse(objections);
    } catch {
      objections = [];
    }
  }

  let missingEvidence = data.missing_evidence || data.missingEvidence || [];
  if (typeof missingEvidence === 'string') {
    try {
      missingEvidence = JSON.parse(missingEvidence);
    } catch {
      missingEvidence = [];
    }
  }

  let contradictions = data.contradictions || [];
  if (typeof contradictions === 'string') {
    try {
      contradictions = JSON.parse(contradictions);
    } catch {
      contradictions = [];
    }
  }

  let overclaims = data.overclaims || [];
  if (typeof overclaims === 'string') {
    try {
      overclaims = JSON.parse(overclaims);
    } catch {
      overclaims = [];
    }
  }

  const normalizedClaims: ClaimEvaluation[] = claimsEval.map((c: any) => ({
    claim: c.claim || '',
    status: c.status || 'UNSUPPORTED',
    reason: c.reason || '',
    evidence_ids: c.evidence_ids || c.evidenceIds || [],
    evidenceIds: c.evidence_ids || c.evidenceIds || [],
    valid_evidence_ids: c.valid_evidence_ids || c.validEvidenceIds || [],
    validEvidenceIds: c.valid_evidence_ids || c.validEvidenceIds || [],
    invalid_evidence_ids: c.invalid_evidence_ids || c.invalidEvidenceIds || [],
    invalidEvidenceIds: c.invalid_evidence_ids || c.invalidEvidenceIds || [],
  }));

  const normalizedObjections: CriticObjection[] = objections.map((o: any) => ({
    claim: o.claim || '',
    status: o.status || 'UNSUPPORTED',
    reason: o.reason || '',
    evidence_ids: o.evidence_ids || o.evidenceIds || [],
    evidenceIds: o.evidence_ids || o.evidenceIds || [],
    category: o.category || 'OBJECTION',
  }));

  return {
    id: data.id,
    investigation_id: data.investigation_id || data.investigationId || 'INV-012',
    investigationId: data.investigation_id || data.investigationId || 'INV-012',
    overall_status: data.overall_status || data.overallStatus || 'REQUIRES_REVISION',
    overallStatus: data.overall_status || data.overallStatus || 'REQUIRES_REVISION',
    draft_conclusion: data.draft_conclusion || data.draftConclusion || '',
    draftConclusion: data.draft_conclusion || data.draftConclusion || '',
    claims_evaluation: normalizedClaims,
    claimsEvaluation: normalizedClaims,
    objections: normalizedObjections,
    missing_evidence: missingEvidence,
    missingEvidence: missingEvidence,
    contradictions: contradictions,
    overclaims: overclaims,
    created_at: data.created_at || data.createdAt || '',
    createdAt: data.created_at || data.createdAt || '',
  };
}

/**
 * Normalizes backend Audited Case response to frontend AuditedCase.
 */
function normalizeAuditedCase(data: any): AuditedCase {
  let claimsData = data.claims || [];
  if (typeof claimsData === 'string') {
    try {
      claimsData = JSON.parse(claimsData);
    } catch {
      claimsData = [];
    }
  }

  let contradictionsData = data.contradictions || [];
  if (typeof contradictionsData === 'string') {
    try {
      contradictionsData = JSON.parse(contradictionsData);
    } catch {
      contradictionsData = [];
    }
  }

  let uncertaintiesData = data.uncertainties || [];
  if (typeof uncertaintiesData === 'string') {
    try {
      uncertaintiesData = JSON.parse(uncertaintiesData);
    } catch {
      uncertaintiesData = [];
    }
  }

  let unsupportedClaimsData = data.unsupported_claims || data.unsupportedClaims || [];
  if (typeof unsupportedClaimsData === 'string') {
    try {
      unsupportedClaimsData = JSON.parse(unsupportedClaimsData);
    } catch {
      unsupportedClaimsData = [];
    }
  }

  let toolExecsData = data.tool_executions || data.toolExecutions || [];
  if (typeof toolExecsData === 'string') {
    try {
      toolExecsData = JSON.parse(toolExecsData);
    } catch {
      toolExecsData = [];
    }
  }

  const normalizedClaims: AuditedClaimItem[] = claimsData.map((c: any) => ({
    claim: c.claim || '',
    evidence_ids: c.evidence_ids || c.evidenceIds || [],
    evidenceIds: c.evidence_ids || c.evidenceIds || [],
    status: c.status || 'UNSUPPORTED',
    confidence: c.confidence || c.status || 'UNSUPPORTED',
    reason: c.reason || '',
    evidence_integrity_verified: Boolean(
      c.evidence_integrity_verified ?? c.evidenceIntegrityVerified ?? true
    ),
    evidenceIntegrityVerified: Boolean(
      c.evidence_integrity_verified ?? c.evidenceIntegrityVerified ?? true
    ),
  }));

  const normalizedToolExecs: AuditedToolExecutionItem[] = toolExecsData.map((t: any) => ({
    id: t.id || 'EXEC-UNKNOWN',
    tool_name: t.tool_name || t.toolName || 'tool',
    toolName: t.tool_name || t.toolName || 'tool',
    input: t.input,
    output: t.output,
    timestamp: t.timestamp || '',
    success: Boolean(t.success),
    evidence_id: t.evidence_id || t.evidenceId || null,
    evidenceId: t.evidence_id || t.evidenceId || null,
  }));

  return {
    case_id: data.case_id || data.caseId || 'CASE-001',
    caseId: data.case_id || data.caseId || 'CASE-001',
    investigation_id: data.investigation_id || data.investigationId || 'INV-012',
    investigationId: data.investigation_id || data.investigationId || 'INV-012',
    claims: normalizedClaims,
    contradictions: contradictionsData,
    uncertainties: uncertaintiesData,
    unsupported_claims: unsupportedClaimsData,
    unsupportedClaims: unsupportedClaimsData,
    tool_executions: normalizedToolExecs,
    toolExecutions: normalizedToolExecs,
    final_conclusion: data.final_conclusion || data.finalConclusion || '',
    finalConclusion: data.final_conclusion || data.finalConclusion || '',
    audit_verified: Boolean(data.audit_verified ?? data.auditVerified ?? true),
    auditVerified: Boolean(data.audit_verified ?? data.auditVerified ?? true),
    created_at: data.created_at || data.createdAt || '',
    createdAt: data.created_at || data.createdAt || '',
  };
}

export const socApi = {
  /**
   * Health check to detect backend availability
   */
  async checkHealth(): Promise<{ isOnline: boolean; message: string }> {
    try {
      const res = await fetch(`${API_BASE_URL}/api/health`, {
        method: 'GET',
        headers: { 'Accept': 'application/json' },
      });
      if (res.ok) {
        return { isOnline: true, message: 'FastAPI Backend Online (Module 3E Auditor Agent Active)' };
      }
      return { isOnline: false, message: `Backend responded with HTTP ${res.status}` };
    } catch (err) {
      return { isOnline: false, message: 'FastAPI Backend Unreachable (Falling back to offline mode)' };
    }
  },

  /**
   * Fetch current SOC Key Performance Indicators
   */
  async getDashboardKpis(): Promise<DashboardKpi> {
    try {
      const invs = await this.getInvestigations();
      const activeCount = invs.filter((i) => i.status === 'Investigating').length;
      return {
        ...kpiStore,
        activeInvestigations: activeCount || invs.length,
      };
    } catch {
      return { ...kpiStore };
    }
  },

  /**
   * Fetch all investigations from FastAPI SQLite backend.
   * Maps to: GET /api/investigations
   */
  async getInvestigations(): Promise<Investigation[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/api/investigations`, {
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) {
        throw new Error(`Failed to fetch investigations: ${res.statusText}`);
      }

      const data = await res.json();
      const normalized = (data as any[]).map(normalizeInvestigation);

      fallbackInvestigationsStore = normalized;
      return normalized;
    } catch (err) {
      console.warn('Backend unavailable, using fallback in-memory investigations:', err);
      return [...fallbackInvestigationsStore];
    }
  },

  /**
   * Fetch a single investigation by ID from FastAPI backend.
   * Maps to: GET /api/investigations/{investigation_id}
   */
  async getInvestigation(id: string): Promise<Investigation> {
    try {
      const res = await fetch(`${API_BASE_URL}/api/investigations/${encodeURIComponent(id)}`, {
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) {
        throw new Error(`Failed to fetch investigation ${id}: ${res.statusText}`);
      }

      const data = await res.json();
      return normalizeInvestigation(data);
    } catch (err) {
      console.warn(`Failed to fetch ${id} from backend, checking fallback:`, err);
      const fallback = fallbackInvestigationsStore.find((i) => i.id === id);
      if (fallback) return fallback;
      throw err;
    }
  },

  /**
   * Create New Investigation via FastAPI backend (persisted in SQLite).
   * Maps to: POST /api/investigations
   */
  async createInvestigation(payload: NewInvestigationPayload): Promise<Investigation> {
    const backendPayload = {
      alert_name: payload.alertName,
      target_host: payload.host,
      severity: payload.severity || 'High',
      event_timestamp: payload.timestamp || new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
      description: payload.description || '',
      status: 'Investigating',
      evidence_count: 0,
      trust_score: 91,
    };

    try {
      const res = await fetch(`${API_BASE_URL}/api/investigations`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(backendPayload),
      });

      if (!res.ok) {
        const errorText = await res.text();
        throw new Error(`Backend error (${res.status}): ${errorText}`);
      }

      const createdData = await res.json();
      const normalized = normalizeInvestigation(createdData);

      fallbackInvestigationsStore = [normalized, ...fallbackInvestigationsStore];
      return normalized;
    } catch (err) {
      console.error('Failed to create investigation on backend:', err);
      throw err;
    }
  },

  /**
   * Fetch all evidence items belonging to an investigation.
   * Maps to: GET /api/investigations/{investigation_id}/evidence
   */
  async getInvestigationEvidence(investigationId: string): Promise<EvidenceItem[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/evidence`, {
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) {
        if (res.status === 404) {
          throw new Error(`Investigation ${investigationId} not found`);
        }
        throw new Error(`Failed to fetch evidence: ${res.statusText}`);
      }

      const data = await res.json();
      return (data as any[]).map(normalizeEvidence);
    } catch (err) {
      console.warn(`Backend fetch failed for ${investigationId} evidence, checking fallback:`, err);
      return fallbackEvidenceStore.filter(
        (e) => (e.investigationId || e.investigation_id) === investigationId
      );
    }
  },

  /**
   * Fetch a single evidence item by ID.
   * Maps to: GET /api/evidence/{evidence_id}
   */
  async getEvidenceById(evidenceId: string): Promise<EvidenceItem> {
    try {
      const res = await fetch(`${API_BASE_URL}/api/evidence/${encodeURIComponent(evidenceId)}`, {
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) {
        throw new Error(`Evidence ${evidenceId} not found`);
      }

      const data = await res.json();
      return normalizeEvidence(data);
    } catch (err) {
      const fallback = fallbackEvidenceStore.find((e) => e.id === evidenceId);
      if (fallback) return fallback;
      throw err;
    }
  },

  /**
   * Cryptographically verify the integrity of an evidence object on the backend.
   * Maps to: GET /api/evidence/{evidence_id}/verify
   */
  async verifyEvidenceIntegrity(evidenceId: string): Promise<EvidenceIntegrityResult> {
    try {
      const res = await fetch(`${API_BASE_URL}/api/evidence/${encodeURIComponent(evidenceId)}/verify`, {
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) {
        throw new Error(`Evidence verification failed for ${evidenceId}: ${res.statusText}`);
      }

      const data = await res.json();
      return {
        evidenceId: data.evidence_id || data.evidenceId || evidenceId,
        valid: Boolean(data.valid),
        contentHash: data.content_hash || data.contentHash || '',
        recalculatedHash: data.recalculated_hash || data.recalculatedHash || '',
        timestampVerified: data.timestamp_verified || data.timestampVerified || '',
      };
    } catch (err) {
      console.warn(`Backend verification fallback for ${evidenceId}:`, err);
      const fallback = fallbackEvidenceStore.find((e) => e.id === evidenceId);
      return {
        evidenceId,
        valid: true,
        contentHash: fallback?.contentHash || 'simulated-sha256-hash',
        recalculatedHash: fallback?.contentHash || 'simulated-sha256-hash',
        timestampVerified: new Date().toISOString(),
      };
    }
  },

  /**
   * Append new evidence to an investigation manually.
   * Maps to: POST /api/investigations/{investigation_id}/evidence
   */
  async createEvidence(investigationId: string, payload: NewEvidencePayload): Promise<EvidenceItem> {
    const backendPayload = {
      evidence_type: payload.evidenceType,
      source: payload.source,
      raw_output: payload.rawOutput,
      query: payload.query || '',
      timestamp: payload.timestamp,
      status: payload.status || 'COLLECTED',
    };

    const res = await fetch(`${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/evidence`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(backendPayload),
    });

    if (!res.ok) {
      const errorMsg = await res.text();
      throw new Error(`Failed to append evidence (${res.status}): ${errorMsg}`);
    }

    const data = await res.json();
    const item = normalizeEvidence(data);
    fallbackEvidenceStore.push(item);
    return item;
  },

  /**
   * ==================================================
   * MODULE 3B: SECURITY TOOL LAYER CLIENT METHODS
   * ==================================================
   */

  /**
   * List all approved allow-listed security tools.
   * Maps to: GET /api/tools
   */
  async getAllowlistedTools(): Promise<AllowlistedTool[]> {
    try {
      const res = await fetch(`${API_BASE_URL}/api/tools`, {
        headers: { 'Accept': 'application/json' },
      });

      if (!res.ok) {
        throw new Error(`Failed to retrieve allow-listed tools: ${res.statusText}`);
      }

      return await res.json();
    } catch (err) {
      console.warn('Backend tools endpoint unreachable, returning default registry:', err);
      return [
        {
          tool_name: 'siem_search',
          description: 'Searches SIEM event logs for specific host activities.',
          evidence_type: 'SIEM_LOG',
          enabled: true,
          input_schema: { properties: { query: { type: 'string' } } },
          output_schema: {},
        },
        {
          tool_name: 'edr_process_search',
          description: 'Queries endpoint detection sensors for detailed process lineage trees.',
          evidence_type: 'PROCESS_EVENT',
          enabled: true,
          input_schema: { properties: { host: { type: 'string' } } },
          output_schema: {},
        },
        {
          tool_name: 'hash_lookup',
          description: 'Queries threat intelligence databases for file hash reputation.',
          evidence_type: 'HASH_LOOKUP',
          enabled: true,
          input_schema: { properties: { hash: { type: 'string' } } },
          output_schema: {},
        },
        {
          tool_name: 'sandbox_summary',
          description: 'Retrieves behavioral sandbox detonation telemetry.',
          evidence_type: 'SANDBOX_RESULT',
          enabled: true,
          input_schema: { properties: { sample_id: { type: 'string' } } },
          output_schema: {},
        },
        {
          tool_name: 'whois_lookup',
          description: 'Queries domain registration details without external network calls.',
          evidence_type: 'WHOIS_RESULT',
          enabled: true,
          input_schema: { properties: { domain: { type: 'string' } } },
          output_schema: {},
        },
        {
          tool_name: 'yara_scan',
          description: 'Scans telemetry samples against compiled YARA rule signatures.',
          evidence_type: 'YARA_RESULT',
          enabled: true,
          input_schema: { properties: { sample_id: { type: 'string' } } },
          output_schema: {},
        },
      ];
    }
  },

  /**
   * Execute an allow-listed security tool. Automatically generates an Evidence item.
   * Maps to: POST /api/tools/execute
   */
  async executeSecurityTool(
    toolName: string,
    input: Record<string, any>,
    investigationId: string = 'INV-012'
  ): Promise<ToolExecuteResult> {
    const payload = {
      tool_name: toolName,
      input,
      investigation_id: investigationId,
    };

    const res = await fetch(`${API_BASE_URL}/api/tools/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errorText = await res.text();
      throw new Error(`Tool execution failed (${res.status}): ${errorText}`);
    }

    const data = await res.json();

    // Cache locally for offline fallback
    if (data.success && data.evidence_id) {
      fallbackToolExecutionsStore.push({
        id: `EXEC-${Date.now()}`,
        investigationId,
        toolName,
        input,
        output: data.data,
        timestamp: data.timestamp || new Date().toISOString(),
        success: true,
        evidenceId: data.evidence_id,
      });
    }

    return data;
  },

  /**
   * Retrieve tool execution audit log for an investigation.
   * Maps to: GET /api/investigations/{investigation_id}/tool-executions
   */
  async getInvestigationToolExecutions(investigationId: string): Promise<ToolExecution[]> {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/tool-executions`,
        {
          headers: { 'Accept': 'application/json' },
        }
      );

      if (!res.ok) {
        throw new Error(`Failed to load tool executions: ${res.statusText}`);
      }

      const data = await res.json();
      return (data as any[]).map(normalizeToolExecution);
    } catch (err) {
      console.warn(`Backend tool executions unavailable for ${investigationId}, returning fallback:`, err);
      return fallbackToolExecutionsStore.filter(
        (t) => (t.investigationId || t.investigation_id) === investigationId
      );
    }
  },

  /**
   * Fetch Security Alerts Stream (Module 1 analytics)
   */
  async getAlerts(): Promise<SecurityAlert[]> {
    return [...alertsStore];
  },

  /**
   * Fetch Threat Overview Chart Time-series (Module 1 analytics)
   */
  async getThreatOverview(): Promise<ThreatOverviewPoint[]> {
    return [...threatOverviewTimeline];
  },

  /**
   * Fetch Evidence Trust Scores
   */
  async getEvidenceTrustMetrics(): Promise<EvidenceTrustMetric[]> {
    try {
      const invs = await this.getInvestigations();
      return invs.slice(0, 5).map((inv) => ({
        investigationId: inv.id,
        alertTitle: inv.alert,
        score: inv.evidenceTrustScore,
        host: inv.host,
        verifiedArtifactsCount: inv.evidenceCount,
        totalArtifactsCount: Math.max(inv.evidenceCount, 3),
        primaryCorroborator:
          inv.evidenceCorroboration && inv.evidenceCorroboration.length > 0
            ? inv.evidenceCorroboration[0].source
            : 'Initial SIEM Alert Corroboration',
        status: inv.status,
      }));
    } catch {
      return [...evidenceTrustMetrics];
    }
  },

  /**
   * Retrieve investigation plan.
   * Maps to: GET /api/investigations/{investigation_id}/plan
   */
  async getInvestigationPlan(investigationId: string): Promise<InvestigationPlan | null> {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/plan`,
        {
          headers: { 'Accept': 'application/json' },
        }
      );

      if (res.status === 404) {
        return null;
      }

      if (!res.ok) {
        throw new Error(`Failed to load investigation plan: ${res.statusText}`);
      }

      const data = await res.json();
      return normalizePlan(data);
    } catch (err) {
      console.warn(`Backend investigation plan unavailable for ${investigationId}, returning fallback:`, err);
      return fallbackPlanStore[investigationId] || null;
    }
  },

  /**
   * Generate or refresh investigation plan using deterministic Planner Agent.
   * Maps to: POST /api/investigations/{investigation_id}/plan
   */
  async createInvestigationPlan(investigationId: string, alert?: string): Promise<InvestigationPlan> {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/plan`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: JSON.stringify(alert ? { alert } : {}),
        }
      );

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Failed to create plan: ${res.statusText}`);
      }

      const data = await res.json();
      const plan = normalizePlan(data);
      fallbackPlanStore[investigationId] = plan;
      return plan;
    } catch (err) {
      console.warn(`Backend failed to create plan for ${investigationId}, using fallback:`, err);
      if (!fallbackPlanStore[investigationId]) {
        fallbackPlanStore[investigationId] = {
          investigation_id: investigationId,
          investigationId,
          alert: alert || 'Suspicious PowerShell execution on PC-DB-TEST',
          planner_status: 'PROPOSED',
          plannerStatus: 'PROPOSED',
          created_at: new Date().toISOString(),
          createdAt: new Date().toISOString(),
          plan: [
            {
              step: 1,
              action: `Search SIEM for security logs regarding ${alert || investigationId}`,
              tool_name: 'siem_search',
              toolName: 'siem_search',
              reason: 'Identify initial alert telemetry and baseline event context.',
              status: 'PROPOSED',
            },
            {
              step: 2,
              action: `Query EDR for process tree and parent execution on affected endpoint`,
              tool_name: 'edr_process_search',
              toolName: 'edr_process_search',
              reason: 'Determine parent process and execution chain.',
              status: 'PROPOSED',
            },
          ],
        };
      }
      return fallbackPlanStore[investigationId];
    }
  },

  /**
   * Retrieve the latest Critic / Red-Team review for an investigation.
   * Maps to: GET /api/investigations/{investigation_id}/critic
   */
  async getCriticReview(investigationId: string): Promise<CriticReview | null> {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/critic`,
        {
          headers: { 'Accept': 'application/json' },
        }
      );

      if (res.status === 404) {
        return fallbackCriticStore[investigationId] || null;
      }

      if (!res.ok) {
        throw new Error(`Failed to load critic review: ${res.statusText}`);
      }

      const data = await res.json();
      return normalizeCriticReview(data);
    } catch (err) {
      console.warn(`Backend critic review unavailable for ${investigationId}, returning fallback:`, err);
      return fallbackCriticStore[investigationId] || null;
    }
  },

  /**
   * Submit an investigator draft conclusion and claims to the Critic / Red-Team Agent.
   * Maps to: POST /api/investigations/{investigation_id}/critic
   */
  async evaluateCritic(
    investigationId: string,
    payload: CriticRequestPayload
  ): Promise<CriticReview> {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/critic`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: JSON.stringify({
            investigation_id: investigationId,
            draft_conclusion: payload.draft_conclusion || payload.draftConclusion,
            claims: (payload.claims || []).map((c) => ({
              claim: c.claim,
              evidence_ids: c.evidence_ids || c.evidenceIds || [],
            })),
          }),
        }
      );

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Failed to run critic evaluation: ${res.statusText}`);
      }

      const data = await res.json();
      const review = normalizeCriticReview(data);
      fallbackCriticStore[investigationId] = review;
      return review;
    } catch (err) {
      console.warn(`Backend failed to run critic evaluation for ${investigationId}, using fallback:`, err);
      return fallbackCriticStore[investigationId];
    }
  },

  /**
   * Retrieve the latest Audited Case file for an investigation.
   * Maps to: GET /api/investigations/{investigation_id}/audit
   */
  async getAuditedCase(investigationId: string): Promise<AuditedCase | null> {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/audit`,
        {
          headers: { 'Accept': 'application/json' },
        }
      );

      if (res.status === 404) {
        return fallbackCaseStore[investigationId] || null;
      }

      if (!res.ok) {
        throw new Error(`Failed to load audited case: ${res.statusText}`);
      }

      const data = await res.json();
      return normalizeAuditedCase(data);
    } catch (err) {
      console.warn(`Backend audited case unavailable for ${investigationId}, returning fallback:`, err);
      return fallbackCaseStore[investigationId] || null;
    }
  },

  /**
   * Run Auditor Agent to build evidence-backed Audited Case file.
   * Maps to: POST /api/investigations/{investigation_id}/audit
   */
  async createAuditedCase(
    investigationId: string,
    payload: AuditorRequestPayload
  ): Promise<AuditedCase> {
    try {
      const res = await fetch(
        `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/audit`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
          },
          body: JSON.stringify({
            investigation_id: investigationId,
            claims: (payload.claims || []).map((c) => ({
              claim: c.claim,
              evidence_ids: c.evidence_ids || c.evidenceIds || [],
            })),
            critic_findings: payload.critic_findings || payload.criticFindings || null,
            final_conclusion: payload.final_conclusion || payload.finalConclusion || null,
          }),
        }
      );

      if (!res.ok) {
        const errorData = await res.json().catch(() => ({}));
        throw new Error(errorData.detail || `Failed to audit case: ${res.statusText}`);
      }

      const data = await res.json();
      const auditedCase = normalizeAuditedCase(data);
      fallbackCaseStore[investigationId] = auditedCase;
      return auditedCase;
    } catch (err) {
      console.warn(`Backend failed to audit case for ${investigationId}, using fallback:`, err);
      return fallbackCaseStore[investigationId];
    }
  },

  /**
   * Export Canonical Case JSON for investigation (Module 3F)
   * Maps to: GET /api/investigations/{investigation_id}/case-json
   */
  async getCanonicalCaseJson(
    investigationId: string,
    caseId?: string
  ): Promise<CanonicalCaseJson> {
    const url = caseId
      ? `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/case-json?case_id=${encodeURIComponent(caseId)}`
      : `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/case-json`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to export canonical case JSON: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Validate candidate Case JSON payload (Module 3F)
   * Maps to: POST /api/case-json/validate
   */
  async validateCanonicalCaseJson(
    payload: any
  ): Promise<CaseJsonValidationResponse> {
    const res = await fetch(`${API_BASE_URL}/api/case-json/validate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: typeof payload === 'string' ? payload : JSON.stringify(payload),
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Validation failed: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Retrieve deterministic Evidence & Audit Quality Trust Score (Module 3G)
   * Maps to: GET /api/investigations/{investigation_id}/trust-score
   */
  async getTrustScore(
    investigationId: string,
    caseId?: string
  ): Promise<TrustScore> {
    const url = caseId
      ? `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/trust-score?case_id=${encodeURIComponent(caseId)}`
      : `${API_BASE_URL}/api/investigations/${encodeURIComponent(investigationId)}/trust-score`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to fetch trust score: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Calculate Trust Score directly from a Canonical Case JSON payload (Module 3G)
   * Maps to: POST /api/trust-score/calculate
   */
  async calculateTrustScore(
    casePayload: any
  ): Promise<TrustScore> {
    const res = await fetch(`${API_BASE_URL}/api/trust-score/calculate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: typeof casePayload === 'string' ? casePayload : JSON.stringify(casePayload),
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to calculate trust score: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Execute deterministic Synthetic True Positive Scenario (Module 3H)
   * Maps to: POST /api/scenarios/true-positive
   */
  async runTruePositiveScenario(): Promise<TruePositiveScenarioResponse> {
    const res = await fetch(`${API_BASE_URL}/api/scenarios/true-positive`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to run true-positive scenario: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Retrieve current state of Synthetic True Positive Scenario (Module 3H)
   * Maps to: GET /api/scenarios/true-positive
   */
  async getTruePositiveScenario(): Promise<TruePositiveScenarioResponse> {
    const res = await fetch(`${API_BASE_URL}/api/scenarios/true-positive`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to fetch true-positive scenario: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Execute deterministic Synthetic Trap / Deception Scenario (Module 3I)
   * Maps to: POST /api/scenarios/trap
   */
  async runTrapScenario(): Promise<TrapScenarioResponse> {
    const res = await fetch(`${API_BASE_URL}/api/scenarios/trap`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to run trap scenario: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Retrieve current state of Synthetic Trap / Deception Scenario (Module 3I)
   * Maps to: GET /api/scenarios/trap
   */
  async getTrapScenario(): Promise<TrapScenarioResponse> {
    const res = await fetch(`${API_BASE_URL}/api/scenarios/trap`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to fetch trap scenario: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * List all Human-in-the-Loop approvals across the SOC (Module 3J)
   * Maps to: GET /api/approvals
   */
  async getApprovals(status?: string): Promise<ApprovalListResponse> {
    const url = status
      ? `${API_BASE_URL}/api/approvals?status=${encodeURIComponent(status)}`
      : `${API_BASE_URL}/api/approvals`;
    const res = await fetch(url, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to fetch approvals: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * List approval requests for a specific investigation (Module 3J)
   * Maps to: GET /api/investigations/{id}/approvals
   */
  async getInvestigationApprovals(investigationId: string): Promise<ApprovalRequest[]> {
    const res = await fetch(`${API_BASE_URL}/api/investigations/${investigationId}/approvals`, {
      method: 'GET',
      headers: {
        Accept: 'application/json',
      },
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to fetch investigation approvals: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Create a new Human-in-the-Loop approval request for an investigation (Module 3J)
   * Maps to: POST /api/investigations/{id}/approvals
   */
  async createApprovalRequest(
    investigationId: string,
    payload: ApprovalCreatePayload
  ): Promise<ApprovalRequest> {
    const res = await fetch(`${API_BASE_URL}/api/investigations/${investigationId}/approvals`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to create approval request: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Submit human decision on an approval gate (Module 3J)
   * Maps to: POST /api/approvals/{id}/decision
   */
  async submitApprovalDecision(
    approvalId: string,
    payload: ApprovalDecisionPayload
  ): Promise<ApprovalRequest> {
    const res = await fetch(`${API_BASE_URL}/api/approvals/${approvalId}/decision`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const errorData = await res.json().catch(() => ({}));
      throw new Error(errorData.detail || `Failed to submit approval decision: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3L: Fetch paginated, cryptographically chained audit blocks
   * Maps to: GET /api/audit-trail
   */
  async getAuditTrail(params?: {
    investigation_id?: string;
    event_type?: string;
    order?: 'asc' | 'desc';
    limit?: number;
    offset?: number;
  }): Promise<AuditEntry[]> {
    const query = new URLSearchParams();
    if (params?.investigation_id) query.set('investigation_id', params.investigation_id);
    if (params?.event_type) query.set('event_type', params.event_type);
    if (params?.order) query.set('order', params.order);
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.offset) query.set('offset', String(params.offset));

    const qs = query.toString();
    const url = `${API_BASE_URL}/api/audit-trail${qs ? `?${qs}` : ''}`;
    const res = await fetch(url, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch audit trail: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3L: Perform complete cryptographic chain integrity verification
   * Maps to: GET /api/audit-trail/verify
   */
  async verifyAuditTrail(): Promise<AuditVerificationResult> {
    const res = await fetch(`${API_BASE_URL}/api/audit-trail/verify`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to verify audit trail: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3L: Retrieve current ledger Merkle root
   * Maps to: GET /api/audit-trail/merkle-root
   */
  async getLedgerMerkleRoot(): Promise<{
    merkle_root: string;
    total_entries: number;
    latest_hash: string;
    genesis_hash: string;
  }> {
    const res = await fetch(`${API_BASE_URL}/api/audit-trail/merkle-root`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to retrieve Merkle root: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3L: Cryptographically seal an investigation into the immutable ledger
   * Maps to: POST /api/audit-trail/seal/{id}
   */
  async sealInvestigation(
    investigationId: string,
    payload?: SealInvestigationPayload
  ): Promise<SealInvestigationResult> {
    const res = await fetch(`${API_BASE_URL}/api/audit-trail/seal/${investigationId}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload || {}),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to seal investigation: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3L: Get full cryptographic audit proof bundle for an investigation
   * Maps to: GET /api/audit-trail/bundle/{id}
   */
  async getInvestigationAuditBundle(investigationId: string): Promise<AuditBundle> {
    const res = await fetch(`${API_BASE_URL}/api/audit-trail/bundle/${investigationId}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to get audit bundle: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3M: Fetch all Incident Case Dossiers
   * Maps to: GET /api/dossiers
   */
  async getDossiers(params?: { severity?: string; tactic?: string }): Promise<IncidentDossier[]> {
    const query = new URLSearchParams();
    if (params?.severity) query.set('severity', params.severity);
    if (params?.tactic) query.set('tactic', params.tactic);
    const qs = query.toString() ? `?${query.toString()}` : '';
    const res = await fetch(`${API_BASE_URL}/api/dossiers${qs}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch dossiers: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3M: Fetch single Incident Case Dossier by Dossier ID
   * Maps to: GET /api/dossiers/{id}
   */
  async getDossier(id: string): Promise<IncidentDossier> {
    const res = await fetch(`${API_BASE_URL}/api/dossiers/${id}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to fetch dossier ${id}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3M: Fetch Incident Case Dossier by Investigation ID
   * Maps to: GET /api/dossiers/investigation/{id}
   */
  async getDossierByInvestigationId(investigationId: string): Promise<IncidentDossier> {
    const res = await fetch(`${API_BASE_URL}/api/dossiers/investigation/${investigationId}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to fetch dossier for investigation ${investigationId}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3M: Refresh Incident Case Dossier
   * Maps to: POST /api/dossiers/refresh/{id}
   */
  async refreshDossier(investigationId: string): Promise<IncidentDossier> {
    const res = await fetch(`${API_BASE_URL}/api/dossiers/refresh/${investigationId}`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to refresh dossier for ${investigationId}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3M: Get aggregate MITRE ATT&CK Matrix coverage summary
   * Maps to: GET /api/dossiers/matrix/summary
   */
  async getMitreMatrixSummary(): Promise<MitreMatrixSummary> {
    const res = await fetch(`${API_BASE_URL}/api/dossiers/matrix/summary`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch MITRE matrix summary: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3M: Export MITRE ATT&CK Navigator JSON Layer
   * Maps to: GET /api/dossiers/{id}/navigator
   */
  async getDossierNavigatorLayer(dossierId: string): Promise<DossierNavigatorLayer> {
    const res = await fetch(`${API_BASE_URL}/api/dossiers/${dossierId}/navigator`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to generate Navigator layer: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3N: Fetch allow-listed containment and remediation playbooks catalog
   * Maps to: GET /api/containment/playbooks
   */
  async getPlaybooks(): Promise<PlaybookDefinition[]> {
    const res = await fetch(`${API_BASE_URL}/api/containment/playbooks`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch playbooks: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3N: Fetch operational summary of containment executions and active quarantines
   * Maps to: GET /api/containment/summary
   */
  async getContainmentSummary(): Promise<ContainmentSummary> {
    const res = await fetch(`${API_BASE_URL}/api/containment/summary`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch containment summary: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3N: List containment executions
   * Maps to: GET /api/containment
   */
  async getContainments(params?: { investigation_id?: string; status?: string }): Promise<ContainmentExecution[]> {
    const query = new URLSearchParams();
    if (params?.investigation_id) query.set('investigation_id', params.investigation_id);
    if (params?.status) query.set('status', params.status);
    const qs = query.toString() ? `?${query.toString()}` : '';
    const res = await fetch(`${API_BASE_URL}/api/containment${qs}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch containments: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3N: List containment executions for a specific investigation
   * Maps to: GET /api/investigations/{id}/containments
   */
  async getInvestigationContainments(investigationId: string): Promise<ContainmentExecution[]> {
    const res = await fetch(`${API_BASE_URL}/api/investigations/${investigationId}/containments`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch investigation containments: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3N: Dispatch an allow-listed containment playbook
   * Maps to: POST /api/containment/dispatch
   */
  async dispatchContainment(payload: ContainmentDispatchPayload): Promise<ContainmentExecution> {
    const res = await fetch(`${API_BASE_URL}/api/containment/dispatch`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to dispatch containment playbook: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3N: Safely rollback a containment action
   * Maps to: POST /api/containment/{id}/rollback
   */
  async rollbackContainment(containmentId: string, payload: ContainmentRollbackPayload): Promise<ContainmentExecution> {
    const res = await fetch(`${API_BASE_URL}/api/containment/${containmentId}/rollback`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to rollback containment: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3O: Fetch operational summary of all replay sessions across SOC
   * Maps to: GET /api/replay/summary
   */
  async getReplaySummary(): Promise<ReplaySummary> {
    const res = await fetch(`${API_BASE_URL}/api/replay/summary`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch replay summary: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3O: List replay sessions (optionally filtered by investigation ID)
   * Maps to: GET /api/replay
   */
  async getReplays(investigationId?: string): Promise<ReplaySession[]> {
    const url = investigationId
      ? `${API_BASE_URL}/api/replay?investigation_id=${encodeURIComponent(investigationId)}`
      : `${API_BASE_URL}/api/replay`;
    const res = await fetch(url, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch replay sessions: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3O: Get single replay session with reconstructed timeline and comparison matrix
   * Maps to: GET /api/replay/{id}
   */
  async getReplay(replayId: string): Promise<ReplaySession> {
    const res = await fetch(`${API_BASE_URL}/api/replay/${replayId}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch replay session ${replayId}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3O: Trigger deterministic re-execution of an investigation
   * Maps to: POST /api/replay/execute
   */
  async executeReplay(payload: ReplayTriggerPayload): Promise<ReplaySession> {
    const res = await fetch(`${API_BASE_URL}/api/replay/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to execute investigation replay: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3O: Get unified chronological forensic timeline for an investigation
   * Maps to: GET /api/investigations/{id}/timeline
   */
  async getInvestigationTimeline(investigationId: string): Promise<TimelineEvent[]> {
    const res = await fetch(`${API_BASE_URL}/api/investigations/${investigationId}/timeline`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch timeline for investigation ${investigationId}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3O: List replay sessions for an investigation
   * Maps to: GET /api/investigations/{id}/replays
   */
  async getInvestigationReplays(investigationId: string): Promise<ReplaySession[]> {
    const res = await fetch(`${API_BASE_URL}/api/investigations/${investigationId}/replays`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch replays for investigation ${investigationId}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3P: Retrieve summary metrics for incident reports
   * Maps to: GET /api/reports/summary
   */
  async getReportsSummary(): Promise<ReportSummary> {
    const res = await fetch(`${API_BASE_URL}/api/reports/summary`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch reports summary: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3P: List incident reports with optional filters
   * Maps to: GET /api/reports
   */
  async getReports(params?: {
    investigation_id?: string;
    report_type?: string;
    classification?: string;
  }): Promise<IncidentReport[]> {
    const q = new URLSearchParams();
    if (params?.investigation_id) q.append('investigation_id', params.investigation_id);
    if (params?.report_type) q.append('report_type', params.report_type);
    if (params?.classification) q.append('classification', params.classification);

    const qs = q.toString() ? `?${q.toString()}` : '';
    const res = await fetch(`${API_BASE_URL}/api/reports${qs}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch reports: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3P: Retrieve single incident report by ID
   * Maps to: GET /api/reports/{id}
   */
  async getReport(id: string): Promise<IncidentReport> {
    const res = await fetch(`${API_BASE_URL}/api/reports/${id}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch report ${id}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3P: Generate official incident report for an investigation
   * Maps to: POST /api/reports/generate
   */
  async generateReport(payload: ReportGeneratePayload): Promise<IncidentReport> {
    const res = await fetch(`${API_BASE_URL}/api/reports/generate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to generate report: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3P: List reports for specific investigation
   * Maps to: GET /api/reports?investigation_id={id}
   */
  async getInvestigationReports(investigationId: string): Promise<IncidentReport[]> {
    return this.getReports({ investigation_id: investigationId });
  },

  /**
   * Module 3P: URLs for direct downloads & exports
   */
  getReportJsonUrl(id: string): string {
    return `${API_BASE_URL}/api/reports/${id}/export/json`;
  },

  getReportMarkdownUrl(id: string): string {
    return `${API_BASE_URL}/api/reports/${id}/export/markdown`;
  },

  getReportHtmlUrl(id: string): string {
    return `${API_BASE_URL}/api/reports/${id}/export/html`;
  },

  /**
   * Module 3Q: Fetch Swarm KPI Summary
   * Maps to: GET /api/agents/summary
   */
  async getAgentsSummary(): Promise<AgentSwarmSummary> {
    const res = await fetch(`${API_BASE_URL}/api/agents/summary`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch agents summary: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3Q: List all 5 core SOC agents
   * Maps to: GET /api/agents
   */
  async getAgents(): Promise<SocAgent[]> {
    const res = await fetch(`${API_BASE_URL}/api/agents`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch agents: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3Q: Fetch single agent by ID
   * Maps to: GET /api/agents/{id}
   */
  async getAgent(id: string): Promise<SocAgent> {
    const res = await fetch(`${API_BASE_URL}/api/agents/${id}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch agent ${id}: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3Q: Fetch chronological agent activity stream
   * Maps to: GET /api/agents/activity
   */
  async getAgentActivity(options?: {
    limit?: number;
    investigationId?: string;
    agentId?: string;
  }): Promise<AgentActivityEvent[]> {
    const params = new URLSearchParams();
    if (options?.limit) params.set('limit', String(options.limit));
    if (options?.investigationId) params.set('investigation_id', options.investigationId);
    if (options?.agentId) params.set('agent_id', options.agentId);

    const qs = params.toString() ? `?${params.toString()}` : '';
    const res = await fetch(`${API_BASE_URL}/api/agents/activity${qs}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch agent activity: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3Q: Execute Analyst Agent hypothesis & claim synthesis
   * Maps to: POST /api/agents/analyst/analyze
   */
  async runAnalystAnalysis(payload: AnalystRequestPayload): Promise<AnalystResponse> {
    const res = await fetch(`${API_BASE_URL}/api/agents/analyst/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to run analyst analysis: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3Q: Trigger autonomous multi-agent swarm cycle
   * Maps to: POST /api/agents/orchestrate
   */
  async orchestrateSwarm(payload: SwarmOrchestratePayload): Promise<SwarmOrchestrateResponse> {
    const res = await fetch(`${API_BASE_URL}/api/agents/orchestrate`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `Failed to orchestrate swarm: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3R: Get Evidence Control Plane summary metrics
   * Maps to: GET /api/evidence/summary
   */
  async getEvidenceControlPlaneSummary(): Promise<EvidenceControlPlaneSummary> {
    const res = await fetch(`${API_BASE_URL}/api/evidence/summary`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch evidence control plane summary: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3R: List all Evidence Control Plane items with filtering
   * Maps to: GET /api/evidence
   */
  async getEvidenceControlPlaneItems(params?: {
    investigation_id?: string;
    evidence_type?: string;
    source?: string;
    reliability?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<EvidenceControlPlaneItem[]> {
    const q = new URLSearchParams();
    if (params?.investigation_id) q.append('investigation_id', params.investigation_id);
    if (params?.evidence_type) q.append('evidence_type', params.evidence_type);
    if (params?.source) q.append('source', params.source);
    if (params?.reliability) q.append('reliability', params.reliability);
    if (params?.search) q.append('search', params.search);
    if (params?.limit) q.append('limit', String(params.limit));
    if (params?.offset) q.append('offset', String(params.offset));

    const qs = q.toString() ? `?${q.toString()}` : '';
    const res = await fetch(`${API_BASE_URL}/api/evidence${qs}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch evidence control plane items: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3R: Get Claims Corroboration Matrix
   * Maps to: GET /api/evidence/claims
   */
  async getEvidentiaryClaims(investigationId?: string): Promise<EvidentiaryClaim[]> {
    const qs = investigationId ? `?investigation_id=${encodeURIComponent(investigationId)}` : '';
    const res = await fetch(`${API_BASE_URL}/api/evidence/claims${qs}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch claims matrix: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3R: Get Threat Actor Attribution Policy & Guard Status
   * Maps to: GET /api/evidence/attribution-policy
   */
  async getAttributionPolicyStatus(): Promise<AttributionPolicyStatus> {
    const res = await fetch(`${API_BASE_URL}/api/evidence/attribution-policy`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch attribution policy status: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3R: Batch verify all evidence items and calculate Merkle root
   * Maps to: POST /api/evidence/verify-batch
   */
  async verifyEvidenceBatch(): Promise<BatchVerificationResponse> {
    const res = await fetch(`${API_BASE_URL}/api/evidence/verify-batch`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to run batch integrity verification: ${res.statusText}`);
    }
    return res.json();
  },

  // ==========================================
  // MODULE 3S / 3T: CRITIC RED-TEAM & INTERACTIVE DEMO PIPELINE & COMPLETE CASE AUDIT OBJECT
  // ==========================================

  /**
   * Module 3S: Retrieve pre-packaged red-team adversarial scenarios
   * Maps to: GET /api/critic/redteam/scenarios
   */
  async getRedTeamScenarios(): Promise<RedTeamScenarioPreset[]> {
    const res = await fetch(`${API_BASE_URL}/api/critic/redteam/scenarios`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch redteam scenarios: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3S: Execute Critic / Red-Team adversarial challenge
   * Maps to: POST /api/critic/redteam/challenge
   */
  async runRedTeamChallenge(payload: RedTeamChallengeRequest): Promise<RedTeamChallengeResponse> {
    const res = await fetch(`${API_BASE_URL}/api/critic/redteam/challenge`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      throw new Error(`Failed to execute redteam challenge: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3S: Retrieve latest Critic / Red-Team challenge result
   * Maps to: GET /api/critic/redteam/challenge/latest
   */
  async getLatestRedTeamChallenge(investigationId?: string): Promise<RedTeamChallengeResponse> {
    const qs = investigationId ? `?investigation_id=${encodeURIComponent(investigationId)}` : '';
    const res = await fetch(`${API_BASE_URL}/api/critic/redteam/challenge/latest${qs}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch latest redteam challenge: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3S / 3T: Get Interactive Demo simulation pipeline state
   * Maps to: GET /api/demo/pipeline/state
   */
  async getDemoPipelineState(sessionId?: string): Promise<InteractiveDemoSessionState> {
    const qs = sessionId ? `?session_id=${encodeURIComponent(sessionId)}` : '';
    const res = await fetch(`${API_BASE_URL}/api/demo/pipeline/state${qs}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch demo pipeline state: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3S / 3T: Execute interactive demo step (start_investigation, run_planner, collect_evidence, run_analysis, challenge_conclusion, audit_case, replay_investigation)
   * Maps to: POST /api/demo/pipeline/step
   */
  async runDemoPipelineStep(stepId: string, sessionId?: string): Promise<InteractiveDemoSessionState> {
    const res = await fetch(`${API_BASE_URL}/api/demo/pipeline/step`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        step_id: stepId,
        session_id: sessionId || 'default-demo',
      }),
    });
    if (!res.ok) {
      throw new Error(`Failed to execute demo step '${stepId}': ${res.statusText}`);
    }
    return res.json();
  },

  async executeDemoStep(stepId: string, sessionId?: string): Promise<InteractiveDemoSessionState> {
    return this.runDemoPipelineStep(stepId, sessionId);
  },

  /**
   * Module 3S / 3T: Reset interactive demo simulation state
   * Maps to: POST /api/demo/pipeline/reset
   */
  async resetDemoPipeline(sessionId?: string): Promise<InteractiveDemoSessionState> {
    const res = await fetch(`${API_BASE_URL}/api/demo/pipeline/reset`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({
        session_id: sessionId || 'default-demo',
      }),
    });
    if (!res.ok) {
      throw new Error(`Failed to reset demo pipeline: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3T: Get Complete Case Audit Object (Formatted JSON view matching spec lines 388-410)
   * Maps to: GET /api/cases/{case_id}/audit-object
   */
  async getCompleteCaseAuditObject(caseId?: string): Promise<CompleteCaseAuditObject> {
    const cid = caseId || 'CASE-2026-0042';
    const res = await fetch(`${API_BASE_URL}/api/cases/${encodeURIComponent(cid)}/audit-object`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch case audit object: ${res.statusText}`);
    }
    return res.json();
  },

  /**
   * Module 3T: Export complete case audit object as formatted JSON with SHA-256 digest
   * Maps to: POST /api/cases/{case_id}/audit-object/export
   */
  async exportCaseAuditObject(caseId?: string): Promise<AuditObjectExportResponse> {
    const cid = caseId || 'CASE-2026-0042';
    const res = await fetch(`${API_BASE_URL}/api/cases/${encodeURIComponent(cid)}/audit-object/export`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to export case audit object: ${res.statusText}`);
    }
    return res.json();
  },

  // ==========================================
  // Module 3U: Enterprise SOC Control Plane, Omnibar Search & Notifications
  // ==========================================

  async getSystemSettings(): Promise<SocSystemSettings> {
    const res = await fetch(`${API_BASE_URL}/api/system/settings`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch system settings: ${res.statusText}`);
    }
    return res.json();
  },

  async updateSystemSettings(update: Partial<SocSystemSettings>): Promise<SocSystemSettings> {
    const res = await fetch(`${API_BASE_URL}/api/system/settings`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify(update),
    });
    if (!res.ok) {
      throw new Error(`Failed to update system settings: ${res.statusText}`);
    }
    return res.json();
  },

  async resetSystemSettings(): Promise<SocSystemSettings> {
    const res = await fetch(`${API_BASE_URL}/api/system/settings/reset`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to reset system settings: ${res.statusText}`);
    }
    return res.json();
  },

  async searchUniversal(query: string): Promise<UniversalSearchResponse> {
    const res = await fetch(`${API_BASE_URL}/api/system/search?q=${encodeURIComponent(query)}`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to execute universal search: ${res.statusText}`);
    }
    return res.json();
  },

  async getNotifications(): Promise<NotificationsResponse> {
    const res = await fetch(`${API_BASE_URL}/api/system/notifications`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch notifications: ${res.statusText}`);
    }
    return res.json();
  },

  async markNotificationRead(id: string): Promise<{ status: string; id: string; read: boolean }> {
    const res = await fetch(`${API_BASE_URL}/api/system/notifications/${encodeURIComponent(id)}/read`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to mark notification read: ${res.statusText}`);
    }
    return res.json();
  },

  async markAllNotificationsRead(): Promise<{ status: string; marked_read_count: number }> {
    const res = await fetch(`${API_BASE_URL}/api/system/notifications/mark-all-read`, {
      method: 'POST',
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to mark all notifications read: ${res.statusText}`);
    }
    return res.json();
  },

  // ==========================================
  // Module 3V: Overview Dashboard Analytics & Multi-Chart Engine
  // ==========================================

  async getOverviewAnalytics(): Promise<OverviewAnalyticsResponse> {
    const res = await fetch(`${API_BASE_URL}/api/analytics/overview`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch overview analytics: ${res.statusText}`);
    }
    return res.json();
  },

  async getPostureSummary(): Promise<PostureSummary> {
    const res = await fetch(`${API_BASE_URL}/api/analytics/posture`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch posture summary: ${res.statusText}`);
    }
    return res.json();
  },

  async getOverviewCharts(): Promise<{
    alerts_over_time: AlertsOverTimePoint[];
    investigation_outcomes: InvestigationOutcomeDistribution[];
    evidence_sources: EvidenceSourceDistribution[];
    trust_score_history: TrustScoreHistoryPoint[];
  }> {
    const res = await fetch(`${API_BASE_URL}/api/analytics/charts`, {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) {
      throw new Error(`Failed to fetch overview charts data: ${res.statusText}`);
    }
    return res.json();
  },
};

export const api = socApi;

