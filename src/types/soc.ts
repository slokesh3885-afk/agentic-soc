export type SeverityLevel = 'Critical' | 'High' | 'Medium' | 'Low';

export type InvestigationStatus = 'Investigating' | 'Awaiting Review' | 'Completed' | 'Inconclusive';

export type AlertStatus = 'Open' | 'Triaged' | 'Escalated' | 'Resolved' | 'Suppressed';

export type EvidenceType =
  | 'SIEM_LOG'
  | 'EDR_EVENT'
  | 'HASH_LOOKUP'
  | 'SANDBOX_RESULT'
  | 'WHOIS_RESULT'
  | 'YARA_RESULT'
  | 'DNS_EVENT'
  | 'PROCESS_EVENT'
  | 'FILE_EVENT'
  | 'OTHER';

export interface EvidenceItem {
  id: string; // e.g. "E-001"
  investigationId: string; // e.g. "INV-012"
  investigation_id?: string;
  evidenceType: string;
  evidence_type?: string;
  source: string;
  timestamp: string;
  query?: string;
  rawOutput: string;
  raw_output?: string;
  contentHash: string; // SHA-256 hex digest
  content_hash?: string;
  status: string;
  createdAt: string;
  created_at?: string;
  integrityVerified?: boolean;
}

export interface EvidenceIntegrityResult {
  evidenceId: string;
  evidence_id?: string;
  valid: boolean;
  contentHash: string;
  content_hash?: string;
  recalculatedHash: string;
  recalculated_hash?: string;
  timestampVerified: string;
  timestamp_verified?: string;
}

export interface NewEvidencePayload {
  evidenceType: string;
  source: string;
  rawOutput: string;
  query?: string;
  timestamp?: string;
  status?: string;
}

export interface AllowlistedTool {
  tool_name: string;
  description: string;
  evidence_type: string;
  enabled: boolean;
  input_schema: Record<string, any>;
  output_schema: Record<string, any>;
}

export interface ToolExecution {
  id: string; // e.g. "EXEC-001"
  investigationId: string;
  investigation_id?: string;
  toolName: string;
  tool_name?: string;
  input: any;
  output: any;
  timestamp: string;
  success: boolean;
  evidenceId?: string | null;
  evidence_id?: string | null;
  error?: string | null;
}

export interface ToolExecuteResult {
  tool_name: string;
  success: boolean;
  timestamp: string;
  data?: any;
  evidence_id?: string;
  error?: string | null;
}

export interface PlanStep {
  step: number;
  action: string;
  tool_name: string;
  toolName?: string;
  reason: string;
  status: string; // "PROPOSED"
}

export interface InvestigationPlan {
  investigation_id: string;
  investigationId?: string;
  alert: string;
  plan: PlanStep[];
  planner_status: string;
  plannerStatus?: string;
  created_at: string;
  createdAt?: string;
}

export interface Investigation {
  id: string;
  alert: string;
  host: string;
  severity: SeverityLevel;
  status: InvestigationStatus;
  evidenceTrustScore: number; // Percentage 0 - 100
  started: string;
  eventTimestamp: string; // Event timestamp
  createdTimestamp: string; // Created timestamp
  startedAtTimestamp?: string;
  description?: string;
  assignedAgent?: string;
  evidenceCount: number; // Evidence count
  artifactCount?: number; // Kept for backward compatibility
  evidenceCorroboration?: {
    source: string;
    score: number;
    corroborated: boolean;
  }[];
  mitreTechnique?: string;
}

export interface SecurityAlert {
  id: string;
  severity: SeverityLevel;
  name: string;
  host: string;
  timestamp: string;
  status: AlertStatus;
  source: string;
  category: string;
  rawEventSnippet?: string;
}

export interface DashboardKpi {
  activeInvestigations: number;
  openAlerts: number;
  confirmedThreats: number;
  inconclusiveCases: number;
  averageTrustScore: number;
  // Trend comparisons
  investigationsDelta?: string;
  alertsDelta?: string;
  threatsDelta?: string;
  inconclusiveDelta?: string;
  trustScoreDelta?: string;
}

export interface ThreatOverviewPoint {
  time: string;
  alerts: number;
  confirmedThreats: number;
  inconclusive: number;
}

export interface EvidenceTrustMetric {
  investigationId: string;
  alertTitle: string;
  score: number;
  host: string;
  verifiedArtifactsCount: number;
  totalArtifactsCount: number;
  primaryCorroborator: string;
  status: InvestigationStatus;
}

export interface NewInvestigationPayload {
  alertName: string;
  host: string;
  timestamp: string;
  description: string;
  severity?: SeverityLevel;
}

// ==========================================
// MODULE 3D: CRITIC / RED-TEAM AGENT SCHEMAS
// ==========================================

export type ClaimStatus =
  | 'SUPPORTED'
  | 'UNSUPPORTED'
  | 'CONTRADICTED'
  | 'UNCERTAIN'
  | 'INVALID_EVIDENCE_REFERENCE';

export type OverallCriticStatus = 'PASS' | 'REQUIRES_REVISION';

export interface ClaimInput {
  claim: string;
  evidence_ids?: string[];
  evidenceIds?: string[];
}

export interface ClaimEvaluation {
  claim: string;
  status: ClaimStatus;
  reason: string;
  evidence_ids?: string[];
  evidenceIds?: string[];
  valid_evidence_ids?: string[];
  validEvidenceIds?: string[];
  invalid_evidence_ids?: string[];
  invalidEvidenceIds?: string[];
}

export interface CriticObjection {
  claim: string;
  status: string;
  reason: string;
  evidence_ids?: string[];
  evidenceIds?: string[];
  category?: string;
}

export interface CriticReview {
  id?: string;
  investigation_id: string;
  investigationId?: string;
  overall_status: OverallCriticStatus;
  overallStatus?: OverallCriticStatus;
  draft_conclusion: string;
  draftConclusion?: string;
  claims_evaluation: ClaimEvaluation[];
  claimsEvaluation?: ClaimEvaluation[];
  objections: CriticObjection[];
  missing_evidence: string[];
  missingEvidence?: string[];
  contradictions: string[];
  overclaims: string[];
  created_at: string;
  createdAt?: string;
}

export interface CriticRequestPayload {
  investigation_id?: string;
  investigationId?: string;
  draft_conclusion: string;
  draftConclusion?: string;
  claims: ClaimInput[];
}

// ==========================================
// MODULE 3E: AUDITOR AGENT SCHEMAS
// ==========================================

export interface AuditedClaimItem {
  claim: string;
  evidence_ids: string[];
  evidenceIds?: string[];
  status: 'SUPPORTED' | 'UNSUPPORTED' | 'CONTRADICTED' | 'UNCERTAIN' | string;
  confidence: string;
  reason: string;
  evidence_integrity_verified: boolean;
  evidenceIntegrityVerified?: boolean;
}

export interface AuditedToolExecutionItem {
  id: string;
  tool_name: string;
  toolName?: string;
  input: any;
  output: any;
  timestamp: string;
  success: boolean;
  evidence_id?: string | null;
  evidenceId?: string | null;
}

export interface AuditedCase {
  case_id: string;
  caseId?: string;
  investigation_id: string;
  investigationId?: string;
  claims: AuditedClaimItem[];
  contradictions: string[];
  uncertainties: string[];
  unsupported_claims: string[];
  unsupportedClaims?: string[];
  tool_executions: AuditedToolExecutionItem[];
  toolExecutions?: AuditedToolExecutionItem[];
  final_conclusion: string;
  finalConclusion?: string;
  audit_verified: boolean;
  auditVerified?: boolean;
  created_at: string;
  createdAt?: string;
}

export interface AuditorRequestPayload {
  investigation_id?: string;
  investigationId?: string;
  claims: ClaimInput[];
  critic_findings?: any[];
  criticFindings?: any[];
  final_conclusion?: string;
  finalConclusion?: string;
}

// ==========================================
// MODULE 3F: CANONICAL CASE JSON SCHEMAS
// ==========================================

export type CanonicalClaimStatus = 'SUPPORTED' | 'UNSUPPORTED' | 'CONTRADICTED' | 'UNCERTAIN';
export type CanonicalAuditStatus = 'AUDIT_VERIFIED' | 'REJECTED';
export type CanonicalIntegrityStatus = 'VALID' | 'FAILED';

export interface CanonicalClaim {
  claim: string;
  evidence_ids: string[];
  evidenceIds?: string[];
  status: CanonicalClaimStatus;
  confidence: CanonicalClaimStatus;
  reason: string;
  evidence_integrity_verified: boolean;
  evidenceIntegrityVerified?: boolean;
}

export interface CanonicalEvidenceItem {
  evidence_id: string;
  evidenceId?: string;
  evidence_type: string;
  evidenceType?: string;
  source: string;
  raw_output: string;
  rawOutput?: string;
  content_hash: string;
  contentHash?: string;
  integrity_status: CanonicalIntegrityStatus;
  integrityStatus?: CanonicalIntegrityStatus;
  timestamp: string;
}

export interface CanonicalToolExecution {
  execution_id: string;
  executionId?: string;
  tool_name: string;
  toolName?: string;
  input: any;
  output: any;
  success: boolean;
  timestamp: string;
  evidence_id?: string | null;
  evidenceId?: string | null;
}

export interface CanonicalAuditBlock {
  audit_status: CanonicalAuditStatus;
  auditStatus?: CanonicalAuditStatus;
  auditor_verified: boolean;
  auditorVerified?: boolean;
  critic_reviewed: boolean;
  criticReviewed?: boolean;
  critic_objections_count: number;
  criticObjectionsCount?: number;
  audited_at: string;
  auditedAt?: string;
}

export interface CanonicalCaseJson {
  case_id: string;
  caseId?: string;
  investigation_id: string;
  investigationId?: string;
  schema_version: string;
  schemaVersion?: string;
  claims: CanonicalClaim[];
  evidence: Record<string, CanonicalEvidenceItem> | CanonicalEvidenceItem[];
  tool_executions: CanonicalToolExecution[];
  toolExecutions?: CanonicalToolExecution[];
  contradictions: string[];
  uncertainties: string[];
  unsupported_claims: string[];
  unsupportedClaims?: string[];
  final_conclusion: string;
  finalConclusion?: string;
  audit: CanonicalAuditBlock;
}

export interface CaseJsonValidationResponse {
  valid: boolean;
  case_id: string;
  investigation_id: string;
  schema_version: string;
  claims_count: number;
  evidence_count: number;
  audit_status: string;
  message: string;
  errors?: string[];
}

// ==========================================
// MODULE 3G: DETERMINISTIC TRUST SCORE SCHEMAS
// ==========================================

export type TrustVerdict = 'HIGH_TRUST' | 'MODERATE_TRUST' | 'LOW_TRUST' | 'UNTRUSTED';

export interface ScoreComponent {
  name: string;
  value: number;
  weight: number;
  contribution: number;
  explanation: string;
}

export interface Penalty {
  name: string;
  value: number;
  rate_per_unit: number;
  ratePerUnit?: number;
  deduction: number;
  explanation: string;
}

export interface ScoreExplanation {
  summary: string;
  formula: string;
  verdict: TrustVerdict;
  key_findings: string[];
  keyFindings?: string[];
}

export interface TrustScore {
  case_id: string;
  caseId?: string;
  investigation_id: string;
  investigationId?: string;
  trust_score: number;
  trustScore?: number;
  score_components: ScoreComponent[];
  scoreComponents?: ScoreComponent[];
  penalties: Penalty[];
  explanation: ScoreExplanation;
  calculated_at: string;
  calculatedAt?: string;
}

// ==========================================
// MODULE 3H: SYNTHETIC TRUE POSITIVE SCENARIO
// ==========================================

export interface TruePositiveScenarioResponse {
  scenario_id: string;
  scenarioId?: string;
  scenario_name: string;
  scenarioName?: string;
  is_synthetic: boolean;
  isSynthetic?: boolean;
  status: string;
  investigation_id: string;
  investigationId?: string;
  target_host: string;
  targetHost?: string;
  alert_name: string;
  alertName?: string;
  evidence_count: number;
  evidenceCount?: number;
  supported_claims_count: number;
  supportedClaimsCount?: number;
  evidence_items: EvidenceItem[];
  evidenceItems?: EvidenceItem[];
  planner: InvestigationPlan;
  critic: CriticReview;
  audited_case: AuditedCase;
  auditedCase?: AuditedCase;
  case_json: CanonicalCaseJson;
  caseJson?: CanonicalCaseJson;
  trust_score: TrustScore;
  trustScore?: TrustScore;
  explanation: string;
  executed_at: string;
  executedAt?: string;
}

// ==========================================
// MODULE 3I: SYNTHETIC TRAP / DECEPTION SCENARIO
// ==========================================

export interface TrapScenarioResponse {
  scenario_id: string;
  scenarioId?: string;
  scenario_name: string;
  scenarioName?: string;
  is_synthetic: boolean;
  isSynthetic?: boolean;
  status: string;
  investigation_id: string;
  investigationId?: string;
  target_host: string;
  targetHost?: string;
  alert_name: string;
  alertName?: string;
  deceptive_evidence_id: string;
  deceptiveEvidenceId?: string;
  deceptive_evidence_summary: string;
  deceptiveEvidenceSummary?: string;
  evidence_count: number;
  evidenceCount?: number;
  contradicted_claims_count: number;
  contradictedClaimsCount?: number;
  unsupported_claims_count: number;
  unsupportedClaimsCount?: number;
  supported_claims_count: number;
  supportedClaimsCount?: number;
  evidence_items: EvidenceItem[];
  evidenceItems?: EvidenceItem[];
  planner: InvestigationPlan;
  critic: CriticReview;
  audited_case: AuditedCase;
  auditedCase?: AuditedCase;
  case_json: CanonicalCaseJson;
  caseJson?: CanonicalCaseJson;
  trust_score: TrustScore;
  trustScore?: TrustScore;
  explanation: string;
  executed_at: string;
  executedAt?: string;
}

// ==========================================
// MODULE 3J: HUMAN-IN-THE-LOOP APPROVAL SCHEMAS
// ==========================================

export type ApprovalActionType =
  | 'CASE_CLOSURE'
  | 'CONTAINMENT_ISOLATE_HOST'
  | 'CONTAINMENT_BLOCK_IP'
  | 'REMEDIAL_ACTION'
  | 'ESCALATION_TIER2';

export type ApprovalStatus = 'PENDING' | 'APPROVED' | 'REJECTED' | 'CANCELLED';

export type ApprovalRiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface ApprovalRequest {
  id: string;
  investigation_id: string;
  investigationId?: string;
  case_id?: string | null;
  caseId?: string | null;
  action_type: ApprovalActionType;
  actionType?: ApprovalActionType;
  recommended_action: string;
  recommendedAction?: string;
  risk_level: ApprovalRiskLevel;
  riskLevel?: ApprovalRiskLevel;
  trust_score: number;
  trustScore?: number;
  trust_verdict: string;
  trustVerdict?: string;
  status: ApprovalStatus;
  requested_by: string;
  requestedBy?: string;
  requested_at: string;
  requestedAt?: string;
  reviewer?: string | null;
  decision_notes?: string | null;
  decisionNotes?: string | null;
  decision_at?: string | null;
  decisionAt?: string | null;
  requires_override: boolean;
  requiresOverride?: boolean;
  override_justification?: string | null;
  overrideJustification?: string | null;
}

export interface ApprovalCreatePayload {
  action_type: ApprovalActionType;
  recommended_action: string;
  risk_level?: ApprovalRiskLevel;
  requested_by?: string;
  case_id?: string;
}

export interface ApprovalDecisionPayload {
  decision: 'APPROVED' | 'REJECTED' | 'CANCELLED';
  reviewer: string;
  decision_notes: string;
  override_justification?: string;
}

export interface ApprovalListResponse {
  total: number;
  pending_count: number;
  pendingCount?: number;
  approvals: ApprovalRequest[];
}

// ==========================================
// Module 3K: WebSockets & Live Telemetry
// ==========================================
export type WebSocketConnectionStatus = 'connecting' | 'connected' | 'disconnected' | 'error';

export interface WebSocketEventMessage<T = any> {
  event: string;
  investigation_id?: string | null;
  channel?: string;
  timestamp: string;
  data?: T;
  message?: string;
}

export interface WebSocketStatusResponse {
  total_active_connections: number;
  channels: Record<string, number>;
  total_broadcast_count: number;
  status: string;
}

// ==========================================
// Module 3L: Cryptographic Immutable Audit Trail
// ==========================================
export type AuditEventType =
  | 'GENESIS_BLOCK'
  | 'EVIDENCE_SEALED'
  | 'TOOL_INVOCATION'
  | 'PLAN_APPROVED'
  | 'CRITIC_ASSESSMENT'
  | 'CASE_AUDITED'
  | 'HUMAN_APPROVAL'
  | 'HUMAN_OVERRIDE'
  | 'CONTAINMENT_DISPATCHED'
  | 'INVESTIGATION_SEALED';

export interface AuditEntry {
  id: string;
  sequence: number;
  timestamp: string;
  event_type: AuditEventType | string;
  investigation_id?: string | null;
  actor: string;
  payload_summary: string;
  payload_hash: string;
  prev_hash: string;
  entry_hash: string;
  signature: string;
  metadata_json?: string;
}

export interface AuditVerificationResult {
  chain_valid: boolean;
  total_entries: number;
  genesis_hash: string;
  latest_hash: string;
  merkle_root: string;
  corrupted_entry_id?: string | null;
  verification_timestamp: string;
  details: string;
}

export interface SealInvestigationPayload {
  investigation_id: string;
  signed_by?: string;
  notes?: string;
}

export interface SealInvestigationResult {
  audit_id: string;
  investigation_id: string;
  sequence: number;
  merkle_root: string;
  entry_hash: string;
  signature: string;
  timestamp: string;
  evidence_count: number;
  status: string;
}

export interface AuditBundle {
  investigation_id: string;
  sealed: boolean;
  seal_audit_id?: string | null;
  merkle_root?: string | null;
  entry_hash?: string | null;
  signature?: string | null;
  timestamp?: string | null;
  evidence_hashes: Array<{ id: string; hash: string; type: string }>;
  case_id?: string | null;
  case_hash?: string | null;
  approval_hashes: Array<{ id: string; action_type: string; status: string }>;
  chain_verified: boolean;
}
// ==========================================
// Module 3M: Incident Cases Dossier & MITRE ATT&CK Matrix Mapping
// ==========================================

export interface MitreTechniqueMapping {
  technique_id: string;
  technique_name: string;
  tactic: string;
  tactic_id: string;
  confidence: number;
  evidence_ids: string[];
  description: string;
  url: string;
}

export interface ForensicCustodyEvent {
  sequence: number;
  timestamp: string;
  action: string;
  actor: string;
  source: string;
  artifact_hash: string;
  verified: boolean;
  notes: string;
}

export interface IncidentDossier {
  id: string;
  investigation_id: string;
  title: string;
  severity: SeverityLevel | string;
  status: string;
  threat_actor_attribution?: string | null;
  primary_tactic: string;
  mitre_techniques: MitreTechniqueMapping[];
  custody_chain: ForensicCustodyEvent[];
  summary: string;
  recommendations: string[];
  created_at: string;
  updated_at: string;
}

export interface MitreTacticCoverage {
  tactic_id: string;
  tactic_name: string;
  technique_count: number;
  techniques: string[];
}

export interface MitreMatrixSummary {
  matrix_version: string;
  total_dossiers: number;
  total_techniques_mapped: number;
  tactics_breakdown: Record<string, number>;
  top_techniques: Array<{
    technique_id: string;
    technique_name: string;
    tactic: string;
    count: number;
  }>;
  coverage: MitreTacticCoverage[];
}

export interface DossierNavigatorTechnique {
  techniqueID: string;
  tactic: string;
  score: number;
  color: string;
  comment: string;
  enabled: boolean;
}

export interface DossierNavigatorLayer {
  name: string;
  versions: {
    attack: string;
    navigator: string;
    layer: string;
  };
  domain: string;
  description: string;
  techniques: DossierNavigatorTechnique[];
  gradient: {
    colors: string[];
    minValue: number;
    maxValue: number;
  };
}

// ==========================================
// Module 3N: Automated Containment & Remediation Playbooks
// ==========================================

export interface ContainmentStep {
  step_number: number;
  action: string;
  target: string;
  status: string;
  details: string;
  timestamp: string;
  artifact_hash: string;
}

export interface ContainmentExecution {
  id: string;
  investigation_id: string;
  approval_id?: string | null;
  playbook_id: string;
  playbook_name: string;
  target_type: string;
  target_identifier: string;
  status: 'CONTAINED' | 'EXECUTING' | 'FAILED' | 'ROLLED_BACK' | string;
  execution_steps: ContainmentStep[];
  dispatched_by: string;
  dispatched_at: string;
  completed_at?: string | null;
  rollback_enabled: boolean;
  rolled_back_at?: string | null;
  rollback_notes?: string | null;
  audit_entry_id?: string | null;
  quarantine_receipt_hash: string;
}

export interface PlaybookDefinition {
  id: string;
  name: string;
  target_type: string;
  description: string;
  steps: string[];
  safety_level: string;
  reversible: boolean;
}

export interface ContainmentDispatchPayload {
  investigation_id: string;
  playbook_id: string;
  target_identifier: string;
  approval_id?: string | null;
  dispatched_by?: string;
  notes?: string;
}

export interface ContainmentRollbackPayload {
  rolled_back_by: string;
  reason: string;
}

export interface ContainmentSummary {
  total_containments: number;
  active_quarantines: number;
  rolled_back_count: number;
  by_target_type: Record<string, number>;
  by_playbook: Record<string, number>;
}

// ==========================================
// Module 3O: Forensic Timeline Replay & Reproducibility Engine
// ==========================================

export interface TimelineEvent {
  step_index: number;
  event_type: string;
  title: string;
  description: string;
  timestamp: string;
  actor: string;
  metadata?: Record<string, any>;
  artifact_ref?: string | null;
  state_snapshot?: {
    step: number;
    cumulative_evidence_count: number;
    cumulative_tool_executions: number;
    investigation_status: string;
    evidence_trust_score: number;
  } | null;
}

export interface ReplayComparisonMatrix {
  verdict_match: boolean;
  original_verdict: string;
  replayed_verdict: string;
  trust_score_delta: number;
  original_trust_score: number;
  replayed_trust_score: number;
  claims_match_rate: number;
  evidence_integrity_verified: boolean;
  divergence_count: number;
  divergence_notes: string[];
}

export interface ReplaySession {
  id: string;
  investigation_id: string;
  status: 'COMPLETED' | 'RUNNING' | 'FAILED' | string;
  original_verdict: string;
  replayed_verdict: string;
  verdict_match: boolean;
  consistency_score: number;
  claims_match_rate: number;
  original_trust_score: number;
  replayed_trust_score: number;
  evidence_snapshot_hash: string;
  total_steps: number;
  replay_duration_ms: number;
  executed_at: string;
  replayed_by: string;
  audit_entry_id?: string | null;
  comparison: ReplayComparisonMatrix;
  timeline: TimelineEvent[];
}

export interface ReplayTriggerPayload {
  investigation_id: string;
  notes?: string;
  strict_verification?: boolean;
}

export interface ReplaySummary {
  total_replays: number;
  average_consistency: number;
  perfect_replays_count: number;
  divergent_replays_count: number;
  investigations_replayed: number;
  by_verdict: Record<string, number>;
}

// ==========================================
// Module 3P: Executive Security Incident Reporting & Regulatory Compliance Engine
// ==========================================

export interface ComplianceControl {
  framework: string;
  control_id: string;
  control_name: string;
  status: 'COMPLIANT' | 'WARNING' | 'NOT_APPLICABLE' | string;
  description: string;
  evidence_refs: string[];
}

export interface ComplianceFrameworkReport {
  framework_name: string;
  adherence_score: number;
  status: string;
  controls: ComplianceControl[];
}

export interface IncidentReport {
  id: string;
  investigation_id: string;
  title: string;
  report_type: 'EXECUTIVE' | 'TECHNICAL' | 'REGULATORY_COMPLIANCE' | 'FORENSIC' | string;
  classification: 'CONFIDENTIAL' | 'RESTRICTED' | 'INTERNAL' | 'PUBLIC' | string;
  verdict: string;
  trust_score: number;
  compliance_score: number;
  executive_summary: string;
  claims: Array<{
    claim_id: string;
    statement: string;
    status: string;
    evidence_ids: string[];
    confidence?: number;
    rejection_reason?: string;
  }>;
  evidence: Array<{
    id: string;
    evidence_type: string;
    source: string;
    timestamp: string;
    content_hash?: string;
    status?: string;
  }>;
  contradictions: Array<{
    issue: string;
    detail: string;
  }>;
  critic_findings: Array<{
    aspect: string;
    finding: string;
  }>;
  threat_attribution: {
    status: string;
    actor: string;
    confidence: number;
    policy_rule?: string;
    policy_note?: string;
    evidence_count?: number;
  };
  uncertainties: string[];
  mitre_tactics: Array<any>;
  containment_actions: Array<{
    id: string;
    playbook_id: string;
    target: string;
    status: string;
    quarantine_receipt_hash?: string;
  }>;
  approval_status: Record<string, any>;
  compliance_mappings: Record<string, ComplianceFrameworkReport>;
  timeline_summary: Array<any>;
  case_json_payload: Record<string, any>;
  markdown_content: string;
  html_content: string;
  report_hash: string;
  audit_entry_id?: string | null;
  created_at: string;
  author: string;
  status: string;
}

export interface ReportGeneratePayload {
  investigation_id: string;
  report_type?: string;
  classification?: string;
  notes?: string;
  author?: string;
}

export interface ReportSummary {
  total_reports: number;
  published_count: number;
  average_trust_score: number;
  average_compliance_score: number;
  by_report_type: Record<string, number>;
  by_classification: Record<string, number>;
  by_verdict: Record<string, number>;
}



// ==========================================
// MODULE 3Q: Autonomous Multi-Agent Swarm Orchestration & Live Control Plane
// ==========================================

export type AgentOperationalStatus = 'IDLE' | 'RUNNING' | 'COMPLETED' | 'DEGRADED';

export interface SocAgent {
  id: string;
  name: string;
  role: string;
  status: AgentOperationalStatus;
  current_task: string;
  currentTask?: string;
  execution_time_ms: number;
  executionTimeMs?: number;
  actions_count: number;
  actionsCount?: number;
  evidence_generated: number;
  evidenceGenerated?: number;
  capabilities: string[];
  last_active_at: string;
  lastActiveAt?: string;
  created_at: string;
}

export interface AgentActivityEvent {
  id: string;
  investigation_id?: string | null;
  investigationId?: string | null;
  agent_id: string;
  agentId?: string;
  agent_name: string;
  agentName?: string;
  action: string;
  details: string;
  evidence_ids: string[];
  evidenceIds?: string[];
  timestamp: string;
  full_datetime: string;
  fullDatetime?: string;
}

export interface AgentSwarmSummary {
  total_agents: number;
  totalAgents?: number;
  active_agents: number;
  activeAgents?: number;
  idle_agents: number;
  idleAgents?: number;
  completed_agents: number;
  completedAgents?: number;
  total_actions: number;
  totalActions?: number;
  total_evidence_generated: number;
  totalEvidenceGenerated?: number;
  swarm_status: string;
  swarmStatus?: string;
  average_execution_time_ms: number;
  averageExecutionTimeMs?: number;
}

export interface AnalystClaim {
  claim_id: string;
  statement: string;
  supporting_evidence_ids: string[];
  confidence: number;
  threat_attribution_hypothesis?: string | null;
  mitre_tactics: string[];
}

export interface AnalystRequestPayload {
  investigation_id: string;
  analyst_notes?: string;
  include_threat_intel?: boolean;
}

export interface AnalystResponse {
  investigation_id: string;
  preliminary_hypothesis: string;
  claims: AnalystClaim[];
  overall_confidence: number;
  evidence_analyzed_count: number;
  recommended_next_action: string;
  created_at: string;
}

export interface SwarmOrchestratePayload {
  investigation_id: string;
  auto_contain?: boolean;
}

export interface SwarmOrchestrateResponse {
  investigation_id: string;
  cycle_id: string;
  status: string;
  stages_executed: string[];
  planner_steps_count: number;
  tool_executions_count: number;
  analyst_claims_count: number;
  critic_objections_count: number;
  auditor_status: string;
  total_duration_ms: number;
  timestamp: string;
}

// ==========================================
// MODULE 3R: EVIDENCE CONTROL PLANE & CLAIMS CORROBORATION
// ==========================================

export interface EvidenceControlPlaneItem {
  id: string;
  investigation_id: string;
  investigationId?: string;
  evidence_type: string;
  evidenceType?: string;
  source: string;
  timestamp: string;
  tool: string;
  result: string;
  raw_output: string;
  rawOutput?: string;
  content_hash: string;
  contentHash?: string;
  reliability: string;
  status: string;
  used_by_claims: string[];
  usedByClaims?: string[];
  created_at: string;
  createdAt?: string;
}

export interface EvidenceControlPlaneSummary {
  total_evidence_items: number;
  verified_integrity_count: number;
  corroborated_claims_count: number;
  unsupported_claims_count: number;
  attribution_blocked_count: number;
  average_reliability_score: number;
  sources_breakdown: Record<string, number>;
  types_breakdown: Record<string, number>;
}

export interface EvidentiaryClaim {
  claim_id: string;
  investigation_id: string;
  claim_text: string;
  supported_by: string[];
  confidence: string; // HIGH, MEDIUM, LOW, NONE
  status: string; // SUPPORTED, UNSUPPORTED, BLOCKED
  reason?: string | null;
  is_threat_actor_attribution: boolean;
  created_at: string;
}

export interface AttributionPolicyStatus {
  policy_name: string;
  policy_rule: string;
  attribution_status: string;
  evidence_status: string;
  action: string;
  required_evidence_sources_count: number;
  current_sources_count: number;
  blocked_claims: EvidentiaryClaim[];
  policy_enforced: boolean;
}

export interface BatchVerificationResponse {
  total_verified: number;
  all_valid: boolean;
  corrupted_count: number;
  merkle_root: string;
  verified_at: string;
  details: string;
}

// ==========================================
// MODULE 3S / 3T: CRITIC & RED-TEAM ADVERSARIAL & INTERACTIVE DEMO PIPELINE & COMPLETE CASE AUDIT OBJECT
// ==========================================

export interface CriticAdversarialFinding {
  finding_id: string;
  category: string;
  finding_text: string;
  supporting_evidence_ids: string[];
  contradicts_preliminary: boolean;
  status: string;
  counter_argument: string;
}

export interface ContradictionAnalysis {
  contradiction_id: string;
  evidence_a_id: string;
  evidence_a_summary: string;
  evidence_b_id: string;
  evidence_b_summary: string;
  conflict_type: string;
  impact_assessment: string;
  resolution: string;
}

export interface AttributionGuardEvaluation {
  policy_name: string;
  policy_rule: string;
  asserted_threat_actor?: string | null;
  attribution_status: string;
  evidence_sufficiency: string;
  action: string;
  reason: string;
}

export interface RedTeamChallengeRequest {
  investigation_id?: string;
  scenario_id?: string;
  preliminary_conclusion?: string;
  attacker_hypothesis?: string;
  asserted_threat_actor?: string;
  evidence_ids?: string[];
}

export interface RedTeamChallengeResponse {
  challenge_id: string;
  investigation_id: string;
  preliminary_conclusion: string;
  attacker_hypothesis: string;
  critic_findings: CriticAdversarialFinding[];
  contradictions: ContradictionAnalysis[];
  attribution_guard: AttributionGuardEvaluation;
  final_critic_decision: string;
  verdict_category: string;
  original_trust_score: number;
  revised_trust_score: number;
  tamper_proof_signature: string;
  timestamp: string;
}

export interface RedTeamScenarioPreset {
  scenario_id: string;
  title: string;
  description: string;
  preliminary_conclusion: string;
  attacker_hypothesis: string;
  asserted_threat_actor?: string | null;
  expected_verdict: string;
}

export interface InteractiveDemoStep {
  step_id: string;
  step_name: string;
  step_number: number;
  agent_id: string;
  agent_name: string;
  status: string;
  action_summary: string;
  telemetry_logs: string[];
  evidence_ids: string[];
  trust_score: number;
  claims_count: number;
  current_conclusion: string;
  timestamp: string;
}

export interface InteractiveDemoSessionState {
  session_id: string;
  case_id: string;
  current_step_id: string;
  current_step_number: number;
  is_complete: boolean;
  completed_steps: InteractiveDemoStep[];
  available_steps: string[];
  cumulative_evidence: string[];
  latest_telemetry: string[];
  current_trust_score: number;
  current_verdict: string;
}

export interface CompleteCaseAuditObject {
  case_id: string;
  alert: Record<string, any>;
  investigation_plan: Record<string, any>[];
  claims: Record<string, any>[];
  evidence: Record<string, any>[];
  tool_executions: Record<string, any>[];
  contradictions: Record<string, any>[];
  critic_findings: Record<string, any>[];
  uncertainties: Record<string, any>[];
  recommended_actions: Record<string, any>[];
  human_approval_required: Record<string, any>[];
  threat_actor_attribution: Record<string, any>;
  trust_score: number;
  final_conclusion: string;
  tamper_proof_seal?: string | null;
  timestamp: string;
}

export interface AuditObjectExportResponse {
  case_id: string;
  filename: string;
  content: string;
  sha256_hash: string;
  exported_at: string;
}

// ==========================================
// Module 3U: Enterprise SOC Control Plane, Search & Notifications
// ==========================================

export interface TrustScoreWeights {
  evidence_coverage: number;
  evidence_quality: number;
  contradiction_handling: number;
  attribution_support: number;
  replay_consistency: number;
}

export interface SocSystemSettings {
  platform_name: string;
  tagline: string;
  environment: string;
  backend_version: string;
  database_type: string;
  database_path: string;
  tool_registry_enforcement: boolean;
  max_tool_execution_timeout_sec: number;
  allowlisted_tools_count: number;
  attribution_policy_strictness: string;
  min_attribution_evidence_count: number;
  trust_score_weights: TrustScoreWeights;
  websocket_telemetry_active: boolean;
  merkle_sealing_enabled: boolean;
  updated_at: string;
}

export interface SearchResultItem {
  id: string;
  category: string;
  title: string;
  description: string;
  severity_or_status?: string | null;
  timestamp?: string | null;
  route: string;
}

export interface UniversalSearchResponse {
  query: string;
  total_matches: number;
  categories: Record<string, number>;
  results: SearchResultItem[];
  searched_at: string;
}

export interface SocNotificationItem {
  id: string;
  title: string;
  message: string;
  severity: 'critical' | 'warning' | 'info' | 'success';
  timestamp: string;
  read: boolean;
  category: string;
  reference_id?: string | null;
}

export interface NotificationsResponse {
  total_notifications: number;
  unread_count: number;
  notifications: SocNotificationItem[];
}

// ==========================================
// Module 3V: Overview Dashboard Analytics & Multi-Chart Engine
// ==========================================

export interface AlertsOverTimePoint {
  timestamp: string;
  alerts: number;
  confirmed_threats: number;
  inconclusive: number;
}

export interface InvestigationOutcomeDistribution {
  outcome: string;
  count: number;
  percentage: number;
  color: string;
}

export interface EvidenceSourceDistribution {
  source_type: string;
  count: number;
  percentage: number;
  reliability_avg: number;
}

export interface TrustScoreHistoryPoint {
  case_id: string;
  label: string;
  trust_score: number;
  coverage_score: number;
  quality_score: number;
  benchmark_target: number;
}

export interface PostureSummary {
  posture_status: 'SECURE' | 'ELEVATED' | 'HIGH_RISK' | 'UNDER_ATTACK';
  posture_score: number;
  active_investigations: number;
  high_severity_cases: number;
  evidence_collected: number;
  cases_awaiting_approval: number;
  average_trust_score: number;
  evidence_coverage_pct: number;
  audit_integrity_status: string;
  active_threats_blocked: number;
  philosophy: string;
  updated_at: string;
}

export interface OverviewAnalyticsResponse {
  posture: PostureSummary;
  alerts_over_time: AlertsOverTimePoint[];
  investigation_outcomes: InvestigationOutcomeDistribution[];
  evidence_sources: EvidenceSourceDistribution[];
  trust_score_history: TrustScoreHistoryPoint[];
  generated_at: string;
}



