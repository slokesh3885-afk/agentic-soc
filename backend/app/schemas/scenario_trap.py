"""
Trap Scenario Schema (Module 3I)
Agentic SOC — Auditable AI Security Operations Center

Defines schemas for the deterministic Trap / Deception demonstration scenario:
- TrapScenarioResponse: Complete end-to-end pipeline output demonstrating detection of
  contradictory and misleading evidence rather than blindly accepting agent conclusions.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.canonical_case import CanonicalCaseJson
from app.schemas.trust_score import TrustScore
from app.schemas.auditor import AuditedCaseResponse
from app.schemas.critic import CriticResponse
from app.schemas.plan import InvestigationPlanResponse
from app.schemas.evidence import EvidenceResponse


class TrapScenarioResponse(BaseModel):
    """
    Deterministic Synthetic Trap / Deception Scenario (Module 3I).
    Demonstrates that the multi-agent SOC pipeline detects misleading, contradictory,
    or deceptive evidence and rejects unsupported conclusions rather than blindly
    approving them.
    This is a demonstration test scenario; NOT a real incident.
    """
    model_config = ConfigDict(extra="ignore")

    scenario_id: str = Field(default="SCENARIO-TRAP", description="Unique Scenario Identifier")
    scenario_name: str = Field(default="Synthetic Trap / Deception Demonstration", description="Scenario descriptive name")
    is_synthetic: bool = Field(default=True, description="Explicit flag indicating synthetic demonstration data")
    status: str = Field(default="TRAP_DETECTED_CONTRADICTION", description="Final scenario verification status")
    investigation_id: str = Field(..., description="Bound Investigation ID (e.g. INV-TRAP-001)")
    target_host: str = Field(..., description="Synthetic target host (e.g. TEST-SRV-FIN-02.corp.test)")
    alert_name: str = Field(..., description="Alert headline triggering investigation")
    deceptive_evidence_id: str = Field(default="E-TRAP-DECEPTIVE", description="ID of deceptive/contradictory evidence item")
    deceptive_evidence_summary: str = Field(..., description="Explanation of deceptive/contradictory signal")
    evidence_count: int = Field(..., ge=0, description="Count of synthetic evidence items")
    contradicted_claims_count: int = Field(..., ge=0, description="Count of claims invalidated by evidence contradictions")
    unsupported_claims_count: int = Field(..., ge=0, description="Count of ungrounded or overclaimed statements")
    supported_claims_count: int = Field(..., ge=0, description="Count of corroborated claims")
    evidence_items: List[EvidenceResponse] = Field(..., description="Synthetic evidence items with SHA-256 hashes")
    planner: InvestigationPlanResponse = Field(..., description="Planner Agent proposed steps")
    critic: CriticResponse = Field(..., description="Critic Agent red-team review challenging draft claims")
    audited_case: AuditedCaseResponse = Field(..., description="Auditor Agent verified case with contradiction resolution")
    case_json: CanonicalCaseJson = Field(..., description="Canonical Case JSON (Module 3F)")
    trust_score: TrustScore = Field(..., description="Evidence & Audit Quality Trust Score with contradiction deductions")
    explanation: str = Field(..., description="Executive narrative explanation of trap detection and resolution")
    executed_at: str = Field(..., description="Timestamp of scenario pipeline execution")

    # Frontend camelCase aliases
    scenarioId: Optional[str] = None
    scenarioName: Optional[str] = None
    isSynthetic: Optional[bool] = None
    investigationId: Optional[str] = None
    targetHost: Optional[str] = None
    alertName: Optional[str] = None
    deceptiveEvidenceId: Optional[str] = None
    deceptiveEvidenceSummary: Optional[str] = None
    evidenceCount: Optional[int] = None
    contradictedClaimsCount: Optional[int] = None
    unsupportedClaimsCount: Optional[int] = None
    supportedClaimsCount: Optional[int] = None
    evidenceItems: Optional[List[EvidenceResponse]] = None
    auditedCase: Optional[AuditedCaseResponse] = None
    caseJson: Optional[CanonicalCaseJson] = None
    trustScore: Optional[TrustScore] = None
    executedAt: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "scenario_id" not in data and "scenarioId" in data:
                data["scenario_id"] = data["scenarioId"]
            if "investigation_id" not in data and "investigationId" in data:
                data["investigation_id"] = data["investigationId"]
            if "target_host" not in data and "targetHost" in data:
                data["target_host"] = data["targetHost"]
            if "alert_name" not in data and "alertName" in data:
                data["alert_name"] = data["alertName"]
            if "deceptive_evidence_id" not in data and "deceptiveEvidenceId" in data:
                data["deceptive_evidence_id"] = data["deceptiveEvidenceId"]
            if "deceptive_evidence_summary" not in data and "deceptiveEvidenceSummary" in data:
                data["deceptive_evidence_summary"] = data["deceptiveEvidenceSummary"]
            if "evidence_count" not in data and "evidenceCount" in data:
                data["evidence_count"] = data["evidenceCount"]
            if "contradicted_claims_count" not in data and "contradictedClaimsCount" in data:
                data["contradicted_claims_count"] = data["contradictedClaimsCount"]
            if "unsupported_claims_count" not in data and "unsupportedClaimsCount" in data:
                data["unsupported_claims_count"] = data["unsupportedClaimsCount"]
            if "supported_claims_count" not in data and "supportedClaimsCount" in data:
                data["supported_claims_count"] = data["supportedClaimsCount"]
            if "evidence_items" not in data and "evidenceItems" in data:
                data["evidence_items"] = data["evidenceItems"]
            if "audited_case" not in data and "auditedCase" in data:
                data["audited_case"] = data["auditedCase"]
            if "case_json" not in data and "caseJson" in data:
                data["case_json"] = data["caseJson"]
            if "trust_score" not in data and "trustScore" in data:
                data["trust_score"] = data["trustScore"]
        return data

    @model_validator(mode="after")
    def populate_camel_case(self) -> "TrapScenarioResponse":
        self.scenarioId = self.scenario_id
        self.scenarioName = self.scenario_name
        self.isSynthetic = self.is_synthetic
        self.investigationId = self.investigation_id
        self.targetHost = self.target_host
        self.alertName = self.alert_name
        self.deceptiveEvidenceId = self.deceptive_evidence_id
        self.deceptiveEvidenceSummary = self.deceptive_evidence_summary
        self.evidenceCount = self.evidence_count
        self.contradictedClaimsCount = self.contradicted_claims_count
        self.unsupportedClaimsCount = self.unsupported_claims_count
        self.supportedClaimsCount = self.supported_claims_count
        self.evidenceItems = self.evidence_items
        self.auditedCase = self.audited_case
        self.caseJson = self.case_json
        self.trustScore = self.trust_score
        self.executedAt = self.executed_at
        return self
