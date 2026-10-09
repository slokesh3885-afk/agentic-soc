"""
Scenario Schema (Module 3H)
Agentic SOC — Auditable AI Security Operations Center

Defines schemas for deterministic, synthetic demonstration scenarios:
- TruePositiveScenarioResponse: Complete end-to-end pipeline output for synthetic true positive testing.
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.schemas.canonical_case import CanonicalCaseJson
from app.schemas.trust_score import TrustScore
from app.schemas.auditor import AuditedCaseResponse
from app.schemas.critic import CriticResponse
from app.schemas.plan import InvestigationPlanResponse
from app.schemas.evidence import EvidenceResponse


class TruePositiveScenarioResponse(BaseModel):
    """
    Deterministic Synthetic True Positive Scenario (Module 3H).
    Demonstrates full-pipeline validation where all evidence items consistently
    corroborate malicious activity, with zero unsupported attribution.
    This is a demonstration test scenario; NOT a real incident.
    """
    model_config = ConfigDict(extra="ignore")

    scenario_id: str = Field(default="SCENARIO-TRUE-POSITIVE", description="Unique Scenario Identifier")
    scenario_name: str = Field(default="Synthetic True Positive Demonstration", description="Scenario descriptive name")
    is_synthetic: bool = Field(default=True, description="Explicit flag indicating synthetic demonstration data")
    status: str = Field(default="VERIFIED_TRUE_POSITIVE", description="Final scenario verification status")
    investigation_id: str = Field(..., description="Bound Investigation ID (e.g. INV-TP-001)")
    target_host: str = Field(..., description="Synthetic target host (e.g. TEST-SRV-APP-01.corp.test)")
    alert_name: str = Field(..., description="Alert headline triggering investigation")
    evidence_count: int = Field(..., ge=0, description="Count of synthetic evidence items")
    supported_claims_count: int = Field(..., ge=0, description="Count of corroborated claims")
    evidence_items: List[EvidenceResponse] = Field(..., description="Synthetic evidence items with SHA-256 hashes")
    planner: InvestigationPlanResponse = Field(..., description="Planner Agent proposed steps")
    critic: CriticResponse = Field(..., description="Critic Agent red-team review")
    audited_case: AuditedCaseResponse = Field(..., description="Auditor Agent verified case")
    case_json: CanonicalCaseJson = Field(..., description="Canonical Case JSON (Module 3F)")
    trust_score: TrustScore = Field(..., description="Deterministic Evidence Trust Score (Module 3G)")
    explanation: str = Field(..., description="Executive narrative explanation of scenario findings")
    executed_at: str = Field(..., description="Timestamp of scenario pipeline execution")

    # Frontend camelCase aliases
    scenarioId: Optional[str] = None
    scenarioName: Optional[str] = None
    isSynthetic: Optional[bool] = None
    investigationId: Optional[str] = None
    targetHost: Optional[str] = None
    alertName: Optional[str] = None
    evidenceCount: Optional[int] = None
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
            if "evidence_count" not in data and "evidenceCount" in data:
                data["evidence_count"] = data["evidenceCount"]
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
    def populate_camel_case(self) -> "TruePositiveScenarioResponse":
        self.scenarioId = self.scenario_id
        self.scenarioName = self.scenario_name
        self.isSynthetic = self.is_synthetic
        self.investigationId = self.investigation_id
        self.targetHost = self.target_host
        self.alertName = self.alert_name
        self.evidenceCount = self.evidence_count
        self.supportedClaimsCount = self.supported_claims_count
        self.evidenceItems = self.evidence_items
        self.auditedCase = self.audited_case
        self.caseJson = self.case_json
        self.trustScore = self.trust_score
        self.executedAt = self.executed_at
        return self
