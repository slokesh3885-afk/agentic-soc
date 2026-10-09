"""
Trust Score Schema (Module 3G)
Agentic SOC — Auditable AI Security Operations Center

Defines strict Pydantic schemas for the deterministic Evidence & Audit Quality Trust Score:
- TrustScore: Overall score container (0-100)
- ScoreComponent: Positive scoring component breakdown
- Penalty: Negative deduction penalty breakdown
- ScoreExplanation: Formula documentation, tier verdict, and qualitative summary
"""

from typing import List, Optional, Any, Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator


VerdictType = Literal["HIGH_TRUST", "MODERATE_TRUST", "LOW_TRUST", "UNTRUSTED"]


class ScoreComponent(BaseModel):
    """
    An individual positive scoring component measuring evidence/audit quality.
    """
    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., description="Name of the scoring component")
    value: float = Field(..., description="Normalized metric value (0.0 to 1.0 or ratio)")
    weight: float = Field(..., description="Maximum possible points for this component")
    contribution: float = Field(..., description="Actual points contributed to final score")
    explanation: str = Field(..., description="Human-readable explanation of this factor")

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        return data


class Penalty(BaseModel):
    """
    An individual deduction penalty for evidence gaps, contradictions, or integrity failures.
    """
    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., description="Name of the penalty")
    value: int = Field(..., ge=0, description="Count of occurrences triggering penalty")
    rate_per_unit: float = Field(..., ge=0.0, description="Points deducted per unit")
    deduction: float = Field(..., ge=0.0, description="Total points deducted (positive value)")
    explanation: str = Field(..., description="Human-readable explanation of the deduction")

    # CamelCase convenience alias
    ratePerUnit: Optional[float] = None

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "rate_per_unit" not in data and "ratePerUnit" in data:
                data["rate_per_unit"] = data["ratePerUnit"]
        return data

    @model_validator(mode="after")
    def populate_camel_case(self) -> "Penalty":
        self.ratePerUnit = self.rate_per_unit
        return self


class ScoreExplanation(BaseModel):
    """
    Summary, verdict classification, and documented formula for the Trust Score.
    """
    model_config = ConfigDict(extra="ignore")

    summary: str = Field(..., min_length=1, description="Executive quality summary")
    formula: str = Field(..., min_length=1, description="Exact mathematical formula used")
    verdict: VerdictType = Field(..., description="Quality tier: HIGH_TRUST | MODERATE_TRUST | LOW_TRUST | UNTRUSTED")
    key_findings: List[str] = Field(default_factory=list, description="Key strengths and weaknesses identified")

    # CamelCase convenience alias
    keyFindings: Optional[List[str]] = None

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "key_findings" not in data and "keyFindings" in data:
                data["key_findings"] = data["keyFindings"]
        return data

    @model_validator(mode="after")
    def populate_camel_case(self) -> "ScoreExplanation":
        self.keyFindings = self.key_findings
        return self


class TrustScore(BaseModel):
    """
    Deterministic Evidence & Audit Quality Trust Score (Module 3G).
    Measures the quality, auditability, and evidentiary backing of an audited investigation.
    Strictly bounded between 0.0 and 100.0.
    """
    model_config = ConfigDict(extra="ignore")

    case_id: str = Field(..., description="Associated Audited Case ID (e.g. CASE-001)")
    investigation_id: str = Field(..., description="Associated Investigation ID (e.g. INV-012)")
    trust_score: float = Field(..., ge=0.0, le=100.0, description="Overall Evidence Quality Score (0-100)")
    score_components: List[ScoreComponent] = Field(..., description="Breakdown of positive scoring factors")
    penalties: List[Penalty] = Field(default_factory=list, description="Breakdown of negative deduction penalties")
    explanation: ScoreExplanation = Field(..., description="Mathematical formula, verdict, and narrative rationale")
    calculated_at: str = Field(..., description="Timestamp of score calculation")

    # CamelCase convenience aliases for React frontend
    caseId: Optional[str] = None
    investigationId: Optional[str] = None
    trustScore: Optional[float] = None
    scoreComponents: Optional[List[ScoreComponent]] = None
    calculatedAt: Optional[str] = None

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "case_id" not in data and "caseId" in data:
                data["case_id"] = data["caseId"]
            if "investigation_id" not in data and "investigationId" in data:
                data["investigation_id"] = data["investigationId"]
            if "trust_score" not in data and "trustScore" in data:
                data["trust_score"] = data["trustScore"]
            if "score_components" not in data and "scoreComponents" in data:
                data["score_components"] = data["scoreComponents"]
            if "calculated_at" not in data and "calculatedAt" in data:
                data["calculated_at"] = data["calculatedAt"]
        return data

    @model_validator(mode="after")
    def populate_camel_case(self) -> "TrustScore":
        self.caseId = self.case_id
        self.investigationId = self.investigation_id
        self.trustScore = self.trust_score
        self.scoreComponents = self.score_components
        self.calculatedAt = self.calculated_at
        return self
