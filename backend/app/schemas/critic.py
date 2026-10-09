from enum import Enum
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, ConfigDict, Field, model_validator


class ClaimStatus(str, Enum):
    """Controlled statuses for claim-by-claim evaluation."""
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    CONTRADICTED = "CONTRADICTED"
    UNCERTAIN = "UNCERTAIN"
    INVALID_EVIDENCE_REFERENCE = "INVALID_EVIDENCE_REFERENCE"


class OverallCriticStatus(str, Enum):
    """High-level decision status of the Critic / Red-Team agent."""
    PASS = "PASS"
    REQUIRES_REVISION = "REQUIRES_REVISION"


class ClaimInput(BaseModel):
    """Single claim submitted as part of investigator draft conclusion."""
    claim: str = Field(..., min_length=1, description="Claim statement made by investigator")
    evidence_ids: List[str] = Field(default_factory=list, description="Referenced evidence IDs")

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "evidence_ids" not in data and "evidenceIds" in data:
                data["evidence_ids"] = data["evidenceIds"]
        return data


class CriticRequest(BaseModel):
    """Payload sent to Critic agent to challenge an investigator draft conclusion."""
    investigation_id: Optional[str] = Field(default=None, description="Target investigation ID")
    draft_conclusion: str = Field(..., min_length=1, description="Draft conclusion text to critique")
    claims: List[ClaimInput] = Field(default_factory=list, description="Granular claims to evaluate against evidence")

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "draft_conclusion" not in data and "draftConclusion" in data:
                data["draft_conclusion"] = data["draftConclusion"]
            if "investigation_id" not in data and "investigationId" in data:
                data["investigation_id"] = data["investigationId"]
        return data


class ClaimEvaluation(BaseModel):
    """Detailed evaluation of a single claim."""
    claim: str
    status: str  # Supported, Unsupported, Contradicted, Uncertain, Invalid_Evidence_Reference
    reason: str
    evidence_ids: List[str] = Field(default_factory=list)
    valid_evidence_ids: List[str] = Field(default_factory=list)
    invalid_evidence_ids: List[str] = Field(default_factory=list)

    # CamelCase aliases for frontend
    evidenceIds: Optional[List[str]] = None
    validEvidenceIds: Optional[List[str]] = None
    invalidEvidenceIds: Optional[List[str]] = None

    @model_validator(mode="after")
    def populate_camel_case(self) -> "ClaimEvaluation":
        self.evidenceIds = self.evidence_ids
        self.validEvidenceIds = self.valid_evidence_ids
        self.invalidEvidenceIds = self.invalid_evidence_ids
        return self


class CriticObjection(BaseModel):
    """Specific objection raised by Critic agent."""
    claim: str
    status: str
    reason: str
    evidence_ids: List[str] = Field(default_factory=list)
    category: Optional[str] = None  # e.g. "UNSUPPORTED_ATTRIBUTION", "MISSING_EVIDENCE", "CONTRADICTION", "OVERCONFIDENT_LANGUAGE", "INVALID_EVIDENCE"

    evidenceIds: Optional[List[str]] = None

    @model_validator(mode="after")
    def populate_camel_case(self) -> "CriticObjection":
        self.evidenceIds = self.evidence_ids
        return self


class CriticResponse(BaseModel):
    """Structured response from the Critic / Red-Team agent."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    investigation_id: str
    overall_status: str  # PASS or REQUIRES_REVISION
    draft_conclusion: str
    claims_evaluation: List[ClaimEvaluation] = Field(default_factory=list)
    objections: List[CriticObjection] = Field(default_factory=list)
    missing_evidence: List[str] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)
    overclaims: List[str] = Field(default_factory=list)
    created_at: str

    # Frontend camelCase convenience aliases
    investigationId: Optional[str] = None
    overallStatus: Optional[str] = None
    draftConclusion: Optional[str] = None
    claimsEvaluation: Optional[List[ClaimEvaluation]] = None
    missingEvidence: Optional[List[str]] = None
    createdAt: Optional[str] = None

    @model_validator(mode="after")
    def populate_camel_case(self) -> "CriticResponse":
        self.investigationId = self.investigation_id
        self.overallStatus = self.overall_status
        self.draftConclusion = self.draft_conclusion
        self.claimsEvaluation = self.claims_evaluation
        self.missingEvidence = self.missing_evidence
        self.createdAt = self.created_at
        return self
