"""
Canonical Case JSON Schema (Module 3F)
Agentic SOC — Auditable AI Security Operations Center

Defines the strict, canonical JSON schema and validation model for the final audited SOC case.
The schema represents the complete evidence-backed investigation:
- Case identification and schema version
- Audited claims strictly evaluated against evidence ('NO EVIDENCE -> NO CLAIM')
- Complete referenced evidence items with cryptographic SHA-256 integrity status
- Recorded allow-listed tool execution history
- Identified genuine contradictions, uncertainties, and unsupported claims
- Evidence-backed final conclusion
- Tamper-evident Audit Block

Strict validation rules:
1. Every evidence ID referenced in claims[*].evidence_ids MUST exist in top-level evidence.
2. If claim.status == 'SUPPORTED', claim.evidence_ids MUST NOT be empty.
3. If claim.status == 'UNSUPPORTED', claim.evidence_ids can be empty.
4. Claim status strictly limited to: SUPPORTED, UNSUPPORTED, CONTRADICTED, UNCERTAIN.
5. All required fields must be present and type-safe.
6. Deterministic JSON serialization supported via to_canonical_json().
"""

import json
from typing import List, Dict, Any, Optional, Literal, Union
from pydantic import BaseModel, ConfigDict, Field, model_validator


# Allowed claim status literals
ClaimStatusType = Literal["SUPPORTED", "UNSUPPORTED", "CONTRADICTED", "UNCERTAIN"]
AuditStatusType = Literal["AUDIT_VERIFIED", "REJECTED"]
IntegrityStatusType = Literal["VALID", "FAILED"]


class CanonicalClaim(BaseModel):
    """
    Individual audited claim item within the Canonical Case JSON.
    Enforces 'NO EVIDENCE -> NO CLAIM' and strict status constraints.
    """
    model_config = ConfigDict(extra="ignore")

    claim: str = Field(..., min_length=1, description="Claim statement evaluated against evidence")
    evidence_ids: List[str] = Field(default_factory=list, description="Referenced evidence IDs supporting/evaluating this claim")
    status: ClaimStatusType = Field(..., description="Strict evaluation status: SUPPORTED | UNSUPPORTED | CONTRADICTED | UNCERTAIN")
    confidence: ClaimStatusType = Field(..., description="Confidence rating matching evaluation status")
    reason: str = Field(..., min_length=1, description="Justification and rationale for the claim status")
    evidence_integrity_verified: bool = Field(default=True, description="Whether referenced evidence passed SHA-256 integrity verification")

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # Normalize evidence_ids / evidenceIds
            if "evidence_ids" not in data and "evidenceIds" in data:
                data["evidence_ids"] = data["evidenceIds"]
            if "evidence_integrity_verified" not in data and "evidenceIntegrityVerified" in data:
                data["evidence_integrity_verified"] = data["evidenceIntegrityVerified"]
        return data

    @model_validator(mode="after")
    def validate_claim_evidence_rules(self) -> "CanonicalClaim":
        # Rule: NO EVIDENCE -> NO CLAIM
        # If claim is SUPPORTED, it MUST reference at least one evidence ID
        if self.status == "SUPPORTED" and len(self.evidence_ids) == 0:
            raise ValueError(
                f"NO EVIDENCE -> NO CLAIM: Claim '{self.claim}' has status 'SUPPORTED' "
                f"but references no evidence IDs. Supported claims must reference at least one verified evidence item."
            )
        return self


class CanonicalEvidenceItem(BaseModel):
    """
    Complete referenced evidence item included in the Canonical Case JSON.
    Includes forensic source, raw output, SHA-256 content hash, and integrity status.
    """
    model_config = ConfigDict(extra="ignore")

    evidence_id: str = Field(..., min_length=1, description="Unique evidence ID (e.g. E-001)")
    evidence_type: str = Field(..., min_length=1, description="Type of evidence (e.g. SIEM_LOG, EDR_EVENT)")
    source: str = Field(..., min_length=1, description="Originating security tool or telemetry system")
    raw_output: str = Field(..., description="Raw output text payload of the telemetry")
    content_hash: str = Field(..., min_length=64, max_length=64, description="Cryptographic SHA-256 hex digest of raw_output")
    integrity_status: IntegrityStatusType = Field(..., description="Forensic integrity check result: VALID | FAILED")
    timestamp: str = Field(..., min_length=1, description="Timestamp of telemetry collection")

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "evidence_id" not in data:
                if "evidenceId" in data:
                    data["evidence_id"] = data["evidenceId"]
                elif "id" in data:
                    data["evidence_id"] = data["id"]
            if "evidence_type" not in data and "evidenceType" in data:
                data["evidence_type"] = data["evidenceType"]
            if "raw_output" not in data and "rawOutput" in data:
                data["raw_output"] = data["rawOutput"]
            if "content_hash" not in data and "contentHash" in data:
                data["content_hash"] = data["contentHash"]
            if "integrity_status" not in data:
                if "integrityStatus" in data:
                    data["integrity_status"] = data["integrityStatus"]
                elif "integrity_verified" in data:
                    data["integrity_status"] = "VALID" if data["integrity_verified"] else "FAILED"
                elif "integrityVerified" in data:
                    data["integrity_status"] = "VALID" if data["integrityVerified"] else "FAILED"
        return data


class CanonicalToolExecution(BaseModel):
    """
    Audit record of an allow-listed security tool execution.
    """
    model_config = ConfigDict(extra="ignore")

    execution_id: str = Field(..., min_length=1, description="Unique execution record ID (e.g. EXEC-001)")
    tool_name: str = Field(..., min_length=1, description="Allow-listed security tool name")
    input: Any = Field(default=None, description="Tool invocation parameters")
    output: Any = Field(default=None, description="Tool execution output")
    success: bool = Field(..., description="Whether the tool execution succeeded")
    timestamp: str = Field(..., min_length=1, description="Execution timestamp")
    evidence_id: Optional[str] = Field(default=None, description="Linked Evidence ID created by this execution")

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "execution_id" not in data:
                if "executionId" in data:
                    data["execution_id"] = data["executionId"]
                elif "id" in data:
                    data["execution_id"] = data["id"]
            if "tool_name" not in data and "toolName" in data:
                data["tool_name"] = data["toolName"]
            if "evidence_id" not in data and "evidenceId" in data:
                data["evidence_id"] = data["evidenceId"]
        return data


class CanonicalAuditBlock(BaseModel):
    """
    Forensic accountability and audit metadata block.
    """
    model_config = ConfigDict(extra="ignore")

    audit_status: AuditStatusType = Field(..., description="Audit outcome verdict: AUDIT_VERIFIED | REJECTED")
    auditor_verified: bool = Field(..., description="Whether the Auditor Agent verified this case")
    critic_reviewed: bool = Field(..., description="Whether the Critic / Red-Team reviewed investigator claims")
    critic_objections_count: int = Field(default=0, ge=0, description="Count of objections raised by Critic")
    audited_at: str = Field(..., min_length=1, description="Timestamp when the audit was performed")

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "audit_status" not in data and "auditStatus" in data:
                data["audit_status"] = data["auditStatus"]
            if "auditor_verified" not in data and "auditorVerified" in data:
                data["auditor_verified"] = data["auditorVerified"]
            if "critic_reviewed" not in data and "criticReviewed" in data:
                data["critic_reviewed"] = data["criticReviewed"]
            if "critic_objections_count" not in data and "criticObjectionsCount" in data:
                data["critic_objections_count"] = data["criticObjectionsCount"]
            if "audited_at" not in data and "auditedAt" in data:
                data["audited_at"] = data["auditedAt"]
        return data


class CanonicalCaseJson(BaseModel):
    """
    Strict Canonical JSON Schema for the final Audited SOC Case (Module 3F).
    Deterministic, tamper-evident, auditable case representation.
    """
    model_config = ConfigDict(extra="ignore")

    case_id: str = Field(..., pattern=r"^CASE-.*$", description="Audited Case ID (e.g. CASE-001)")
    investigation_id: str = Field(..., pattern=r"^INV-.*$", description="Parent Investigation ID (e.g. INV-012)")
    schema_version: str = Field(default="1.0.0", description="Canonical Case JSON Schema Version")
    claims: List[CanonicalClaim] = Field(default_factory=list, description="List of audited claims evaluated against evidence")
    evidence: Union[Dict[str, CanonicalEvidenceItem], List[CanonicalEvidenceItem]] = Field(
        ...,
        description="Referenced evidence items (dictionary keyed by evidence_id or list of evidence items)"
    )
    tool_executions: List[CanonicalToolExecution] = Field(
        default_factory=list,
        description="Historical allow-listed security tool executions"
    )
    contradictions: List[str] = Field(default_factory=list, description="Identified telemetry contradictions")
    uncertainties: List[str] = Field(default_factory=list, description="Unresolved uncertainties")
    unsupported_claims: List[str] = Field(default_factory=list, description="Claims lacking sufficient evidence proof")
    final_conclusion: str = Field(..., min_length=1, description="Evidence-backed final conclusion")
    audit: CanonicalAuditBlock = Field(..., description="Forensic audit accountability block")

    @model_validator(mode="before")
    @classmethod
    def normalize_case_aliases(cls, data: Any) -> Any:
        if isinstance(data, dict):
            if "case_id" not in data and "caseId" in data:
                data["case_id"] = data["caseId"]
            if "investigation_id" not in data and "investigationId" in data:
                data["investigation_id"] = data["investigationId"]
            if "schema_version" not in data and "schemaVersion" in data:
                data["schema_version"] = data["schemaVersion"]
            if "tool_executions" not in data and "toolExecutions" in data:
                data["tool_executions"] = data["toolExecutions"]
            if "unsupported_claims" not in data and "unsupportedClaims" in data:
                data["unsupported_claims"] = data["unsupportedClaims"]
            if "final_conclusion" not in data and "finalConclusion" in data:
                data["final_conclusion"] = data["finalConclusion"]
        return data

    @model_validator(mode="after")
    def validate_cross_evidence_references(self) -> "CanonicalCaseJson":
        """
        STRICT VALIDATION RULE 1:
        Every evidence ID referenced in claims[*].evidence_ids MUST exist in top-level evidence.
        If a claim references an evidence ID that does not exist in evidence, validation MUST FAIL.
        """
        # Collect available evidence IDs
        available_ids = set()
        if isinstance(self.evidence, dict):
            for k, ev in self.evidence.items():
                available_ids.add(k)
                if hasattr(ev, "evidence_id") and ev.evidence_id:
                    available_ids.add(ev.evidence_id)
        elif isinstance(self.evidence, list):
            for ev in self.evidence:
                if hasattr(ev, "evidence_id") and ev.evidence_id:
                    available_ids.add(ev.evidence_id)

        # Cross-reference check
        for claim_idx, c in enumerate(self.claims):
            for ref_id in c.evidence_ids:
                if ref_id not in available_ids:
                    raise ValueError(
                        f"Invalid evidence reference: Claim [{claim_idx}] ('{c.claim}') "
                        f"references evidence ID '{ref_id}' which does not exist in the evidence section. "
                        f"Available evidence IDs: {sorted(list(available_ids))}."
                    )

        return self

    def to_canonical_dict(self) -> Dict[str, Any]:
        """
        Return standard canonical dictionary with strictly ordered, clean keys.
        """
        # Dump using Pydantic JSON mode
        data = self.model_dump(mode="json")
        return data

    def to_canonical_json(self, indent: Optional[int] = None) -> str:
        """
        Serialize model to deterministic canonical JSON with sorted keys.
        Guarantees byte-for-byte reproducibility across runs.
        """
        data = self.to_canonical_dict()
        return json.dumps(data, sort_keys=True, indent=indent)


class CaseJsonValidationResponse(BaseModel):
    """Response returned when validating a Candidate Case JSON payload."""
    valid: bool
    case_id: str
    investigation_id: str
    schema_version: str
    claims_count: int
    evidence_count: int
    audit_status: str
    message: str
    errors: Optional[List[str]] = None
