from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class AuditEntrySchema(BaseModel):
    """Schema representing a single block in the cryptographic immutable audit ledger."""
    id: str = Field(..., description="Unique audit entry identifier (e.g. AUD-0001)")
    sequence: int = Field(..., description="Monotonically increasing sequence number (0 for Genesis)")
    timestamp: str = Field(..., description="UTC timestamp of the recorded audit block")
    event_type: str = Field(..., description="Category of the audit event (e.g. EVIDENCE_SEALED, INVESTIGATION_SEALED)")
    investigation_id: Optional[str] = Field(None, description="Linked investigation ID (e.g. INV-001) or null for system events")
    actor: str = Field(..., description="Entity or agent responsible for the action")
    payload_summary: str = Field(..., description="Human-readable summary of the recorded action")
    payload_hash: str = Field(..., description="SHA-256 hash of the canonical JSON payload")
    prev_hash: str = Field(..., description="SHA-256 hash of the preceding block (64 zeros for Genesis)")
    entry_hash: str = Field(..., description="SHA-256 hash of the block header and previous hash")
    signature: str = Field(..., description="Cryptographic digital signature/seal verifying block integrity")
    metadata_json: Optional[str] = Field("{}", description="Serialized JSON metadata")

    model_config = {
        "from_attributes": True,
    }


class AuditVerificationResponse(BaseModel):
    """Schema representing the result of a full cryptographic chain verification."""
    chain_valid: bool = Field(..., description="True if every block hash, previous link, and signature is intact")
    total_entries: int = Field(..., description="Total count of verified blocks in the ledger")
    genesis_hash: str = Field(..., description="SHA-256 hash of the Genesis block")
    latest_hash: str = Field(..., description="SHA-256 hash of the most recent block")
    merkle_root: str = Field(..., description="Current Merkle root derived across all ledger entry hashes")
    corrupted_entry_id: Optional[str] = Field(None, description="Identifier of the first tampered entry if chain is broken")
    verification_timestamp: str = Field(..., description="UTC timestamp when verification was executed")
    details: str = Field(..., description="Human-readable description of verification results")


class SealInvestigationRequest(BaseModel):
    """Schema for requesting a cryptographic audit seal over an investigation."""
    investigation_id: str = Field(..., description="Target investigation to seal (e.g. INV-001)")
    signed_by: Optional[str] = Field("SOC Lead Auditor", description="Designated human or system signatory")
    notes: Optional[str] = Field("Cryptographically sealed investigation bundle", description="Optional sealing notes")


class SealInvestigationResponse(BaseModel):
    """Schema for the response after sealing an investigation into the audit ledger."""
    audit_id: str = Field(..., description="Assigned audit entry ID for the seal event")
    investigation_id: str = Field(..., description="Sealed investigation ID")
    sequence: int = Field(..., description="Ledger sequence number")
    merkle_root: str = Field(..., description="Merkle root calculated across all investigation artifacts")
    entry_hash: str = Field(..., description="SHA-256 block hash recorded in the immutable ledger")
    signature: str = Field(..., description="Cryptographic seal signature")
    timestamp: str = Field(..., description="UTC timestamp of sealing")
    evidence_count: int = Field(..., description="Number of evidence items sealed in this bundle")
    status: str = Field("SEALED", description="Sealing lifecycle status")


class AuditBundleResponse(BaseModel):
    """Schema for the complete cryptographic proof bundle of an investigation."""
    investigation_id: str = Field(..., description="Investigation ID")
    sealed: bool = Field(..., description="True if a cryptographic seal has been recorded in the ledger")
    seal_audit_id: Optional[str] = Field(None, description="Audit entry ID of the seal event")
    merkle_root: Optional[str] = Field(None, description="Merkle root of all evidence and case artifacts")
    entry_hash: Optional[str] = Field(None, description="SHA-256 ledger block hash")
    signature: Optional[str] = Field(None, description="Cryptographic seal signature")
    timestamp: Optional[str] = Field(None, description="UTC timestamp of the seal")
    evidence_hashes: List[Dict[str, Any]] = Field(default_factory=list, description="List of evidence IDs with SHA-256 content hashes")
    case_id: Optional[str] = Field(None, description="Canonical Audited Case ID if available")
    case_hash: Optional[str] = Field(None, description="SHA-256 hash of the canonical case JSON")
    approval_hashes: List[Dict[str, Any]] = Field(default_factory=list, description="List of approval IDs and hashes")
    chain_verified: bool = Field(True, description="True if the ledger chain containing the seal is intact")
