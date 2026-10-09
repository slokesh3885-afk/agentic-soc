from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class ContainmentStep(BaseModel):
    """Deterministic step executed within a containment playbook."""
    step_number: int = Field(..., description="Step sequence number (1, 2, 3...)")
    action: str = Field(..., description="Allow-listed containment action identifier")
    target: str = Field(..., description="Target host, IP, domain, or process")
    status: str = Field("SUCCESS", description="Step execution outcome")
    details: str = Field(..., description="Detailed outcome summary and forensic receipt")
    timestamp: str = Field(..., description="UTC timestamp of step completion")
    artifact_hash: str = Field(..., description="SHA-256 hash verifying step execution receipt")


class ContainmentDispatchPayload(BaseModel):
    """Payload to dispatch an authorized containment and remediation playbook."""
    investigation_id: str = Field(..., description="Target investigation ID (e.g. INV-001)")
    playbook_id: str = Field(..., description="Selected allow-listed playbook ID")
    target_identifier: str = Field(..., description="Target host FQDN, IP, or process identifier")
    approval_id: Optional[str] = Field(None, description="Optional linked human approval request ID")
    dispatched_by: Optional[str] = Field("sec_analyst_01", description="Authorizing human or autonomous SOAR agent")
    notes: Optional[str] = Field(None, description="Operational justification notes")


class ContainmentRollbackPayload(BaseModel):
    """Payload to safely reverse a containment and restore target state."""
    rolled_back_by: str = Field("sec_analyst_01", description="Authorizing analyst identity")
    reason: str = Field(..., description="Justification for containment de-escalation and restoration")


class ContainmentExecutionResponse(BaseModel):
    """Canonical representation of an executed containment playbook."""
    id: str = Field(..., description="Unique containment execution ID (e.g. CONT-001)")
    investigation_id: str = Field(..., description="Target investigation ID")
    approval_id: Optional[str] = Field(None, description="Linked human approval request ID")
    playbook_id: str = Field(..., description="Playbook ID")
    playbook_name: str = Field(..., description="Human-readable playbook name")
    target_type: str = Field(..., description="Entity type (HOST, IP_ADDRESS, DOMAIN, PROCESS)")
    target_identifier: str = Field(..., description="Target identifier")
    status: str = Field(..., description="State (CONTAINED, EXECUTING, FAILED, ROLLED_BACK)")
    execution_steps: List[ContainmentStep] = Field(default_factory=list, description="Ordered step audit trail")
    dispatched_by: str = Field(..., description="Dispatching actor")
    dispatched_at: str = Field(..., description="Dispatch timestamp (UTC)")
    completed_at: Optional[str] = Field(None, description="Completion timestamp (UTC)")
    rollback_enabled: bool = Field(True, description="Whether containment can be safely reverted")
    rolled_back_at: Optional[str] = Field(None, description="Rollback timestamp if reverted")
    rollback_notes: Optional[str] = Field(None, description="Rollback justification")
    audit_entry_id: Optional[str] = Field(None, description="SHA-256 block reference in Module 3L immutable ledger")
    quarantine_receipt_hash: str = Field(..., description="Digital SHA-256 quarantine proof receipt")

    model_config = {
        "from_attributes": True,
    }


class PlaybookDefinition(BaseModel):
    """Catalog definition of an allow-listed containment playbook."""
    id: str = Field(..., description="Playbook identifier (e.g. PLAYBOOK-HOST-ISOLATION)")
    name: str = Field(..., description="Human-readable title")
    target_type: str = Field(..., description="Target type (HOST, IP_ADDRESS, DOMAIN, PROCESS)")
    description: str = Field(..., description="Operational capability and scope")
    steps: List[str] = Field(..., description="Sequential action descriptions")
    safety_level: str = Field("HIGH_SAFEGUARD", description="Risk and safety categorization")
    reversible: bool = Field(True, description="Supports automatic rollback")


class ContainmentSummaryResponse(BaseModel):
    """Aggregated containment metrics across enterprise SOC."""
    total_containments: int = Field(..., description="Total playbooks dispatched")
    active_quarantines: int = Field(..., description="Currently active isolations/blocks")
    rolled_back_count: int = Field(..., description="De-escalated and restored containments")
    by_target_type: Dict[str, int] = Field(default_factory=dict, description="Counts by target category")
    by_playbook: Dict[str, int] = Field(default_factory=dict, description="Counts by playbook type")
