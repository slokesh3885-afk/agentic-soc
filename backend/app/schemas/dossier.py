from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class MitreTechniqueMapping(BaseModel):
    """Represents a validated MITRE ATT&CK technique mapped to investigative evidence."""
    technique_id: str = Field(..., description="MITRE Technique ID (e.g., T1059.001)")
    technique_name: str = Field(..., description="Descriptive technique name (e.g., PowerShell)")
    tactic: str = Field(..., description="Enterprise tactic name (e.g., Execution)")
    tactic_id: str = Field(..., description="Enterprise tactic ID (e.g., TA0002)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Mapping confidence score (0.0 to 1.0)")
    evidence_ids: List[str] = Field(default_factory=list, description="IDs of evidence objects supporting this mapping")
    description: str = Field(..., description="Analysis rationale explaining the technical mapping")
    url: str = Field(..., description="Direct reference URL to MITRE ATT&CK knowledge base")


class ForensicCustodyEvent(BaseModel):
    """Represents an unbroken chain-of-custody transfer event for investigative evidence."""
    sequence: int = Field(..., description="Chronological custody index")
    timestamp: str = Field(..., description="UTC timestamp of the custody event")
    action: str = Field(..., description="Action performed (e.g., TELEMETRY_ACQUIRED, EVIDENCE_SEALED, HUMAN_REVIEW)")
    actor: str = Field(..., description="Agent or analyst executing the custody action")
    source: str = Field(..., description="Originating sensor or subsystem")
    artifact_hash: str = Field(..., description="SHA-256 hash of the artifact at time of transfer")
    verified: bool = Field(True, description="True if artifact integrity has been mathematically confirmed")
    notes: Optional[str] = Field(None, description="Optional custody notes or audit references")


class IncidentDossierSchema(BaseModel):
    """Complete forensic dossier for an incident case mapped to MITRE ATT&CK."""
    id: str = Field(..., description="Unique dossier ID (e.g. DOS-001)")
    investigation_id: str = Field(..., description="Target investigation identifier (e.g. INV-001)")
    title: str = Field(..., description="Formal case dossier title")
    severity: str = Field(..., description="Incident severity level (Critical, High, Medium, Low)")
    status: str = Field(..., description="Lifecycle status (Open, Under Review, Contained, Closed)")
    threat_actor_attribution: Optional[str] = Field(None, description="Attributed threat group or null if unverified")
    primary_tactic: str = Field(..., description="Primary MITRE ATT&CK enterprise tactic")
    mitre_techniques: List[MitreTechniqueMapping] = Field(default_factory=list, description="Mapped MITRE techniques")
    custody_chain: List[ForensicCustodyEvent] = Field(default_factory=list, description="Chronological forensic custody chain")
    summary: str = Field(..., description="Comprehensive investigative narrative")
    recommendations: List[str] = Field(default_factory=list, description="Prioritized remediation and containment actions")
    created_at: str = Field(..., description="UTC timestamp of dossier creation")
    updated_at: str = Field(..., description="UTC timestamp of last dossier update")

    model_config = {
        "from_attributes": True,
    }


class MitreTacticCoverage(BaseModel):
    """Summary of coverage for an individual MITRE tactic."""
    tactic_id: str = Field(..., description="Tactic ID (e.g. TA0002)")
    tactic_name: str = Field(..., description="Tactic Name (e.g. Execution)")
    technique_count: int = Field(..., description="Number of techniques observed in this tactic")
    techniques: List[str] = Field(default_factory=list, description="List of observed technique IDs")


class MitreMatrixSummaryResponse(BaseModel):
    """Enterprise-wide MITRE ATT&CK Matrix coverage analytics."""
    matrix_version: str = Field("v14.1", description="MITRE ATT&CK Enterprise Matrix version")
    total_dossiers: int = Field(..., description="Total active incident dossiers")
    total_techniques_mapped: int = Field(..., description="Total unique technique mappings across all dossiers")
    tactics_breakdown: Dict[str, int] = Field(..., description="Observed technique count per enterprise tactic")
    top_techniques: List[Dict[str, Any]] = Field(default_factory=list, description="Most frequent MITRE techniques observed")
    coverage: List[MitreTacticCoverage] = Field(default_factory=list, description="Per-tactic breakdown items")


class DossierNavigatorLayer(BaseModel):
    """Export schema compatible with MITRE ATT&CK Navigator JSON layers."""
    name: str = Field(..., description="Layer title")
    versions: Dict[str, str] = Field(default_factory=lambda: {"attack": "14", "navigator": "4.9.1", "layer": "4.5"})
    domain: str = Field("enterprise-attack", description="MITRE ATT&CK domain")
    description: str = Field(..., description="Layer description and case scope")
    techniques: List[Dict[str, Any]] = Field(default_factory=list, description="Color-coded techniques matrix")
