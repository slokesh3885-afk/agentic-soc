"""
Complete Case Audit Object Schema (Module 3T)
Agentic SOC — Auditable AI Security Operations Center

Defines the formatted Case JSON audit object schema specified in prompt_d075_full.txt lines 388-410:
{
  "case_id": "CASE-2026-0042",
  "alert": {},
  "investigation_plan": [],
  "claims": [],
  "evidence": [],
  "tool_executions": [],
  "contradictions": [],
  "critic_findings": [],
  "uncertainties": [],
  "recommended_actions": [],
  "human_approval_required": [],
  "threat_actor_attribution": {},
  "trust_score": 87,
  "final_conclusion": ""
}
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class CompleteCaseAuditObject(BaseModel):
    """
    Formatted complete audit object for a SOC investigation.
    Strictly aligns with the canonical schema required in the specification.
    """
    case_id: str = Field("CASE-2026-0042", description="Unique case identifier")
    alert: Dict[str, Any] = Field(default_factory=dict, description="Original ingested alert telemetry")
    investigation_plan: List[Dict[str, Any]] = Field(default_factory=list, description="Ordered allow-listed plan steps")
    claims: List[Dict[str, Any]] = Field(default_factory=list, description="Audited claims bound to evidence IDs")
    evidence: List[Dict[str, Any]] = Field(default_factory=list, description="Cryptographic SHA-256 evidence items")
    tool_executions: List[Dict[str, Any]] = Field(default_factory=list, description="Recorded sandboxed tool outputs")
    contradictions: List[Dict[str, Any]] = Field(default_factory=list, description="Detected evidence and hypothesis contradictions")
    critic_findings: List[Dict[str, Any]] = Field(default_factory=list, description="Adversarial findings from Critic Agent")
    uncertainties: List[Dict[str, Any]] = Field(default_factory=list, description="Residual forensic uncertainties")
    recommended_actions: List[Dict[str, Any]] = Field(default_factory=list, description="Recommended remediation playbooks")
    human_approval_required: List[Dict[str, Any]] = Field(default_factory=list, description="High-impact actions awaiting human approval")
    threat_actor_attribution: Dict[str, Any] = Field(default_factory=dict, description="Attribution Policy Guard evaluation")
    trust_score: float = Field(87.0, description="Explainable evidence & audit quality Trust Score (0-100)")
    final_conclusion: str = Field(..., description="Evidence-backed final conclusion")
    tamper_proof_seal: Optional[str] = Field(None, description="SHA-256 Merkle root seal of this case audit object")
    timestamp: str = Field(..., description="ISO 8601 case sealing timestamp")


class AuditObjectExportResponse(BaseModel):
    """Export container for raw JSON download."""
    case_id: str
    filename: str
    content: str
    sha256_hash: str
    exported_at: str
