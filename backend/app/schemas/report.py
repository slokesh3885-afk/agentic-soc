"""
Pydantic v2 Schemas for Executive Security Incident Reporting & Regulatory Compliance Engine (Module 3P).
Agentic SOC — Auditable AI Security Operations Center
"""

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ComplianceControl(BaseModel):
    """Specific regulatory compliance control assessment."""
    framework: str
    control_id: str
    control_name: str
    status: str = "COMPLIANT"  # COMPLIANT, WARNING, NOT_APPLICABLE
    description: str
    evidence_refs: List[str] = Field(default_factory=list)


class ComplianceFrameworkReport(BaseModel):
    """Aggregate evaluation for a specific compliance standard."""
    framework_name: str
    adherence_score: float  # e.g., 100.0 or 95.0
    status: str = "COMPLIANT"
    controls: List[ComplianceControl] = Field(default_factory=list)


class ReportGeneratePayload(BaseModel):
    """Payload to trigger incident report generation."""
    investigation_id: str = Field(..., description="ID of the investigation e.g. INV-001")
    report_type: str = Field(default="EXECUTIVE", description="EXECUTIVE, TECHNICAL, REGULATORY_COMPLIANCE, FORENSIC")
    classification: str = Field(default="CONFIDENTIAL", description="CONFIDENTIAL, RESTRICTED, INTERNAL, PUBLIC")
    notes: Optional[str] = Field(default=None, description="Optional analyst notes")
    author: str = Field(default="Lead Forensic Investigator", description="Author of the report")


class ReportSummaryResponse(BaseModel):
    """High-level summary of all generated incident reports."""
    total_reports: int
    published_count: int
    average_trust_score: float
    average_compliance_score: float
    by_report_type: Dict[str, int]
    by_classification: Dict[str, int]
    by_verdict: Dict[str, int]


class IncidentReportResponse(BaseModel):
    """Comprehensive incident report object with full evidence, audit, and compliance data."""
    id: str
    investigation_id: str
    title: str
    report_type: str
    classification: str
    verdict: str
    trust_score: float
    compliance_score: float
    executive_summary: str
    claims: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    contradictions: List[Dict[str, Any]] = Field(default_factory=list)
    critic_findings: List[Dict[str, Any]] = Field(default_factory=list)
    threat_attribution: Dict[str, Any] = Field(default_factory=dict)
    uncertainties: List[str] = Field(default_factory=list)
    mitre_tactics: List[Dict[str, Any]] = Field(default_factory=list)
    containment_actions: List[Dict[str, Any]] = Field(default_factory=list)
    approval_status: Dict[str, Any] = Field(default_factory=dict)
    compliance_mappings: Dict[str, ComplianceFrameworkReport] = Field(default_factory=dict)
    timeline_summary: List[Dict[str, Any]] = Field(default_factory=list)
    case_json_payload: Dict[str, Any] = Field(default_factory=dict)
    markdown_content: str
    html_content: str
    report_hash: str
    audit_entry_id: Optional[str] = None
    created_at: str
    author: str
    status: str
