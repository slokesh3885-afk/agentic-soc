"""
Database Model for Executive Security Incident Reporting & Regulatory Compliance Engine (Module 3P).
Agentic SOC — Auditable AI Security Operations Center
"""

from sqlalchemy import Column, String, Integer, Float, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


class IncidentReportModel(Base):
    """
    Persisted record of an executive security incident report with regulatory compliance attestations.
    Aggregates multi-agent investigation evidence, claims, red-team critiques, auditor decisions,
    mitigations, and compliance framework controls (NIST, ISO 27035, SOC 2, GDPR, HIPAA).
    """
    __tablename__ = "incident_reports"

    id = Column(String, primary_key=True, index=True)  # e.g., 'REP-001'
    investigation_id = Column(String, ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String, nullable=False)
    report_type = Column(String, nullable=False, default="EXECUTIVE")  # EXECUTIVE, TECHNICAL, REGULATORY_COMPLIANCE, FORENSIC
    classification = Column(String, nullable=False, default="CONFIDENTIAL")  # CONFIDENTIAL, RESTRICTED, INTERNAL, PUBLIC
    verdict = Column(String, nullable=False)  # Confirmed Malicious Activity, False Positive / Authorized Activity, Inconclusive
    trust_score = Column(Float, nullable=False, default=90.0)
    compliance_score = Column(Float, nullable=False, default=100.0)  # 0.0 to 100.0%

    executive_summary = Column(Text, nullable=False)
    claims_json = Column(Text, nullable=False, default="[]")
    evidence_json = Column(Text, nullable=False, default="[]")
    contradictions_json = Column(Text, nullable=False, default="[]")
    critic_findings_json = Column(Text, nullable=False, default="[]")
    threat_attribution_json = Column(Text, nullable=False, default="{}")
    uncertainties_json = Column(Text, nullable=False, default="[]")
    mitre_tactics_json = Column(Text, nullable=False, default="[]")
    containment_actions_json = Column(Text, nullable=False, default="[]")
    approval_status_json = Column(Text, nullable=False, default="{}")
    compliance_mappings_json = Column(Text, nullable=False, default="{}")
    timeline_summary_json = Column(Text, nullable=False, default="[]")
    case_json_payload = Column(Text, nullable=False, default="{}")

    markdown_content = Column(Text, nullable=False)
    html_content = Column(Text, nullable=False)
    report_hash = Column(String, nullable=False)  # Deterministic SHA-256 fingerprint of report content

    audit_entry_id = Column(String, nullable=True)  # Linked Module 3L audit block
    created_at = Column(String, nullable=False)  # ISO timestamp
    author = Column(String, nullable=False, default="Automated Reporting Agent & Lead Investigator")
    status = Column(String, nullable=False, default="PUBLISHED")  # PUBLISHED, DRAFT, ARCHIVED

    # Relationship back to investigation
    investigation = relationship("InvestigationModel", back_populates="reports")
