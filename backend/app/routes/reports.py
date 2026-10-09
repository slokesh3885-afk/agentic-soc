"""
API Routes for Executive Security Incident Reporting & Regulatory Compliance Engine (Module 3P).
Agentic SOC — Auditable AI Security Operations Center
"""

import json
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.database import get_db
from app.models.report import IncidentReportModel
from app.schemas.report import (
    ReportGeneratePayload,
    ReportSummaryResponse,
    IncidentReportResponse,
)
from app.services.report_service import (
    generate_incident_report,
)

reports_router = APIRouter(prefix="/reports", tags=["Executive Incident Reports (Module 3P)"])


def _serialize_report(r: IncidentReportModel) -> IncidentReportResponse:
    """Helper to deserialize JSON text fields into schema response."""
    return IncidentReportResponse(
        id=r.id,
        investigation_id=r.investigation_id,
        title=r.title,
        report_type=r.report_type,
        classification=r.classification,
        verdict=r.verdict,
        trust_score=r.trust_score,
        compliance_score=r.compliance_score,
        executive_summary=r.executive_summary,
        claims=json.loads(r.claims_json or "[]"),
        evidence=json.loads(r.evidence_json or "[]"),
        contradictions=json.loads(r.contradictions_json or "[]"),
        critic_findings=json.loads(r.critic_findings_json or "[]"),
        threat_attribution=json.loads(r.threat_attribution_json or "{}"),
        uncertainties=json.loads(r.uncertainties_json or "[]"),
        mitre_tactics=json.loads(r.mitre_tactics_json or "[]"),
        containment_actions=json.loads(r.containment_actions_json or "[]"),
        approval_status=json.loads(r.approval_status_json or "{}"),
        compliance_mappings=json.loads(r.compliance_mappings_json or "{}"),
        timeline_summary=json.loads(r.timeline_summary_json or "[]"),
        case_json_payload=json.loads(r.case_json_payload or "{}"),
        markdown_content=r.markdown_content,
        html_content=r.html_content,
        report_hash=r.report_hash,
        audit_entry_id=r.audit_entry_id,
        created_at=r.created_at,
        author=r.author,
        status=r.status,
    )


@reports_router.get("/summary", response_model=ReportSummaryResponse)
def get_reports_summary(db: Session = Depends(get_db)):
    """Retrieve high-level metrics for all executive incident reports."""
    reports = db.query(IncidentReportModel).all()
    total = len(reports)
    if total == 0:
        return ReportSummaryResponse(
            total_reports=0,
            published_count=0,
            average_trust_score=0.0,
            average_compliance_score=0.0,
            by_report_type={},
            by_classification={},
            by_verdict={},
        )

    published = sum(1 for r in reports if r.status == "PUBLISHED")
    avg_trust = round(sum(r.trust_score for r in reports) / total, 1)
    avg_comp = round(sum(r.compliance_score for r in reports) / total, 1)

    by_type = {}
    by_class = {}
    by_verdict = {}
    for r in reports:
        by_type[r.report_type] = by_type.get(r.report_type, 0) + 1
        by_class[r.classification] = by_class.get(r.classification, 0) + 1
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1

    return ReportSummaryResponse(
        total_reports=total,
        published_count=published,
        average_trust_score=avg_trust,
        average_compliance_score=avg_comp,
        by_report_type=by_type,
        by_classification=by_class,
        by_verdict=by_verdict,
    )


@reports_router.get("", response_model=List[IncidentReportResponse])
def list_reports(
    investigation_id: Optional[str] = Query(None, description="Filter by investigation ID"),
    report_type: Optional[str] = Query(None, description="Filter by report type"),
    classification: Optional[str] = Query(None, description="Filter by classification"),
    db: Session = Depends(get_db),
):
    """List all incident security reports matching optional filters."""
    query = db.query(IncidentReportModel)
    if investigation_id:
        query = query.filter(IncidentReportModel.investigation_id == investigation_id)
    if report_type:
        query = query.filter(IncidentReportModel.report_type == report_type)
    if classification:
        query = query.filter(IncidentReportModel.classification == classification)

    reports = query.order_by(desc(IncidentReportModel.created_at), desc(IncidentReportModel.id)).all()
    return [_serialize_report(r) for r in reports]


@reports_router.get("/{id}", response_model=IncidentReportResponse)
def get_report(id: str, db: Session = Depends(get_db)):
    """Retrieve full details of a specific incident report by ID."""
    r = db.query(IncidentReportModel).filter(IncidentReportModel.id == id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Incident report '{id}' not found.")
    return _serialize_report(r)


@reports_router.post("/generate", response_model=IncidentReportResponse)
def generate_report(payload: ReportGeneratePayload, db: Session = Depends(get_db)):
    """Generate a new official incident report for an investigation."""
    model = generate_incident_report(db, payload)
    return _serialize_report(model)


@reports_router.get("/{id}/export/json")
def export_report_json(id: str, db: Session = Depends(get_db)):
    """Export the canonical Case JSON package for a report."""
    r = db.query(IncidentReportModel).filter(IncidentReportModel.id == id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Incident report '{id}' not found.")

    headers = {
        "Content-Disposition": f'attachment; filename="{r.id}_case_audit.json"',
        "Content-Type": "application/json",
    }
    return Response(content=r.case_json_payload, headers=headers, media_type="application/json")


@reports_router.get("/{id}/export/markdown")
def export_report_markdown(id: str, db: Session = Depends(get_db)):
    """Export the complete Markdown representation for a report."""
    r = db.query(IncidentReportModel).filter(IncidentReportModel.id == id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Incident report '{id}' not found.")

    headers = {
        "Content-Disposition": f'attachment; filename="{r.id}_security_report.md"',
        "Content-Type": "text/markdown; charset=utf-8",
    }
    return Response(content=r.markdown_content, headers=headers, media_type="text/markdown")


@reports_router.get("/{id}/export/html")
def export_report_html(id: str, db: Session = Depends(get_db)):
    """Render the standalone printable HTML view for an incident report."""
    r = db.query(IncidentReportModel).filter(IncidentReportModel.id == id).first()
    if not r:
        raise HTTPException(status_code=404, detail=f"Incident report '{id}' not found.")

    return Response(content=r.html_content, media_type="text/html")
