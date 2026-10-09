"""
Module 3T: Complete Case Audit Object Routes
Agentic SOC — Auditable AI Security Operations Center
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.case_audit_object import CompleteCaseAuditObject, AuditObjectExportResponse
from app.services.case_audit_object_service import (
    generate_complete_case_audit_object,
    export_case_audit_json,
)

router = APIRouter(prefix="", tags=["case_audit_object"])


@router.get(
    "/cases/{case_id}/audit-object",
    response_model=CompleteCaseAuditObject,
    status_code=status.HTTP_200_OK,
    summary="Get formatted complete case audit object (Module 3T)",
)
def get_case_audit_object(
    case_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieve the formatted complete case audit object.
    Includes case ID, alert, investigation plan, claims, evidence, tool executions,
    contradictions, critic findings, uncertainties, recommended actions,
    human approval requirements, threat actor attribution, trust score, and final conclusion.
    """
    return generate_complete_case_audit_object(db, case_id)


@router.post(
    "/cases/{case_id}/audit-object/export",
    response_model=AuditObjectExportResponse,
    status_code=status.HTTP_200_OK,
    summary="Export complete case audit object JSON and SHA-256 digest (Module 3T)",
)
def export_audit_object(
    case_id: str,
    db: Session = Depends(get_db),
):
    """
    Generate downloadable JSON payload and cryptographic SHA-256 integrity digest for the complete case audit object.
    """
    return export_case_audit_json(db, case_id)
