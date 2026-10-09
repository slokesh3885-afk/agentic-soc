from typing import Optional, Dict, Any
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.auditor import AuditorRequest, AuditedCaseResponse
from app.schemas.canonical_case import CanonicalCaseJson, CaseJsonValidationResponse
from app.services.auditor_service import (
    audit_investigation,
    get_latest_audited_case,
    export_canonical_case,
    validate_canonical_case_payload,
)

router = APIRouter(tags=["auditor"])


@router.post(
    "/investigations/{investigation_id}/audit",
    response_model=AuditedCaseResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate evidence-backed Audited Case file via Auditor Agent (Module 3E)",
)
def run_auditor(
    investigation_id: str,
    payload: AuditorRequest,
    db: Session = Depends(get_db),
):
    """
    Auditor Agent endpoint.
    Converts investigation into a structured, tamper-evident audited case file.
    Evaluates claims against the verified evidence ledger ('NO EVIDENCE -> NO CLAIM'),
    verifies cryptographic SHA-256 integrity, preserves Critic objections,
    exposes genuine contradictions and uncertainties, and includes recorded tool execution history.
    Does NOT execute tools or mutate evidence.
    """
    return audit_investigation(db, investigation_id, payload)


@router.get(
    "/investigations/{investigation_id}/audit",
    response_model=AuditedCaseResponse,
    status_code=status.HTTP_200_OK,
    summary="Get latest Audited Case file for an investigation",
)
def get_audited_case(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """
    Retrieve the most recent Audited Case file for the specified investigation.
    """
    case_file = get_latest_audited_case(db, investigation_id)
    if not case_file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No audited case found for investigation '{investigation_id}'.",
        )
    return case_file


@router.get(
    "/investigations/{investigation_id}/case-json",
    response_model=CanonicalCaseJson,
    status_code=status.HTTP_200_OK,
    summary="Export Canonical Case JSON for investigation (Module 3F)",
)
def get_canonical_case_json(
    investigation_id: str,
    case_id: Optional[str] = None,
    db: Session = Depends(get_db),
):
    """
    Export the canonical audited Case JSON representation (Module 3F).
    Deterministic, strict schema representing the entire evidence-backed investigation:
    case metadata, audited claims strictly tied to evidence ('NO EVIDENCE -> NO CLAIM'),
    cryptographic SHA-256 evidence items, tool executions, contradictions, uncertainties,
    and audit block.
    """
    return export_canonical_case(db, investigation_id, case_id)


@router.post(
    "/investigations/{investigation_id}/case-json/validate",
    response_model=CaseJsonValidationResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate candidate Case JSON payload for an investigation (Module 3F)",
)
def validate_investigation_case_json(
    investigation_id: str,
    payload: Dict[str, Any],
):
    """
    Validate a Candidate Case JSON payload against the strict Canonical Case JSON Schema.
    Validates evidence cross-referencing, 'NO EVIDENCE -> NO CLAIM' rules, status constraints,
    and required fields.
    """
    return validate_canonical_case_payload(payload)


@router.post(
    "/case-json/validate",
    response_model=CaseJsonValidationResponse,
    status_code=status.HTTP_200_OK,
    summary="Validate any Case JSON payload against canonical schema (Module 3F)",
)
def validate_generic_case_json(
    payload: Dict[str, Any],
):
    """
    Validate any Candidate Case JSON payload against the strict Canonical Case JSON Schema.
    """
    return validate_canonical_case_payload(payload)

