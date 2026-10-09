"""
Human-in-the-Loop (HITL) Approval Routes (Module 3J)
Agentic SOC — Auditable AI Security Operations Center

Exposes endpoints for human approval gates:
- GET /api/approvals: List all approval requests
- GET /api/approvals/{approval_id}: Get single approval request
- POST /api/approvals/{approval_id}/decision: Submit human decision (Approve/Reject)
- GET /api/investigations/{investigation_id}/approvals: List approvals for investigation
- POST /api/investigations/{investigation_id}/approvals: Create new approval request
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.approval import (
    ApprovalResponse,
    ApprovalListResponse,
    ApprovalCreatePayload,
    ApprovalDecisionPayload,
)
from app.services.approval_service import (
    create_approval_request,
    submit_approval_decision,
    get_approval_by_id,
    list_approvals_for_investigation,
    list_all_approvals,
)

router = APIRouter(tags=["approvals"])


@router.get(
    "/approvals",
    response_model=ApprovalListResponse,
    summary="List all Human-in-the-Loop approval requests across the SOC",
)
def get_all_approvals_route(
    status: Optional[str] = Query(None, description="Filter by status (PENDING, APPROVED, REJECTED, CANCELLED)"),
    db: Session = Depends(get_db),
):
    """Retrieve all human approval gates across the enterprise SOC."""
    return list_all_approvals(db, status=status)


@router.get(
    "/approvals/{approval_id}",
    response_model=ApprovalResponse,
    summary="Get details of a specific approval request",
)
def get_single_approval_route(
    approval_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve details, status, and audit history for an approval request."""
    record = get_approval_by_id(db, approval_id)
    return ApprovalResponse.model_validate(record, from_attributes=True)


@router.post(
    "/approvals/{approval_id}/decision",
    response_model=ApprovalResponse,
    summary="Submit human analyst decision (Approve or Reject)",
)
def submit_decision_route(
    approval_id: str,
    payload: ApprovalDecisionPayload,
    db: Session = Depends(get_db),
):
    """
    Submit a human analyst approval or rejection decision.
    Enforces terminal state immutability, reviewer identity validation,
    and mandatory safety override justifications when approving uncorroborated
    or contradictory cases.
    """
    record = submit_approval_decision(db, approval_id, payload)
    return ApprovalResponse.model_validate(record, from_attributes=True)


@router.get(
    "/investigations/{investigation_id}/approvals",
    response_model=List[ApprovalResponse],
    summary="List approval requests for an investigation",
)
def list_investigation_approvals_route(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve all human approval gates bound to a specific investigation."""
    records = list_approvals_for_investigation(db, investigation_id)
    return [ApprovalResponse.model_validate(r, from_attributes=True) for r in records]


@router.post(
    "/investigations/{investigation_id}/approvals",
    response_model=ApprovalResponse,
    summary="Create a new human approval request for an investigation",
)
def create_investigation_approval_route(
    investigation_id: str,
    payload: ApprovalCreatePayload,
    db: Session = Depends(get_db),
):
    """
    Create a new human-in-the-loop approval request for containment, remediation,
    or case closure on an active investigation.
    """
    record = create_approval_request(db, investigation_id, payload)
    return ApprovalResponse.model_validate(record, from_attributes=True)
