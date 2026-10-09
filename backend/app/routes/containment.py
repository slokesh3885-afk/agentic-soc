import json
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models.containment import ContainmentExecutionModel
from app.schemas.containment import (
    ContainmentStep,
    ContainmentDispatchPayload,
    ContainmentRollbackPayload,
    ContainmentExecutionResponse,
    PlaybookDefinition,
    ContainmentSummaryResponse,
)
from app.services.containment_service import (
    list_available_playbooks,
    get_playbook_definition,
    dispatch_containment_playbook,
    rollback_containment_playbook,
    list_containments,
    get_containment_by_id,
    get_containment_summary,
)

router = APIRouter(prefix="", tags=["Module 3N: Containment & Remediation Playbooks"])


def _to_response(model: ContainmentExecutionModel) -> ContainmentExecutionResponse:
    """Helper to convert ContainmentExecutionModel to ContainmentExecutionResponse with parsed steps."""
    try:
        steps_raw = json.loads(model.execution_steps_json) if model.execution_steps_json else []
    except Exception:
        steps_raw = []
    steps = [ContainmentStep(**s) for s in steps_raw]

    return ContainmentExecutionResponse(
        id=model.id,
        investigation_id=model.investigation_id,
        approval_id=model.approval_id,
        playbook_id=model.playbook_id,
        playbook_name=model.playbook_name,
        target_type=model.target_type,
        target_identifier=model.target_identifier,
        status=model.status,
        execution_steps=steps,
        dispatched_by=model.dispatched_by,
        dispatched_at=model.dispatched_at,
        completed_at=model.completed_at,
        rollback_enabled=model.rollback_enabled,
        rolled_back_at=model.rolled_back_at,
        rollback_notes=model.rollback_notes,
        audit_entry_id=model.audit_entry_id,
        quarantine_receipt_hash=model.quarantine_receipt_hash,
    )


@router.get(
    "/containment/playbooks",
    response_model=List[PlaybookDefinition],
    summary="List all allow-listed containment and remediation playbooks",
)
def get_playbooks_route():
    """Retrieve catalog of available, allow-listed containment playbooks."""
    return list_available_playbooks()


@router.get(
    "/containment/playbooks/{playbook_id}",
    response_model=PlaybookDefinition,
    summary="Get details for a specific playbook",
)
def get_single_playbook_route(playbook_id: str):
    """Retrieve single playbook definition and step sequence."""
    return get_playbook_definition(playbook_id)


@router.get(
    "/containment/summary",
    response_model=ContainmentSummaryResponse,
    summary="Get operational summary of containment executions and active quarantines",
)
def get_containment_summary_route(db: Session = Depends(get_db)):
    """Retrieve aggregate metrics on active quarantines and playbook runs."""
    return get_containment_summary(db)


@router.get(
    "/containment",
    response_model=List[ContainmentExecutionResponse],
    summary="List containment executions across SOC",
)
def list_containments_route(
    investigation_id: Optional[str] = Query(None, description="Filter by investigation ID"),
    status: Optional[str] = Query(None, description="Filter by status (CONTAINED, ROLLED_BACK, etc.)"),
    db: Session = Depends(get_db),
):
    """List containment executions with optional query filters."""
    records = list_containments(db, investigation_id=investigation_id, status=status)
    return [_to_response(r) for r in records]


@router.get(
    "/containment/{containment_id}",
    response_model=ContainmentExecutionResponse,
    summary="Get details of a specific containment execution",
)
def get_containment_route(containment_id: str, db: Session = Depends(get_db)):
    """Retrieve containment record and execution steps by ID."""
    record = get_containment_by_id(db, containment_id)
    return _to_response(record)


@router.post(
    "/containment/dispatch",
    response_model=ContainmentExecutionResponse,
    summary="Dispatch an allow-listed containment and remediation playbook",
)
def dispatch_containment_route(
    payload: ContainmentDispatchPayload,
    db: Session = Depends(get_db),
):
    """
    Execute an allow-listed containment playbook (e.g. host quarantine, C2 IP block).
    Records step-by-step cryptographic receipts, commits an immutable audit block,
    and broadcasts real-time WebSocket telemetry.
    """
    record = dispatch_containment_playbook(db, payload)
    return _to_response(record)


@router.post(
    "/containment/{containment_id}/rollback",
    response_model=ContainmentExecutionResponse,
    summary="Safely rollback a containment action and restore target state",
)
def rollback_containment_route(
    containment_id: str,
    payload: ContainmentRollbackPayload,
    db: Session = Depends(get_db),
):
    """
    Reverse a previous quarantine/block (e.g. un-isolate host).
    Validates reversibility, records de-escalation steps, and commits an audit event.
    """
    record = rollback_containment_playbook(db, containment_id, payload)
    return _to_response(record)


@router.get(
    "/investigations/{investigation_id}/containments",
    response_model=List[ContainmentExecutionResponse],
    summary="List containment executions for a specific investigation",
)
def get_investigation_containments_route(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    """Retrieve all containment actions dispatched for an investigation."""
    records = list_containments(db, investigation_id=investigation_id)
    return [_to_response(r) for r in records]
