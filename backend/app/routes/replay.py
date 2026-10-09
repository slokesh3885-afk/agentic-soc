"""
FastAPI Routes for Forensic Timeline Replay & Investigation Reproducibility Engine (Module 3O).
Agentic SOC — Auditable AI Security Operations Center
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas.replay import (
    TimelineEvent,
    ReplayTriggerPayload,
    ReplaySessionResponse,
    ReplaySummaryResponse,
)
from app.services.replay_service import (
    execute_investigation_replay,
    get_replay_session,
    list_replays,
    get_replay_summary,
    build_investigation_timeline,
)

router = APIRouter(tags=["replay"])


@router.get(
    "/replay/summary",
    response_model=ReplaySummaryResponse,
    summary="Get operational summary of all replay sessions across the SOC",
)
def get_summary(db: Session = Depends(get_db)):
    """Retrieve aggregate reproducibility metrics, average consistency score, and verdict breakdown."""
    return get_replay_summary(db)


@router.get(
    "/replay",
    response_model=List[ReplaySessionResponse],
    summary="List all investigation replay sessions",
)
def list_all_replays(
    investigation_id: Optional[str] = Query(None, description="Filter by investigation ID"),
    db: Session = Depends(get_db),
):
    """Retrieve all executed replay sessions with comparison matrix and status."""
    return list_replays(db, investigation_id=investigation_id)


@router.get(
    "/replay/{id}",
    response_model=ReplaySessionResponse,
    summary="Retrieve single replay session with full reconstructed timeline",
)
def get_single_replay(id: str, db: Session = Depends(get_db)):
    """Retrieve specific replay session details, comparison matrix, and step-by-step events."""
    return get_replay_session(db, replay_id=id)


@router.post(
    "/replay/execute",
    response_model=ReplaySessionResponse,
    status_code=status.HTTP_200_OK,
    summary="Deterministically replay an investigation from historical artifacts",
)
def trigger_replay(
    payload: ReplayTriggerPayload,
    db: Session = Depends(get_db),
):
    """
    Trigger deterministic re-execution of an investigation.
    Re-runs multi-agent adjudication on frozen tool outputs and evidence snapshot,
    verifying 100% reproducibility and committing an audit block to the ledger.
    """
    return execute_investigation_replay(
        db=db,
        investigation_id=payload.investigation_id,
        notes=payload.notes,
        strict_verification=payload.strict_verification,
    )


@router.get(
    "/investigations/{investigation_id}/timeline",
    response_model=List[TimelineEvent],
    summary="Get unified chronological forensic timeline for an investigation",
)
def get_timeline(investigation_id: str, db: Session = Depends(get_db)):
    """
    Reconstruct the full chronological timeline of events, tool runs, evidence acquisitions,
    agent reviews, approvals, and containment steps for an investigation.
    """
    return build_investigation_timeline(db, investigation_id=investigation_id)


@router.get(
    "/investigations/{investigation_id}/replays",
    response_model=List[ReplaySessionResponse],
    summary="List all replay executions for a specific investigation",
)
def get_investigation_replays(investigation_id: str, db: Session = Depends(get_db)):
    """Retrieve historical replay sessions executed for this investigation."""
    return list_replays(db, investigation_id=investigation_id)
