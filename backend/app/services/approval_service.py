"""
Human-in-the-Loop (HITL) Approval Service (Module 3J)
Agentic SOC — Auditable AI Security Operations Center

Orchestrates human analyst safety gates:
- ID generation (APP-xxx)
- Creation of approval gates with Trust Score & contradiction checks
- Strict override validation for low-trust or contradictory cases
- State machine protection (terminal states cannot be altered)
- Automatic investigation lifecycle transitions upon approval
"""

import re
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models.approval import ApprovalRequestModel
from app.models.investigation import InvestigationModel
from app.models.auditor import AuditedCaseModel
from app.schemas.approval import (
    ApprovalCreatePayload,
    ApprovalDecisionPayload,
    ApprovalResponse,
    ApprovalListResponse,
)
from app.services.trust_score_service import get_investigation_trust_score



def generate_approval_id(db: Session) -> str:
    """Generate sequential, deterministic approval ID (e.g. APP-001, APP-002)."""
    existing_records = db.query(ApprovalRequestModel.id).all()
    max_num = 0
    pattern = re.compile(r"^APP-(\d+)$")
    for (rec_id,) in existing_records:
        match = pattern.match(rec_id)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num
    return f"APP-{max_num + 1:03d}"


def create_approval_request(
    db: Session,
    investigation_id: str,
    payload: ApprovalCreatePayload,
) -> ApprovalRequestModel:
    """
    Create a new Human-in-the-Loop approval request for an investigation.
    Validates investigation existence, inspects evidence trust scores & contradictions,
    and flags safety override requirement if applicable.
    """
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=404,
            detail=f"Cannot create approval request: Investigation '{investigation_id}' does not exist.",
        )

    # Inspect associated audited case if provided or latest
    case: Optional[AuditedCaseModel] = None
    if payload.case_id:
        case = db.query(AuditedCaseModel).filter(AuditedCaseModel.id == payload.case_id).first()
    if not case:
        case = (
            db.query(AuditedCaseModel)
            .filter(AuditedCaseModel.investigation_id == investigation_id)
            .order_by(AuditedCaseModel.created_at.desc(), AuditedCaseModel.id.desc())
            .first()
        )

    # Determine Trust Score and Verdict snapshot
    trust_score_val = float(inv.trust_score) if inv.trust_score is not None else 85.0
    trust_verdict_val = "HIGH_TRUST" if trust_score_val >= 80 else ("MODERATE_TRUST" if trust_score_val >= 60 else "LOW_TRUST")

    has_contradictions = False
    if case:
        try:
            score_res = get_investigation_trust_score(db, investigation_id, case.id)
            trust_score_val = score_res.trust_score
            trust_verdict_val = score_res.explanation.verdict
        except Exception:
            pass
        contradictions = case.get_contradictions()
        if len(contradictions) > 0:
            has_contradictions = True

    # Determine if safety override is required
    requires_override = (
        trust_score_val < 60.0
        or trust_verdict_val in ("LOW_TRUST", "UNTRUSTED")
        or has_contradictions
        or (payload.risk_level == "CRITICAL" and trust_score_val < 80.0)
    )

    approval_id = generate_approval_id(db)
    record = ApprovalRequestModel(
        id=approval_id,
        investigation_id=investigation_id,
        case_id=case.id if case else payload.case_id,
        action_type=payload.action_type,
        recommended_action=payload.recommended_action,
        risk_level=payload.risk_level,
        trust_score=trust_score_val,
        trust_verdict=trust_verdict_val,
        status="PENDING",
        requested_by=payload.requested_by,
        requested_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        requires_override=requires_override,
    )
    db.add(record)
    db.commit()
    db.refresh(record)

    # Module 3K: Broadcast APPROVAL_REQUESTED telemetry event
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel=f"investigation:{investigation_id}",
            event_type="APPROVAL_REQUESTED",
            data={
                "approval_id": record.id,
                "investigation_id": record.investigation_id,
                "action_type": record.action_type,
                "recommended_action": record.recommended_action,
                "risk_level": record.risk_level,
                "status": record.status,
                "trust_score": record.trust_score,
                "requires_override": record.requires_override,
                "requested_by": record.requested_by,
                "requested_at": record.requested_at,
            },
            investigation_id=record.investigation_id,
        )
    except Exception:
        pass

    return record


def submit_approval_decision(
    db: Session,
    approval_id: str,
    payload: ApprovalDecisionPayload,
) -> ApprovalRequestModel:
    """
    Record human analyst approval, rejection, or cancellation decision.
    Enforces terminal state immutability, reviewer validation, and mandatory
    safety override justifications for low-trust or contradictory cases.
    """
    approval = db.query(ApprovalRequestModel).filter(ApprovalRequestModel.id == approval_id).first()
    if not approval:
        raise HTTPException(
            status_code=404,
            detail=f"Approval request '{approval_id}' does not exist.",
        )

    # State Machine Validation: Terminal states cannot be mutated
    if approval.status != "PENDING":
        raise HTTPException(
            status_code=400,
            detail=(
                f"Approval request '{approval_id}' has already been finalized with status '{approval.status}'. "
                "Cannot alter a completed approval decision."
            ),
        )

    # Validate Reviewer Identity
    reviewer = payload.reviewer.strip() if payload.reviewer else ""
    if not reviewer or len(reviewer) < 2:
        raise HTTPException(
            status_code=400,
            detail="A valid reviewer identifier is required (min 2 characters).",
        )

    # Validate Decision Notes
    notes = payload.decision_notes.strip() if payload.decision_notes else ""
    if not notes or len(notes) < 5:
        raise HTTPException(
            status_code=400,
            detail="Decision notes must provide justification for the decision (min 5 characters).",
        )

    # Enforce Safety Override Justification
    override_justification = (
        payload.override_justification.strip() if payload.override_justification else None
    )
    if approval.requires_override and payload.decision == "APPROVED":
        if not override_justification or len(override_justification) < 10:
            raise HTTPException(
                status_code=400,
                detail=(
                    "Explicit safety override justification is required (min 10 characters) "
                    "to approve an action on an uncorroborated, low-trust, or contradictory investigation."
                ),
            )

    # Update Approval Record
    approval.status = payload.decision
    approval.reviewer = reviewer
    approval.decision_notes = notes
    approval.override_justification = override_justification
    approval.decision_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Lifecycle State Transitions on Investigation
    inv = approval.investigation
    if inv:
        if payload.decision == "APPROVED":
            if approval.action_type == "CASE_CLOSURE":
                inv.status = "Closed"
            elif approval.action_type in ("CONTAINMENT_ISOLATE_HOST", "CONTAINMENT_BLOCK_IP"):
                inv.status = "Remediating"
            elif approval.action_type == "REMEDIAL_ACTION":
                inv.status = "Remediating"
        elif payload.decision == "REJECTED":
            if inv.status == "Closed":
                inv.status = "Investigating"

    db.commit()
    db.refresh(approval)

    # Module 3K: Broadcast APPROVAL_DECIDED telemetry event
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel=f"investigation:{approval.investigation_id}",
            event_type="APPROVAL_DECIDED",
            data={
                "approval_id": approval.id,
                "investigation_id": approval.investigation_id,
                "status": approval.status,
                "reviewer": approval.reviewer,
                "decision_notes": approval.decision_notes,
                "override_justification": approval.override_justification,
                "decision_at": approval.decision_at,
            },
            investigation_id=approval.investigation_id,
        )
    except Exception:
        pass

    return approval


def get_approval_by_id(db: Session, approval_id: str) -> ApprovalRequestModel:
    """Retrieve an approval request by its unique ID."""
    approval = db.query(ApprovalRequestModel).filter(ApprovalRequestModel.id == approval_id).first()
    if not approval:
        raise HTTPException(
            status_code=404,
            detail=f"Approval request '{approval_id}' does not exist.",
        )
    return approval


def list_approvals_for_investigation(
    db: Session,
    investigation_id: str,
) -> List[ApprovalRequestModel]:
    """Retrieve all approval requests tied to an investigation, sorted newest first."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation '{investigation_id}' does not exist.",
        )
    return (
        db.query(ApprovalRequestModel)
        .filter(ApprovalRequestModel.investigation_id == investigation_id)
        .order_by(ApprovalRequestModel.requested_at.desc())
        .all()
    )


def list_all_approvals(
    db: Session,
    status: Optional[str] = None,
) -> ApprovalListResponse:
    """Retrieve all approvals system-wide, optionally filtered by status."""
    query = db.query(ApprovalRequestModel)
    if status:
        query = query.filter(ApprovalRequestModel.status == status.upper())
    records = query.order_by(ApprovalRequestModel.requested_at.desc()).all()

    pending_count = (
        db.query(ApprovalRequestModel)
        .filter(ApprovalRequestModel.status == "PENDING")
        .count()
    )
    pydantic_items = [ApprovalResponse.model_validate(r, from_attributes=True) for r in records]
    return ApprovalListResponse(
        total=len(records),
        pending_count=pending_count,
        approvals=pydantic_items,
    )


def seed_initial_approvals(db: Session) -> None:
    """Seed initial deterministic approvals if table is empty."""
    count = db.query(ApprovalRequestModel).count()
    if count > 0:
        return

    # Seed an approval gate for INV-012 (Case Closure Pending)
    inv12 = db.query(InvestigationModel).filter(InvestigationModel.id == "INV-012").first()
    if inv12:
        app1 = ApprovalRequestModel(
            id="APP-001",
            investigation_id="INV-012",
            case_id="CASE-001",
            action_type="CASE_CLOSURE",
            recommended_action="Approve investigation closure following Auditor evaluation of suspicious PowerShell activity.",
            risk_level="MEDIUM",
            trust_score=57.5,
            trust_verdict="LOW_TRUST",
            status="PENDING",
            requested_by="Auditor Agent",
            requested_at="2026-09-27 16:20:00 UTC",
            requires_override=True,
        )
        db.add(app1)

    # Seed an approved containment action for INV-001
    inv1 = db.query(InvestigationModel).filter(InvestigationModel.id == "INV-001").first()
    if inv1:
        app2 = ApprovalRequestModel(
            id="APP-002",
            investigation_id="INV-001",
            case_id=None,
            action_type="CONTAINMENT_ISOLATE_HOST",
            recommended_action="Isolate host from production network to contain suspected C2 beaconing.",
            risk_level="HIGH",
            trust_score=90.0,
            trust_verdict="HIGH_TRUST",
            status="APPROVED",
            requested_by="Autonomous Host Triage Agent",
            requested_at="2026-09-27 13:35:00 UTC",
            reviewer="sec_analyst_lead",
            decision_notes="Host network isolation confirmed. Forensic snapshot taken before isolation.",
            decision_at="2026-09-27 13:40:15 UTC",
            requires_override=False,
        )
        db.add(app2)

    db.commit()
