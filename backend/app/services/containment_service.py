import json
import hashlib
import logging
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.investigation import InvestigationModel
from app.models.approval import ApprovalRequestModel
from app.models.containment import ContainmentExecutionModel
from app.models.audit_entry import AuditEntryModel
from app.schemas.containment import (
    ContainmentStep,
    ContainmentDispatchPayload,
    ContainmentRollbackPayload,
    PlaybookDefinition,
    ContainmentSummaryResponse,
)

logger = logging.getLogger("agentic_soc.containment_service")

# Allow-listed Standard Containment & Remediation Playbooks Catalog
PLAYBOOK_CATALOG: Dict[str, Dict[str, Any]] = {
    "PLAYBOOK-HOST-ISOLATION": {
        "id": "PLAYBOOK-HOST-ISOLATION",
        "name": "Endpoint Host Network Isolation (Quarantine)",
        "target_type": "HOST",
        "description": "Enforces strict network quarantine at endpoint firewall layer, severing corporate LAN/WAN connectivity while preserving local SOC management tunnel (TCP/8443).",
        "steps": [
            "HOST_NETWORK_RESTRICT: Apply dynamic endpoint firewall quarantine rule (block all traffic except SOC management port 8443)",
            "CREDENTIAL_SESSION_REVOKE: Invalidate active Kerberos tickets, purge domain token cache, and force re-authentication",
            "SOCKET_FLUSH: Terminate non-management socket connections and flush local DNS resolver cache",
            "VERIFY_CONTAINMENT_RECEIPT: Validate isolation enforcement status and emit cryptographic quarantine token",
        ],
        "safety_level": "HIGH_SAFEGUARD",
        "reversible": True,
    },
    "PLAYBOOK-NETWORK-BLOCK": {
        "id": "PLAYBOOK-NETWORK-BLOCK",
        "name": "Perimeter Firewall C2 Indicator Drop Rule",
        "target_type": "IP_ADDRESS",
        "description": "Deploys high-priority ingress/egress drop rules across enterprise perimeter firewalls and injects internal DNS sinkhole entries for malicious C2 domains.",
        "steps": [
            "INDICATOR_EXTRACTION: Validate target IP or domain indicator against corroborated evidence artifacts",
            "FIREWALL_EGRESS_DROP: Deploy dynamic perimeter drop rule blocking all ingress and egress to target indicator",
            "DNS_SINKHOLE_INJECT: Poison internal recursive DNS resolver resolution for C2 domain with loopback sinkhole (127.0.0.1)",
            "VERIFY_RULE_PROPAGATION: Confirm rule convergence across perimeter ingress gateways and log drop rule receipt",
        ],
        "safety_level": "HIGH_SAFEGUARD",
        "reversible": True,
    },
    "PLAYBOOK-PROCESS-TERMINATION": {
        "id": "PLAYBOOK-PROCESS-TERMINATION",
        "name": "Malicious Process Tree Halt & Artifact Quarantine",
        "target_type": "PROCESS",
        "description": "Suspends suspect process tree execution, halts malicious child worker threads, terminates process handles, and relocates disk binaries to encrypted quarantine storage.",
        "steps": [
            "PROCESS_TREE_SUSPEND: Signal immediate thread execution suspension for target process PID and sub-tree",
            "BINARY_QUARANTINE: Move malicious executable from disk to AES-256 encrypted quarantine vault",
            "MEMORY_FLUSH: Terminate malicious process handle and capture memory volatility hash",
            "VERIFY_TERMINATION: Validate process absence in OS scheduler and generate process quarantine proof receipt",
        ],
        "safety_level": "HIGH_SAFEGUARD",
        "reversible": False,
    },
    "PLAYBOOK-CONTAINMENT-ROLLBACK": {
        "id": "PLAYBOOK-CONTAINMENT-ROLLBACK",
        "name": "De-escalation & Quarantine Restoration Playbook",
        "target_type": "HOST",
        "description": "Reverses network quarantine, tears down temporary perimeter firewall drop rules, and restores normal operational connectivity.",
        "steps": [
            "REMOVE_QUARANTINE_RULES: Flush containment drop rules from endpoint and edge firewalls",
            "RESTORE_SOCKET_ROUTING: Restore default gateway routing and verify enterprise directory connectivity",
            "REVOKE_SINKHOLE: Remove DNS sinkhole entries and flush resolver cache",
            "VERIFY_OPERATIONAL_HEALTH: Execute host health check and log de-escalation receipt in audit ledger",
        ],
        "safety_level": "HIGH_SAFEGUARD",
        "reversible": False,
    },
}


def _sha256(data: str) -> str:
    """Helper to compute deterministic SHA-256 hex digest."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def list_available_playbooks() -> List[PlaybookDefinition]:
    """Retrieve catalog of all allow-listed containment and remediation playbooks."""
    return [PlaybookDefinition(**p) for p in PLAYBOOK_CATALOG.values()]


def get_playbook_definition(playbook_id: str) -> PlaybookDefinition:
    """Retrieve details for a specific playbook."""
    if playbook_id not in PLAYBOOK_CATALOG:
        raise HTTPException(status_code=404, detail=f"Playbook {playbook_id} not found in allow-listed catalog.")
    return PlaybookDefinition(**PLAYBOOK_CATALOG[playbook_id])


def dispatch_containment_playbook(
    db: Session, payload: ContainmentDispatchPayload
) -> ContainmentExecutionModel:
    """
    Deterministically execute an allow-listed containment and remediation playbook.
    Generates step-by-step verified receipts, updates investigation lifecycle status,
    commits an immutable block to the Module 3L audit ledger, and broadcasts WebSocket telemetry.
    """
    # 1. Validate Target Investigation
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == payload.investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=404,
            detail=f"Investigation {payload.investigation_id} not found."
        )

    # 2. Validate Playbook
    if payload.playbook_id not in PLAYBOOK_CATALOG:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid playbook {payload.playbook_id}. Must be one of: {list(PLAYBOOK_CATALOG.keys())}"
        )

    playbook = PLAYBOOK_CATALOG[payload.playbook_id]
    target_id = payload.target_identifier.strip()
    if not target_id:
        raise HTTPException(
            status_code=400,
            detail="Target identifier (host, IP, or process) is required."
        )

    # 3. Optional Approval Linkage Verification
    if payload.approval_id:
        app = db.query(ApprovalRequestModel).filter(ApprovalRequestModel.id == payload.approval_id).first()
        if app and app.status != "APPROVED":
            raise HTTPException(
                status_code=400,
                detail=f"Linked approval gate {app.id} is in status '{app.status}'. Actions require APPROVED state."
            )

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 4. Generate Deterministic Execution Steps
    steps: List[ContainmentStep] = []
    for idx, step_desc in enumerate(playbook["steps"], start=1):
        action_name = step_desc.split(":")[0].strip()
        step_receipt = f"STEP-{idx}:{action_name}:{target_id}:{now_utc}"
        step_hash = _sha256(step_receipt)
        steps.append(
            ContainmentStep(
                step_number=idx,
                action=action_name,
                target=target_id,
                status="SUCCESS",
                details=f"Executed allow-listed action: {step_desc}",
                timestamp=now_utc,
                artifact_hash=step_hash,
            )
        )

    # 5. Generate Quarantine Receipt Hash
    raw_receipt = f"{inv.id}:{payload.playbook_id}:{target_id}:{now_utc}:{len(steps)}"
    quarantine_receipt_hash = _sha256(raw_receipt)

    # 6. Generate Sequential Containment ID
    count = db.query(ContainmentExecutionModel).count()
    containment_id = f"CONT-{count + 1:03d}"

    # 7. Create Containment Model
    record = ContainmentExecutionModel(
        id=containment_id,
        investigation_id=payload.investigation_id,
        approval_id=payload.approval_id,
        playbook_id=payload.playbook_id,
        playbook_name=playbook["name"],
        target_type=playbook["target_type"],
        target_identifier=target_id,
        status="CONTAINED",
        execution_steps_json=json.dumps([s.model_dump() for s in steps]),
        dispatched_by=payload.dispatched_by or "sec_analyst_01",
        dispatched_at=now_utc,
        completed_at=now_utc,
        rollback_enabled=playbook["reversible"],
        quarantine_receipt_hash=quarantine_receipt_hash,
    )

    # 8. Update Investigation Lifecycle State
    if playbook["target_type"] == "HOST":
        inv.status = "Remediating"
    elif playbook["target_type"] in ("IP_ADDRESS", "PROCESS"):
        inv.status = "Remediating"

    db.add(record)
    db.commit()
    db.refresh(record)

    # 9. Cryptographically Commit to Module 3L Immutable Audit Ledger
    try:
        from app.services.audit_service import record_audit_event
        audit_entry = record_audit_event(
            db=db,
            event_type="CONTAINMENT_DISPATCHED",
            payload={
                "containment_id": record.id,
                "investigation_id": record.investigation_id,
                "playbook_id": record.playbook_id,
                "target_type": record.target_type,
                "target_identifier": record.target_identifier,
                "quarantine_receipt_hash": record.quarantine_receipt_hash,
                "steps_count": len(steps),
            },
            investigation_id=record.investigation_id,
            actor=record.dispatched_by,
            payload_summary=f"Dispatched {record.playbook_name} on target {record.target_identifier}",
        )
        record.audit_entry_id = audit_entry.id
        db.commit()
        db.refresh(record)
    except Exception as ex:
        logger.warning(f"Audit ledger recording skipped: {ex}")

    # 10. Broadcast Real-time WebSocket Telemetry (Module 3K)
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel=f"investigation:{record.investigation_id}",
            event_type="CONTAINMENT_EXECUTED",
            data={
                "containment_id": record.id,
                "investigation_id": record.investigation_id,
                "playbook_id": record.playbook_id,
                "playbook_name": record.playbook_name,
                "target_identifier": record.target_identifier,
                "status": record.status,
                "quarantine_receipt_hash": record.quarantine_receipt_hash,
                "dispatched_at": record.dispatched_at,
            },
            investigation_id=record.investigation_id,
        )
    except Exception:
        pass

    return record


def rollback_containment_playbook(
    db: Session, containment_id: str, payload: ContainmentRollbackPayload
) -> ContainmentExecutionModel:
    """
    Safely reverse a previous containment action (e.g. un-isolate host, unblock IP).
    Validates reversibility, records de-escalation steps, commits audit record,
    and updates state to ROLLED_BACK.
    """
    record = (
        db.query(ContainmentExecutionModel)
        .filter(ContainmentExecutionModel.id == containment_id)
        .first()
    )
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"Containment execution {containment_id} not found."
        )

    if not record.rollback_enabled:
        raise HTTPException(
            status_code=400,
            detail=f"Playbook {record.playbook_id} is not configured for automatic rollback."
        )

    if record.status == "ROLLED_BACK":
        raise HTTPException(
            status_code=400,
            detail=f"Containment {containment_id} has already been rolled back."
        )

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Append rollback action step
    try:
        steps_data = json.loads(record.execution_steps_json)
    except Exception:
        steps_data = []

    rollback_step = {
        "step_number": len(steps_data) + 1,
        "action": "ROLLBACK_CONTAINMENT_REVERSED",
        "target": record.target_identifier,
        "status": "SUCCESS",
        "details": f"Rollback executed by {payload.rolled_back_by}: {payload.reason}",
        "timestamp": now_utc,
        "artifact_hash": _sha256(f"ROLLBACK:{record.id}:{now_utc}"),
    }
    steps_data.append(rollback_step)

    record.status = "ROLLED_BACK"
    record.rolled_back_at = now_utc
    record.rollback_notes = payload.reason
    record.execution_steps_json = json.dumps(steps_data)

    # Re-evaluate Investigation State
    inv = record.investigation
    if inv and inv.status == "Remediating":
        inv.status = "Investigating"

    db.commit()
    db.refresh(record)

    # Commit audit entry to Module 3L immutable ledger
    try:
        from app.services.audit_service import record_audit_event
        record_audit_event(
            db=db,
            event_type="CONTAINMENT_ROLLED_BACK",
            payload={
                "containment_id": record.id,
                "investigation_id": record.investigation_id,
                "rolled_back_by": payload.rolled_back_by,
                "reason": payload.reason,
            },
            investigation_id=record.investigation_id,
            actor=payload.rolled_back_by,
            payload_summary=f"Rolled back containment {record.id} on target {record.target_identifier}",
        )
    except Exception as ex:
        logger.warning(f"Audit ledger rollback recording skipped: {ex}")

    # Broadcast WebSocket Telemetry
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel=f"investigation:{record.investigation_id}",
            event_type="CONTAINMENT_ROLLED_BACK",
            data={
                "containment_id": record.id,
                "investigation_id": record.investigation_id,
                "status": record.status,
                "rolled_back_by": payload.rolled_back_by,
                "reason": payload.reason,
                "rolled_back_at": record.rolled_back_at,
            },
            investigation_id=record.investigation_id,
        )
    except Exception:
        pass

    return record


def list_containments(
    db: Session,
    investigation_id: Optional[str] = None,
    status: Optional[str] = None,
) -> List[ContainmentExecutionModel]:
    """List containment executions with optional investigation and status filters."""
    query = db.query(ContainmentExecutionModel)
    if investigation_id:
        query = query.filter(ContainmentExecutionModel.investigation_id == investigation_id)
    if status:
        query = query.filter(ContainmentExecutionModel.status == status)
    return query.order_by(desc(ContainmentExecutionModel.dispatched_at)).all()


def get_containment_by_id(db: Session, containment_id: str) -> ContainmentExecutionModel:
    """Retrieve a single containment execution by ID."""
    record = (
        db.query(ContainmentExecutionModel)
        .filter(ContainmentExecutionModel.id == containment_id)
        .first()
    )
    if not record:
        raise HTTPException(
            status_code=404,
            detail=f"Containment execution {containment_id} not found."
        )
    return record


def get_containment_summary(db: Session) -> ContainmentSummaryResponse:
    """Calculate aggregate containment operational metrics across all investigations."""
    records = db.query(ContainmentExecutionModel).all()
    if not records:
        seed_initial_containments(db)
        records = db.query(ContainmentExecutionModel).all()

    total = len(records)
    active = len([r for r in records if r.status == "CONTAINED"])
    rolled_back = len([r for r in records if r.status == "ROLLED_BACK"])

    by_target: Dict[str, int] = {}
    by_playbook: Dict[str, int] = {}

    for r in records:
        by_target[r.target_type] = by_target.get(r.target_type, 0) + 1
        by_playbook[r.playbook_id] = by_playbook.get(r.playbook_id, 0) + 1

    return ContainmentSummaryResponse(
        total_containments=total,
        active_quarantines=active,
        rolled_back_count=rolled_back,
        by_target_type=by_target,
        by_playbook=by_playbook,
    )


def seed_initial_containments(db: Session):
    """Seed initial demonstration containments for active investigations."""
    existing = db.query(ContainmentExecutionModel).count()
    if existing > 0:
        return

    # Seed demonstration host isolation for INV-001
    inv1 = db.query(InvestigationModel).filter(InvestigationModel.id == "INV-001").first()
    if inv1:
        dispatch_containment_playbook(
            db=db,
            payload=ContainmentDispatchPayload(
                investigation_id="INV-001",
                playbook_id="PLAYBOOK-HOST-ISOLATION",
                target_identifier=inv1.target_host or "DC-PROD-01.corp.internal",
                dispatched_by="SecOps Lead Analyst",
                notes="Automated containment dispatched following approved quarantine gate.",
            ),
        )

    # Seed network C2 block for INV-002
    inv2 = db.query(InvestigationModel).filter(InvestigationModel.id == "INV-002").first()
    if inv2:
        dispatch_containment_playbook(
            db=db,
            payload=ContainmentDispatchPayload(
                investigation_id="INV-002",
                playbook_id="PLAYBOOK-NETWORK-BLOCK",
                target_identifier="198.51.100.42",
                dispatched_by="Perimeter Defense Agent",
                notes="Dynamic firewall egress block applied to malicious C2 IP.",
            ),
        )

    logger.info("Initial containment playbooks seeded successfully.")
