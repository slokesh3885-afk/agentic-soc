import re
import hashlib
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.evidence import EvidenceModel
from app.schemas.evidence import EvidenceCreate


def compute_content_hash(raw_output: str) -> str:
    """Deterministically compute SHA-256 hex digest of raw evidence output string."""
    return hashlib.sha256(raw_output.encode("utf-8")).hexdigest()


def generate_next_evidence_id(db: Session) -> str:
    """Generate sequential evidence ID (e.g. E-001, E-002) globally unique across all investigations."""
    records = db.query(EvidenceModel.id).all()
    max_num = 0
    pattern = re.compile(r"^E-(\d+)$")

    for (rec_id,) in records:
        match = pattern.match(rec_id)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num

    return f"E-{max_num + 1:03d}"


def create_evidence(db: Session, investigation_id: str, data: EvidenceCreate) -> EvidenceModel:
    """
    Append-only creation of evidence bound to an existing investigation.
    Computes SHA-256 hash and generates sequential ID autonomously.
    """
    # 1. Validate that the parent investigation exists
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot add evidence: Investigation '{investigation_id}' does not exist.",
        )

    # 2. Calculate SHA-256 content hash
    content_hash = compute_content_hash(data.raw_output)

    # 3. Generate sequential Evidence ID
    new_id = generate_next_evidence_id(db)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 4. Save evidence model
    model = EvidenceModel(
        id=new_id,
        investigation_id=investigation_id,
        evidence_type=data.evidence_type.value if hasattr(data.evidence_type, "value") else str(data.evidence_type),
        source=data.source,
        timestamp=data.timestamp or now_utc,
        query=data.query or "",
        raw_output=data.raw_output,
        content_hash=content_hash,
        status=data.status or "COLLECTED",
        created_at=now_utc,
    )

    db.add(model)

    # 5. Increment parent investigation's evidence_count
    current_count = db.query(EvidenceModel).filter(EvidenceModel.investigation_id == investigation_id).count()
    inv.evidence_count = current_count + 1

    db.commit()
    db.refresh(model)

    # Module 3K: Broadcast EVIDENCE_CREATED telemetry event
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel=f"investigation:{investigation_id}",
            event_type="EVIDENCE_CREATED",
            data={
                "evidence_id": model.id,
                "investigation_id": investigation_id,
                "evidence_type": model.evidence_type,
                "source": model.source,
                "content_hash": model.content_hash,
                "status": model.status,
                "timestamp": model.timestamp,
            },
            investigation_id=investigation_id,
        )
    except Exception:
        pass

    return model


def get_evidence_by_investigation(db: Session, investigation_id: str) -> List[EvidenceModel]:
    """Retrieve all evidence objects belonging to an existing investigation."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Investigation '{investigation_id}' does not exist.",
        )

    return db.query(EvidenceModel).filter(EvidenceModel.investigation_id == investigation_id).order_by(EvidenceModel.id.asc()).all()


def get_evidence_by_id(db: Session, evidence_id: str) -> Optional[EvidenceModel]:
    """Retrieve a single evidence object by ID."""
    return db.query(EvidenceModel).filter(EvidenceModel.id == evidence_id).first()


def verify_evidence_integrity(db: Session, evidence_id: str) -> Dict[str, Any]:
    """
    Recalculates the SHA-256 hash from raw_output and compares it with content_hash.
    Ensures mathematical proof of evidence immutability.
    """
    model = get_evidence_by_id(db, evidence_id)
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Evidence '{evidence_id}' does not exist.",
        )

    recalculated = compute_content_hash(model.raw_output)
    is_valid = recalculated == model.content_hash

    return {
        "evidence_id": evidence_id,
        "valid": is_valid,
        "content_hash": model.content_hash,
        "recalculated_hash": recalculated,
        "timestamp_verified": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    }


def seed_initial_evidence(db: Session) -> None:
    """
    Seed initial evidence items into database if empty.
    Guarantees E-001 and E-002 exist for INV-012 as required by specification.
    """
    existing_count = db.query(EvidenceModel).count()
    if existing_count > 0:
        return

    # Ensure parent investigation INV-012 exists in database
    inv_012 = db.query(InvestigationModel).filter(InvestigationModel.id == "INV-012").first()
    if not inv_012:
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        inv_012 = InvestigationModel(
            id="INV-012",
            alert_name="Unusual Parent Process Execution",
            target_host="PC-DB-TEST",
            severity="High",
            status="Investigating",
            trust_score=93,
            evidence_count=2,
            event_timestamp="2026-09-27 16:00:00 UTC",
            created_at=now_utc,
            description="powershell.exe executed from an unusual parent process on host PC-DB-TEST.",
            assigned_agent="Host Triage Agent",
            mitre_technique="T1059.001 (Command and Scripting Interpreter: PowerShell)",
            evidence_corroboration="[]",
        )
        db.add(inv_012)
        db.commit()

    # Required evidence objects for INV-012
    evidence_seeds = [
        {
            "id": "E-001",
            "investigation_id": "INV-012",
            "evidence_type": "SIEM_LOG",
            "source": "Mock SIEM",
            "timestamp": "2026-09-27 16:05:00 UTC",
            "query": "host=PC-DB-TEST powershell",
            "raw_output": "powershell.exe executed from an unusual parent process.",
            "status": "VERIFIED",
        },
        {
            "id": "E-002",
            "investigation_id": "INV-012",
            "evidence_type": "PROCESS_EVENT",
            "source": "Mock EDR",
            "timestamp": "2026-09-27 16:07:30 UTC",
            "query": "host=PC-DB-TEST process_tree",
            "raw_output": "powershell.exe spawned by unknown_process.exe.",
            "status": "VERIFIED",
        },
    ]

    for item in evidence_seeds:
        content_hash = compute_content_hash(item["raw_output"])
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        model = EvidenceModel(
            id=item["id"],
            investigation_id=item["investigation_id"],
            evidence_type=item["evidence_type"],
            source=item["source"],
            timestamp=item["timestamp"],
            query=item["query"],
            raw_output=item["raw_output"],
            content_hash=content_hash,
            status=item["status"],
            created_at=now_utc,
        )
        db.add(model)

    # Also seed initial evidence for INV-001 and INV-002 so analysts see evidence across multiple cases
    inv_001 = db.query(InvestigationModel).filter(InvestigationModel.id == "INV-001").first()
    if inv_001:
        e003_raw = "Event ID 1: Process Create powershell.exe -Enc JABvAD0... Parent: SYSTEM_UPDATE_TASK.exe (PID 4812)"
        db.add(EvidenceModel(
            id="E-003",
            investigation_id="INV-001",
            evidence_type="EDR_EVENT",
            source="CrowdStrike Falcon",
            timestamp="2026-09-27 13:25:12 UTC",
            query="EventID=1 AND CommandLine=*powershell*",
            raw_output=e003_raw,
            content_hash=compute_content_hash(e003_raw),
            status="VERIFIED",
            created_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        ))

    db.commit()
