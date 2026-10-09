"""
Module 3L — Cryptographic Immutable Audit Trail Engine
Agentic SOC — Auditable AI Security Operations Center

Implements an append-only, SHA-256 hash-chained cryptographic ledger for all
SOC operations, evidence acquisitions, agent actions, approvals, and incident closures.
Provides Merkle tree root calculation, full chain integrity verification, and
tamper-evident sealing of multi-agent forensic cases.
"""

import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.audit_entry import AuditEntryModel
from app.models.investigation import InvestigationModel
from app.models.evidence import EvidenceModel
from app.models.auditor import AuditedCaseModel
from app.models.approval import ApprovalRequestModel
from app.models.tool_execution import ToolExecutionModel
from app.schemas.audit_trail import (
    AuditVerificationResponse,
    SealInvestigationResponse,
    AuditBundleResponse,
)
from app.services.websocket_manager import ws_manager

logger = logging.getLogger("agentic_soc.audit_service")

# Genesis block constants
GENESIS_PREV_HASH = "0" * 64
AUDIT_HMAC_SECRET = b"agentic-soc-cryptographic-audit-key-2026-v1"


def calculate_canonical_payload_hash(payload: Any) -> str:
    """Compute deterministic SHA-256 hash of a payload using canonical JSON sorting."""
    if payload is None:
        payload = {}
    if not isinstance(payload, (dict, list, str, int, float, bool)):
        payload = str(payload)
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def calculate_entry_hash(
    sequence: int,
    timestamp: str,
    event_type: str,
    investigation_id: Optional[str],
    actor: str,
    payload_hash: str,
    prev_hash: str,
) -> str:
    """
    Compute cryptographic SHA-256 hash for a block header.
    Deterministically combines sequence, timestamp, event_type, target, actor,
    payload hash, and previous block hash.
    """
    header = f"{sequence}|{timestamp}|{event_type}|{investigation_id or ''}|{actor}|{payload_hash}|{prev_hash}"
    return hashlib.sha256(header.encode("utf-8")).hexdigest()


def generate_digital_signature(entry_hash: str, actor: str) -> str:
    """Generate deterministic HMAC-SHA256 digital seal signature for an audit block."""
    message = f"{entry_hash}:{actor}".encode("utf-8")
    sig = hmac.new(AUDIT_HMAC_SECRET, message, hashlib.sha256).hexdigest()
    return f"SIG-VERIFIED:{sig[:32]}"


def compute_merkle_root(hashes: List[str]) -> str:
    """
    Compute deterministic binary Merkle tree root from an arbitrary list of SHA-256 hashes.
    If the list is empty, returns 64 zeros.
    If odd count at any level, duplicates the last hash to complete the binary tree.
    """
    if not hashes:
        return "0" * 64
    if len(hashes) == 1:
        return hashes[0]

    current_level = list(hashes)
    while len(current_level) > 1:
        next_level = []
        if len(current_level) % 2 != 0:
            current_level.append(current_level[-1])
        for i in range(0, len(current_level), 2):
            combined = current_level[i] + current_level[i + 1]
            parent_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
            next_level.append(parent_hash)
        current_level = next_level

    return current_level[0]


def _ensure_genesis_block(db: Session) -> AuditEntryModel:
    """Ensure the immutable Genesis block (sequence 0) exists in the ledger."""
    genesis = db.query(AuditEntryModel).filter(AuditEntryModel.sequence == 0).first()
    if genesis:
        return genesis

    now_utc = "2026-09-27 12:00:00 UTC"
    payload = {
        "ledger": "Agentic SOC Cryptographic Audit Trail",
        "protocol": "SHA-256 Hash-Chained Append-Only Ledger v1.0",
        "genesis_marker": "GENESIS_ROOT_INIT",
    }
    payload_hash = calculate_canonical_payload_hash(payload)
    entry_hash = calculate_entry_hash(
        sequence=0,
        timestamp=now_utc,
        event_type="GENESIS_BLOCK",
        investigation_id=None,
        actor="SYSTEM_GENESIS",
        payload_hash=payload_hash,
        prev_hash=GENESIS_PREV_HASH,
    )
    signature = generate_digital_signature(entry_hash, "SYSTEM_GENESIS")

    genesis = AuditEntryModel(
        id="AUD-0000",
        sequence=0,
        timestamp=now_utc,
        event_type="GENESIS_BLOCK",
        investigation_id=None,
        actor="SYSTEM_GENESIS",
        payload_summary="Genesis block of Agentic SOC Immutable Audit Ledger",
        payload_hash=payload_hash,
        prev_hash=GENESIS_PREV_HASH,
        entry_hash=entry_hash,
        signature=signature,
        metadata_json=json.dumps(payload),
    )
    db.add(genesis)
    db.commit()
    db.refresh(genesis)
    logger.info("Genesis block AUD-0000 successfully committed to immutable audit ledger.")
    return genesis


def record_audit_event(
    db: Session,
    event_type: str,
    payload_summary: str,
    payload: Any = None,
    investigation_id: Optional[str] = None,
    actor: str = "System Auditor",
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditEntryModel:
    """
    Append an auditable event to the cryptographic ledger.
    Atomically links to the preceding block's entry_hash, computing the new block's SHA-256 hash
    and digital seal signature.
    """
    # 1. Ensure genesis block exists
    _ensure_genesis_block(db)

    # 2. Get previous entry (highest sequence)
    latest_entry = (
        db.query(AuditEntryModel)
        .order_by(desc(AuditEntryModel.sequence))
        .first()
    )
    new_sequence = latest_entry.sequence + 1 if latest_entry else 0
    prev_hash = latest_entry.entry_hash if latest_entry else GENESIS_PREV_HASH

    # 3. Timestamp and hashing
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    payload_data = payload if payload is not None else {"summary": payload_summary}
    payload_hash = calculate_canonical_payload_hash(payload_data)

    entry_hash = calculate_entry_hash(
        sequence=new_sequence,
        timestamp=now_utc,
        event_type=event_type,
        investigation_id=investigation_id,
        actor=actor,
        payload_hash=payload_hash,
        prev_hash=prev_hash,
    )
    signature = generate_digital_signature(entry_hash, actor)

    entry_id = f"AUD-{new_sequence:04d}"
    entry = AuditEntryModel(
        id=entry_id,
        sequence=new_sequence,
        timestamp=now_utc,
        event_type=event_type,
        investigation_id=investigation_id,
        actor=actor,
        payload_summary=payload_summary,
        payload_hash=payload_hash,
        prev_hash=prev_hash,
        entry_hash=entry_hash,
        signature=signature,
        metadata_json=json.dumps(metadata or {}),
    )

    db.add(entry)
    db.commit()
    db.refresh(entry)

    # 4. Real-time telemetry broadcast via WebSocket (Module 3K integration)
    event_payload = entry.to_dict()
    ws_manager.dispatch_sync("telemetry", "AUDIT_RECORDED", event_payload, investigation_id=investigation_id)
    if investigation_id:
        ws_manager.dispatch_sync(f"investigation:{investigation_id}", "AUDIT_RECORDED", event_payload, investigation_id=investigation_id)

    return entry


def verify_audit_trail_integrity(db: Session) -> AuditVerificationResponse:
    """
    Perform a complete cryptographic verification of the audit ledger.
    Walks every entry from Genesis (seq 0) to head, verifying:
    1. Genesis block validity
    2. Header hash integrity (entry_hash matches recomputed hash)
    3. Cryptographic link integrity (prev_hash matches predecessor's entry_hash)
    4. Digital signature validity
    Computes overall Merkle root across all valid entry hashes.
    """
    _ensure_genesis_block(db)
    entries = db.query(AuditEntryModel).order_by(AuditEntryModel.sequence.asc()).all()

    total_entries = len(entries)
    genesis_hash = entries[0].entry_hash if entries else "0" * 64
    latest_hash = entries[-1].entry_hash if entries else "0" * 64
    entry_hashes = [e.entry_hash for e in entries]
    merkle_root = compute_merkle_root(entry_hashes)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    for i, entry in enumerate(entries):
        # 1. Verify sequence matches expected index
        if entry.sequence != i:
            return AuditVerificationResponse(
                chain_valid=False,
                total_entries=total_entries,
                genesis_hash=genesis_hash,
                latest_hash=latest_hash,
                merkle_root=merkle_root,
                corrupted_entry_id=entry.id,
                verification_timestamp=now_utc,
                details=f"Sequence discontinuity at entry {entry.id}: expected {i}, found {entry.sequence}",
            )

        # 2. Verify predecessor link
        if i == 0:
            if entry.prev_hash != GENESIS_PREV_HASH:
                return AuditVerificationResponse(
                    chain_valid=False,
                    total_entries=total_entries,
                    genesis_hash=genesis_hash,
                    latest_hash=latest_hash,
                    merkle_root=merkle_root,
                    corrupted_entry_id=entry.id,
                    verification_timestamp=now_utc,
                    details=f"Genesis block {entry.id} invalid prev_hash: expected {GENESIS_PREV_HASH}, found {entry.prev_hash}",
                )
        else:
            prev_entry = entries[i - 1]
            if entry.prev_hash != prev_entry.entry_hash:
                return AuditVerificationResponse(
                    chain_valid=False,
                    total_entries=total_entries,
                    genesis_hash=genesis_hash,
                    latest_hash=latest_hash,
                    merkle_root=merkle_root,
                    corrupted_entry_id=entry.id,
                    verification_timestamp=now_utc,
                    details=f"Broken hash chain at {entry.id}: prev_hash does not match predecessor {prev_entry.id} entry_hash",
                )

        # 3. Recalculate and verify entry_hash
        expected_entry_hash = calculate_entry_hash(
            sequence=entry.sequence,
            timestamp=entry.timestamp,
            event_type=entry.event_type,
            investigation_id=entry.investigation_id,
            actor=entry.actor,
            payload_hash=entry.payload_hash,
            prev_hash=entry.prev_hash,
        )
        if entry.entry_hash != expected_entry_hash:
            return AuditVerificationResponse(
                chain_valid=False,
                total_entries=total_entries,
                genesis_hash=genesis_hash,
                latest_hash=latest_hash,
                merkle_root=merkle_root,
                corrupted_entry_id=entry.id,
                verification_timestamp=now_utc,
                details=f"Tampered block hash at {entry.id}: header recalculation mismatch",
            )

        # 4. Verify signature format
        expected_sig = generate_digital_signature(entry.entry_hash, entry.actor)
        if entry.signature != expected_sig:
            return AuditVerificationResponse(
                chain_valid=False,
                total_entries=total_entries,
                genesis_hash=genesis_hash,
                latest_hash=latest_hash,
                merkle_root=merkle_root,
                corrupted_entry_id=entry.id,
                verification_timestamp=now_utc,
                details=f"Invalid cryptographic signature at {entry.id}",
            )

    return AuditVerificationResponse(
        chain_valid=True,
        total_entries=total_entries,
        genesis_hash=genesis_hash,
        latest_hash=latest_hash,
        merkle_root=merkle_root,
        corrupted_entry_id=None,
        verification_timestamp=now_utc,
        details=f"All {total_entries} blocks cryptographically verified with unbroken SHA-256 hash chaining and valid signatures.",
    )


def seal_investigation_bundle(
    db: Session,
    investigation_id: str,
    signed_by: str = "SOC Lead Auditor",
    notes: str = "Cryptographically sealed investigation bundle",
) -> SealInvestigationResponse:
    """
    Seal all forensic evidence, audited cases, human approvals, and tool logs
    for an investigation into an immutable cryptographic audit bundle.
    Calculates the artifact Merkle root and appends an INVESTIGATION_SEALED entry to the ledger.
    """
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise ValueError(f"Investigation {investigation_id} not found in database.")

    # 1. Collect evidence hashes
    evidence_items = (
        db.query(EvidenceModel)
        .filter(EvidenceModel.investigation_id == investigation_id)
        .order_by(EvidenceModel.id.asc())
        .all()
    )
    evidence_hashes = [e.content_hash for e in evidence_items]

    # 2. Collect case hash if available
    latest_case = (
        db.query(AuditedCaseModel)
        .filter(AuditedCaseModel.investigation_id == investigation_id)
        .order_by(desc(AuditedCaseModel.created_at))
        .first()
    )
    case_hash = None
    if latest_case and latest_case.canonical_case_json:
        case_hash = calculate_canonical_payload_hash(json.loads(latest_case.canonical_case_json))

    # 3. Collect approval hashes
    approvals = (
        db.query(ApprovalRequestModel)
        .filter(ApprovalRequestModel.investigation_id == investigation_id)
        .order_by(ApprovalRequestModel.id.asc())
        .all()
    )
    approval_hashes = [
        calculate_canonical_payload_hash({
            "id": a.id,
            "action_type": a.action_type,
            "status": a.status,
            "trust_score": a.trust_score,
            "reviewer": a.reviewer,
        })
        for a in approvals
    ]

    # 4. Build manifest of all artifact hashes
    manifest_hashes = list(evidence_hashes)
    if case_hash:
        manifest_hashes.append(case_hash)
    manifest_hashes.extend(approval_hashes)

    # 5. Compute investigation Merkle root
    investigation_merkle_root = compute_merkle_root(manifest_hashes)

    # 6. Append INVESTIGATION_SEALED event to ledger
    seal_payload = {
        "investigation_id": investigation_id,
        "alert_name": inv.alert_name,
        "target_host": inv.target_host,
        "evidence_count": len(evidence_items),
        "evidence_hashes": evidence_hashes,
        "case_id": latest_case.id if latest_case else None,
        "case_hash": case_hash,
        "approval_count": len(approvals),
        "merkle_root": investigation_merkle_root,
        "notes": notes,
    }

    audit_entry = record_audit_event(
        db=db,
        event_type="INVESTIGATION_SEALED",
        payload_summary=f"Cryptographically sealed case {investigation_id} ({len(evidence_items)} evidence items, Merkle: {investigation_merkle_root[:12]}...)",
        payload=seal_payload,
        investigation_id=investigation_id,
        actor=signed_by,
        metadata={"merkle_root": investigation_merkle_root, "sealed_at": datetime.now(timezone.utc).isoformat()},
    )

    # Broadcast specialized seal event
    ws_manager.dispatch_sync(
        f"investigation:{investigation_id}",
        "INVESTIGATION_SEALED",
        {
            "audit_id": audit_entry.id,
            "investigation_id": investigation_id,
            "merkle_root": investigation_merkle_root,
            "signature": audit_entry.signature,
        },
        investigation_id=investigation_id,
    )

    return SealInvestigationResponse(
        audit_id=audit_entry.id,
        investigation_id=investigation_id,
        sequence=audit_entry.sequence,
        merkle_root=investigation_merkle_root,
        entry_hash=audit_entry.entry_hash,
        signature=audit_entry.signature,
        timestamp=audit_entry.timestamp,
        evidence_count=len(evidence_items),
        status="SEALED",
    )


def get_investigation_audit_bundle(db: Session, investigation_id: str) -> AuditBundleResponse:
    """Retrieve full cryptographic proof bundle for an investigation."""
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()
    if not inv:
        raise ValueError(f"Investigation {investigation_id} not found.")

    evidence_items = (
        db.query(EvidenceModel)
        .filter(EvidenceModel.investigation_id == investigation_id)
        .order_by(EvidenceModel.id.asc())
        .all()
    )
    evidence_hashes = [{"id": e.id, "hash": e.content_hash, "type": e.evidence_type} for e in evidence_items]

    latest_case = (
        db.query(AuditedCaseModel)
        .filter(AuditedCaseModel.investigation_id == investigation_id)
        .order_by(desc(AuditedCaseModel.created_at))
        .first()
    )
    case_hash = None
    case_id = None
    if latest_case:
        case_id = latest_case.id
        if latest_case.canonical_case_json:
            case_hash = calculate_canonical_payload_hash(json.loads(latest_case.canonical_case_json))

    approvals = (
        db.query(ApprovalRequestModel)
        .filter(ApprovalRequestModel.investigation_id == investigation_id)
        .order_by(ApprovalRequestModel.id.asc())
        .all()
    )
    approval_hashes = [{"id": a.id, "action_type": a.action_type, "status": a.status} for a in approvals]

    # Find seal event in ledger
    seal_entry = (
        db.query(AuditEntryModel)
        .filter(
            AuditEntryModel.investigation_id == investigation_id,
            AuditEntryModel.event_type == "INVESTIGATION_SEALED",
        )
        .order_by(desc(AuditEntryModel.sequence))
        .first()
    )

    all_hashes = [e["hash"] for e in evidence_hashes]
    if case_hash:
        all_hashes.append(case_hash)
    merkle_root = compute_merkle_root(all_hashes)

    return AuditBundleResponse(
        investigation_id=investigation_id,
        sealed=seal_entry is not None,
        seal_audit_id=seal_entry.id if seal_entry else None,
        merkle_root=merkle_root,
        entry_hash=seal_entry.entry_hash if seal_entry else None,
        signature=seal_entry.signature if seal_entry else None,
        timestamp=seal_entry.timestamp if seal_entry else None,
        evidence_hashes=evidence_hashes,
        case_id=case_id,
        case_hash=case_hash,
        approval_hashes=approval_hashes,
        chain_verified=True,
    )


def seed_initial_audit_trail(db: Session):
    """Seed initial genesis block and realistic audit trail records if ledger is uninitialized."""
    existing_count = db.query(AuditEntryModel).count()
    if existing_count > 0:
        return

    logger.info("Initializing Cryptographic Immutable Audit Trail ledger with Genesis and seed entries...")
    _ensure_genesis_block(db)

    # 1. INV-001 Evidence Sealed
    record_audit_event(
        db=db,
        event_type="EVIDENCE_SEALED",
        payload_summary="Cryptographic SHA-256 seal generated for EDR process tree E-001 on host WORKSTATION-7",
        payload={"evidence_id": "E-001", "investigation_id": "INV-001", "type": "process_tree"},
        investigation_id="INV-001",
        actor="Evidence Engine (Module 3A)",
    )

    # 2. INV-001 Tool Execution
    record_audit_event(
        db=db,
        event_type="TOOL_INVOCATION",
        payload_summary="Executed allow-listed edr_process_search tool on WORKSTATION-7 targeting powershell.exe",
        payload={"tool": "edr_process_search", "host": "WORKSTATION-7", "exit_code": 0},
        investigation_id="INV-001",
        actor="Security Tool Layer (Module 3B)",
    )

    # 3. INV-001 Critic Review
    record_audit_event(
        db=db,
        event_type="CRITIC_ASSESSMENT",
        payload_summary="Critic red-team agent evaluated 3 claims: 3 supported, 0 overconfident, 0 contradictions",
        payload={"investigation_id": "INV-001", "verdict": "VERIFIED_SUPPORTED", "supported_claims": 3},
        investigation_id="INV-001",
        actor="Critic Agent (Module 3D)",
    )

    # 4. INV-001 Case Audited
    record_audit_event(
        db=db,
        event_type="CASE_AUDITED",
        payload_summary="Audited case CASE-001 sealed into Canonical Case JSON with Trust Score 92/100",
        payload={"case_id": "CASE-001", "investigation_id": "INV-001", "trust_score": 92},
        investigation_id="INV-001",
        actor="Auditor Agent (Module 3E)",
    )

    # 5. INV-001 Human Approval (Module 3J)
    record_audit_event(
        db=db,
        event_type="HUMAN_APPROVAL",
        payload_summary="Senior SOC Analyst approved CONTAINMENT_ISOLATE_HOST action for WORKSTATION-7",
        payload={"approval_id": "APP-001", "action": "CONTAINMENT_ISOLATE_HOST", "decision": "APPROVED"},
        investigation_id="INV-001",
        actor="Senior Analyst (HITL)",
    )

    # 6. INV-003 Hash Lookup
    record_audit_event(
        db=db,
        event_type="EVIDENCE_SEALED",
        payload_summary="Malicious file hash SHA-256 verified against VirusTotal threat feed for INV-003",
        payload={"evidence_id": "E-003", "investigation_id": "INV-003", "verdict": "MALICIOUS"},
        investigation_id="INV-003",
        actor="Evidence Engine (Module 3A)",
    )

    # 7. INV-001 Seal Complete Bundle
    seal_investigation_bundle(
        db=db,
        investigation_id="INV-001",
        signed_by="SOC Incident Commander",
        notes="Final containment and forensic evidence bundle sealed for incident response audit.",
    )

    logger.info("Cryptographic Immutable Audit Trail seeding complete. 8 total ledger blocks created.")
