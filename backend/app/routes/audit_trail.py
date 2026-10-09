"""
Module 3L — Cryptographic Immutable Audit Trail Routes
Agentic SOC — Auditable AI Security Operations Center

API endpoints for inspecting the append-only SHA-256 hash-chained audit ledger,
performing cryptographic integrity verification, calculating Merkle roots,
and sealing multi-agent investigation bundles.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from sqlalchemy import desc, asc

from app.database import get_db
from app.models.audit_entry import AuditEntryModel
from app.schemas.audit_trail import (
    AuditEntrySchema,
    AuditVerificationResponse,
    SealInvestigationRequest,
    SealInvestigationResponse,
    AuditBundleResponse,
)
from app.services.audit_service import (
    verify_audit_trail_integrity,
    seal_investigation_bundle,
    get_investigation_audit_bundle,
    compute_merkle_root,
    _ensure_genesis_block,
)

router = APIRouter(prefix="/audit-trail", tags=["audit_trail"])


@router.get(
    "",
    response_model=List[AuditEntrySchema],
    summary="List Cryptographic Audit Ledger Entries",
    description="Retrieve paginated, cryptographically chained audit blocks. Supports filtering by investigation ID and event category.",
)
def list_audit_entries(
    investigation_id: Optional[str] = Query(None, description="Filter by linked investigation ID (e.g. INV-001)"),
    event_type: Optional[str] = Query(None, description="Filter by event type (e.g. EVIDENCE_SEALED, INVESTIGATION_SEALED)"),
    order: str = Query("desc", pattern="^(asc|desc)$", description="Sort order by sequence: 'desc' (newest first) or 'asc' (chronological)"),
    limit: int = Query(500, ge=1, le=2000, description="Maximum number of entries to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    db: Session = Depends(get_db),
):
    _ensure_genesis_block(db)
    query = db.query(AuditEntryModel)

    if investigation_id:
        query = query.filter(AuditEntryModel.investigation_id == investigation_id)
    if event_type:
        query = query.filter(AuditEntryModel.event_type == event_type)

    if order == "asc":
        query = query.order_by(asc(AuditEntryModel.sequence))
    else:
        query = query.order_by(desc(AuditEntryModel.sequence))

    entries = query.offset(offset).limit(limit).all()
    return entries


@router.get(
    "/verify",
    response_model=AuditVerificationResponse,
    summary="Verify Cryptographic Chain Integrity",
    description="Perform end-to-end mathematical verification of the entire SHA-256 hash chain from Genesis block to head. Detects any tampered block or broken link.",
)
def verify_ledger(db: Session = Depends(get_db)):
    result = verify_audit_trail_integrity(db)
    return result


@router.get(
    "/merkle-root",
    summary="Get Current Ledger Merkle Root",
    description="Returns the binary Merkle root calculated over all entry hashes in the immutable ledger.",
)
def get_merkle_root(db: Session = Depends(get_db)):
    _ensure_genesis_block(db)
    entries = db.query(AuditEntryModel).order_by(AuditEntryModel.sequence.asc()).all()
    hashes = [e.entry_hash for e in entries]
    root = compute_merkle_root(hashes)
    latest_hash = entries[-1].entry_hash if entries else "0" * 64
    return {
        "merkle_root": root,
        "total_entries": len(entries),
        "latest_hash": latest_hash,
        "genesis_hash": entries[0].entry_hash if entries else "0" * 64,
    }


@router.post(
    "/seal/{investigation_id}",
    response_model=SealInvestigationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Cryptographically Seal Investigation Bundle",
    description="Calculates a Merkle root over all evidence, cases, and human approvals for an investigation and commits an INVESTIGATION_SEALED block to the immutable ledger.",
)
def seal_investigation(
    investigation_id: str,
    payload: Optional[SealInvestigationRequest] = None,
    db: Session = Depends(get_db),
):
    signed_by = payload.signed_by if payload and payload.signed_by else "SOC Lead Auditor"
    notes = payload.notes if payload and payload.notes else "Cryptographically sealed investigation bundle"

    try:
        response = seal_investigation_bundle(
            db=db,
            investigation_id=investigation_id,
            signed_by=signed_by,
            notes=notes,
        )
        return response
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to seal investigation: {str(e)}")


@router.get(
    "/bundle/{investigation_id}",
    response_model=AuditBundleResponse,
    summary="Get Investigation Audit Proof Bundle",
    description="Retrieve the complete cryptographic proof manifest, artifact hashes, and seal status for an investigation.",
)
def get_audit_bundle(
    investigation_id: str,
    db: Session = Depends(get_db),
):
    try:
        bundle = get_investigation_audit_bundle(db, investigation_id)
        return bundle
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))


@router.get(
    "/{audit_id}",
    response_model=AuditEntrySchema,
    summary="Get Single Audit Entry by ID",
    description="Retrieve a specific audit entry block by its unique identifier (e.g. AUD-0001).",
)
def get_audit_entry(
    audit_id: str,
    db: Session = Depends(get_db),
):
    entry = db.query(AuditEntryModel).filter(AuditEntryModel.id == audit_id).first()
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Audit entry {audit_id} not found.")
    return entry
