"""
Module 3L Test Suite — Cryptographic Immutable Audit Trail
Agentic SOC — Auditable AI Security Operations Center

Verifies:
1. Backend health check registers Module 3L Cryptographic Immutable Audit Trail & Merkle Engine
2. Initial audit ledger retrieval (GET /api/audit-trail)
3. Genesis block invariants (sequence 0, 64-zero prev_hash, GENESIS_BLOCK event type, digital seal)
4. Sequential SHA-256 hash chaining (every entry.prev_hash == predecessor.entry_hash)
5. Cryptographic chain integrity verification (GET /api/audit-trail/verify returns chain_valid=True)
6. Merkle root retrieval & format validation (GET /api/audit-trail/merkle-root)
7. Single entry lookup by unique identifier (GET /api/audit-trail/AUD-0000)
8. Filter audit entries by investigation_id (GET /api/audit-trail?investigation_id=INV-001)
9. Filter audit entries by event_type (GET /api/audit-trail?event_type=EVIDENCE_SEALED)
10. Sequence ordering validation (order=asc vs order=desc)
11. Cryptographic investigation sealing (POST /api/audit-trail/seal/INV-002 returns SEALED with Merkle root)
12. Investigation audit proof bundle retrieval (GET /api/audit-trail/bundle/INV-002)
13. Mathematical Merkle root determinism, sensitivity, and tree balancing
14. Tamper detection verification (payload mutation triggers chain failure and locates corrupted entry ID)
15. Security boundary & error handling (rejects nonexistent investigation sealing with HTTP 404, nonexistent audit ID with HTTP 404)
"""

import json
import urllib.request
import urllib.error
import sys

from app.database import SessionLocal
from app.models.audit_entry import AuditEntryModel
from app.services.audit_service import (
    compute_merkle_root,
    calculate_canonical_payload_hash,
    calculate_entry_hash,
    generate_digital_signature,
    verify_audit_trail_integrity,
    GENESIS_PREV_HASH,
)

BASE_URL = "http://127.0.0.1:8000"


def make_request(path: str, method: str = "GET", data: dict = None):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            return e.code, json.loads(content)
        except Exception:
            return e.code, {"error": content}


def run_tests():
    print("=" * 70)
    print("AGENTIC SOC — MODULE 3L CRYPTOGRAPHIC IMMUTABLE AUDIT TRAIL TESTS")
    print("=" * 70)

    # 1. Health check verification
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed with status: {status}"
    assert "audit_trail_module" in health, f"audit_trail_module missing from health check: {health}"
    assert "Module 3L" in health.get("audit_trail_module", ""), f"Module 3L text missing from health check: {health}"
    assert "SHA-256 Hash-Chained" in health.get("audit_ledger", ""), f"audit_ledger missing from health check: {health}"
    assert "Merkle Root" in health.get("merkle_tree_engine", ""), f"merkle_tree_engine missing from health check: {health}"
    print("[PASS] Check 01: Backend Health Check & Module 3L Registered")
    print(f"        -> Audit Trail Module: {health.get('audit_trail_module')}")
    print(f"        -> Audit Ledger: {health.get('audit_ledger')}")
    print(f"        -> Merkle Engine: {health.get('merkle_tree_engine')}")

    # 2. Initial Audit Ledger Listing
    status, entries = make_request("/api/audit-trail")
    assert status == 200, f"Failed to list audit trail: status {status}"
    assert isinstance(entries, list), f"Expected list of entries, got: {type(entries)}"
    assert len(entries) >= 7, f"Expected at least 7 seeded entries, got {len(entries)}"
    print(f"[PASS] Check 02: Initial Audit Ledger Listing ({len(entries)} entries returned)")

    # 3. Genesis Block Invariants
    status, genesis = make_request("/api/audit-trail/AUD-0000")
    assert status == 200, f"Failed to retrieve Genesis block: status {status}"
    assert genesis["id"] == "AUD-0000"
    assert genesis["sequence"] == 0
    assert genesis["prev_hash"] == GENESIS_PREV_HASH
    assert genesis["event_type"] == "GENESIS_BLOCK"
    assert genesis["actor"] == "SYSTEM_GENESIS"
    assert genesis["signature"].startswith("SIG-VERIFIED:")
    assert len(genesis["entry_hash"]) == 64
    print("[PASS] Check 03: Genesis Block Invariants Verified (AUD-0000, 64-zero prev_hash, valid seal)")

    # 4. Sequential SHA-256 Hash Chaining
    status, asc_entries = make_request("/api/audit-trail?order=asc")
    assert status == 200, f"Failed to list asc audit entries: {status}"
    assert len(asc_entries) >= 2, "Need at least 2 entries to verify chain link"

    for i in range(1, len(asc_entries)):
        curr = asc_entries[i]
        prev = asc_entries[i - 1]
        assert curr["sequence"] == prev["sequence"] + 1, f"Sequence gap between {prev['id']} and {curr['id']}"
        assert curr["prev_hash"] == prev["entry_hash"], (
            f"Broken chain link between {prev['id']} ({prev['entry_hash']}) and {curr['id']} ({curr['prev_hash']})"
        )
    print(f"[PASS] Check 04: Sequential SHA-256 Hash Chaining Verified across {len(asc_entries)} consecutive blocks")

    # 5. Cryptographic Chain Integrity Verification
    status, verify_data = make_request("/api/audit-trail/verify")
    assert status == 200, f"Verification endpoint failed: {status}"
    assert verify_data["chain_valid"] is True, f"Chain verification reported invalid: {verify_data}"
    assert verify_data["corrupted_entry_id"] is None
    assert verify_data["total_entries"] == len(asc_entries)
    assert len(verify_data["merkle_root"]) == 64
    print("[PASS] Check 05: Cryptographic Chain Integrity Verified (chain_valid=True, 0 corruptions)")
    print(f"        -> Details: {verify_data['details']}")
    print(f"        -> Merkle Root: {verify_data['merkle_root']}")

    # 6. Merkle Root Retrieval & Format
    status, merkle_data = make_request("/api/audit-trail/merkle-root")
    assert status == 200, f"Failed to get Merkle root: {status}"
    assert "merkle_root" in merkle_data
    assert len(merkle_data["merkle_root"]) == 64
    assert merkle_data["total_entries"] == len(asc_entries)
    assert merkle_data["merkle_root"] == verify_data["merkle_root"]
    print(f"[PASS] Check 06: Merkle Root Retrieval Validated ({merkle_data['merkle_root'][:16]}...)")

    # 7. Single Entry Lookup
    status, entry_0 = make_request("/api/audit-trail/AUD-0000")
    assert status == 200
    assert entry_0["id"] == "AUD-0000"
    print("[PASS] Check 07: Single Entry Lookup by Identifier (AUD-0000)")

    # 8. Filter Audit Entries by Investigation ID
    status, inv_entries = make_request("/api/audit-trail?investigation_id=INV-001")
    assert status == 200
    assert len(inv_entries) >= 1
    for e in inv_entries:
        assert e["investigation_id"] == "INV-001"
    print(f"[PASS] Check 08: Filter Audit Entries by Investigation ID ({len(inv_entries)} entries for INV-001)")

    # 9. Filter Audit Entries by Event Type
    status, ev_entries = make_request("/api/audit-trail?event_type=EVIDENCE_SEALED")
    assert status == 200
    assert len(ev_entries) >= 1
    for e in ev_entries:
        assert e["event_type"] == "EVIDENCE_SEALED"
    print(f"[PASS] Check 09: Filter Audit Entries by Event Type ({len(ev_entries)} EVIDENCE_SEALED entries)")

    # 10. Sequence Ordering Validation
    status, desc_entries = make_request("/api/audit-trail?order=desc")
    assert status == 200
    assert desc_entries[0]["sequence"] > desc_entries[-1]["sequence"]
    assert asc_entries[0]["sequence"] < asc_entries[-1]["sequence"]
    print("[PASS] Check 10: Sequence Ordering Validation (desc vs asc confirmed)")

    # 11. Cryptographic Investigation Sealing
    seal_payload = {
        "investigation_id": "INV-002",
        "signed_by": "Senior SOC Lead",
        "notes": "Module 3L Verification Test Seal",
    }
    status, seal_resp = make_request("/api/audit-trail/seal/INV-002", method="POST", data=seal_payload)
    assert status == 201, f"Failed to seal investigation: status {status}, {seal_resp}"
    assert seal_resp["investigation_id"] == "INV-002"
    assert seal_resp["status"] == "SEALED"
    assert len(seal_resp["merkle_root"]) == 64
    assert seal_resp["signature"].startswith("SIG-VERIFIED:")
    print(f"[PASS] Check 11: Cryptographic Investigation Sealing Executed ({seal_resp['audit_id']})")
    print(f"        -> Artifact Merkle Root: {seal_resp['merkle_root']}")

    # 12. Investigation Audit Proof Bundle Retrieval
    status, bundle = make_request("/api/audit-trail/bundle/INV-002")
    assert status == 200, f"Failed to get audit bundle: {status}"
    assert bundle["investigation_id"] == "INV-002"
    assert bundle["sealed"] is True
    assert bundle["seal_audit_id"] == seal_resp["audit_id"]
    assert bundle["merkle_root"] == seal_resp["merkle_root"]
    assert bundle["chain_verified"] is True
    print(f"[PASS] Check 12: Investigation Audit Proof Bundle Retrieved (Sealed={bundle['sealed']}, Merkle verified)")

    # 13. Mathematical Merkle Root Determinism & Sensitivity
    sample_hashes = [
        "11" * 32,
        "22" * 32,
        "33" * 32,
        "44" * 32,
    ]
    root_a = compute_merkle_root(sample_hashes)
    root_b = compute_merkle_root(sample_hashes)
    assert root_a == root_b, "Merkle root calculation must be deterministic"

    mutated_hashes = copy.deepcopy(sample_hashes)
    mutated_hashes[2] = "33" * 31 + "ff"
    root_mutated = compute_merkle_root(mutated_hashes)
    assert root_a != root_mutated, "Altering a single hash byte must alter the Merkle root"

    # Edge cases
    assert compute_merkle_root([]) == "0" * 64
    assert compute_merkle_root(["aa" * 32]) == "aa" * 32
    assert len(compute_merkle_root(["11" * 32, "22" * 32, "33" * 32])) == 64  # Odd length balancing
    print("[PASS] Check 13: Mathematical Merkle Root Determinism & Tree Balancing Verified")

    # 14. Tamper Detection Verification (Simulation in direct DB session)
    db = SessionLocal()
    try:
        # Inject an audit entry to tamper with
        tamper_target = db.query(AuditEntryModel).filter(AuditEntryModel.sequence == 1).first()
        original_hash = tamper_target.payload_hash

        # Tamper payload hash
        tamper_target.payload_hash = "deadbeef" * 8
        db.commit()

        tampered_result = verify_audit_trail_integrity(db)
        assert tampered_result.chain_valid is False, "Verification must detect tampered block payload"
        assert tampered_result.corrupted_entry_id == tamper_target.id, (
            f"Expected {tamper_target.id}, got {tampered_result.corrupted_entry_id}"
        )
        assert "Tampered block hash" in tampered_result.details

        # Restore original hash to restore clean ledger state
        tamper_target.payload_hash = original_hash
        db.commit()

        clean_result = verify_audit_trail_integrity(db)
        assert clean_result.chain_valid is True, "Verification should pass after restoring clean ledger"
    finally:
        db.close()
    print("[PASS] Check 14: Tamper Detection Verified (Corrupted entry accurately localized; clean state restored)")

    # 15. Security Boundary & Error Handling
    status, not_found_seal = make_request("/api/audit-trail/seal/INV-NONEXISTENT", method="POST")
    assert status == 404, f"Expected 404 for nonexistent investigation, got {status}"

    status, not_found_entry = make_request("/api/audit-trail/AUD-9999")
    assert status == 404, f"Expected 404 for nonexistent audit ID, got {status}"
    print("[PASS] Check 15: Security Boundary & Error Handling Validated (404 on invalid targets)")

    print("=" * 70)
    print("ALL 15/15 MODULE 3L CRYPTOGRAPHIC AUDIT TRAIL CHECKS PASSED PERFECTLY!")
    print("=" * 70)


if __name__ == "__main__":
    try:
        import copy
        run_tests()
    except Exception as e:
        print(f"\n[FAIL] Test suite aborted with error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)
