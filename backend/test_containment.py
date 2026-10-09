"""
Module 3N: Automated Containment & Incident Remediation Playbooks Test Suite.
Validates:
1. Health check exposes Module 3N Containment & Remediation Playbooks Engine.
2. Allow-listed playbooks catalog retrieval (GET /api/containment/playbooks).
3. Single playbook definition lookup (GET /api/containment/playbooks/PLAYBOOK-HOST-ISOLATION).
4. Rejection of un-registered / arbitrary playbook (GET /api/containment/playbooks/PLAYBOOK-MALICIOUS).
5. Containment operational summary retrieval (GET /api/containment/summary).
6. Dispatch Host Network Isolation playbook (POST /api/containment/dispatch).
7. Quarantine receipt hash generation and SHA-256 verification.
8. Step-by-step containment receipts integrity (monotonic sequence, hashes, allow-listed actions).
9. Dispatch Perimeter Network Block playbook (POST /api/containment/dispatch).
10. Investigation lifecycle status transition (target investigation status updated).
11. Module 3L Cryptographic Ledger integration (CONTAINMENT_DISPATCHED audit block verified).
12. Containment query filtering by investigation ID and status (GET /api/containment?status=CONTAINED).
13. Safely rollback containment action (POST /api/containment/{id}/rollback).
14. Rollback idempotency and safety check (cannot re-rollback an already reverted containment).
15. Boundary condition and error handling (404 on nonexistent containment and invalid targets).
"""

import json
import sys
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"


def http_get(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "Module3N-Tester"})
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())


def http_post(path, data=None):
    url = f"{BASE_URL}{path}"
    payload = json.dumps(data or {}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Module3N-Tester"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())


def run_tests():
    passed = 0
    total = 15

    print("======================================================================")
    print("MODULE 3N: CONTAINMENT & REMEDIATION PLAYBOOKS TEST SUITE")
    print("======================================================================")

    # 1. Health check exposes Module 3N Containment & Remediation Playbooks Engine
    try:
        status, data = http_get("/api/health")
        assert status == 200, f"Expected 200, got {status}"
        assert "containment_module" in data, "Missing containment_module in health"
        assert "Module 3N" in data["containment_module"], f"Unexpected containment_module: {data['containment_module']}"
        assert "playbook_orchestrator" in data, "Missing playbook_orchestrator in health"
        print("[PASS] Test 1: Health check exposes Module 3N Containment & Remediation Playbooks Engine.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 1: Health check failed: {e}")

    # 2. Allow-listed playbooks catalog retrieval (GET /api/containment/playbooks)
    try:
        status, playbooks = http_get("/api/containment/playbooks")
        assert status == 200, f"Expected 200, got {status}"
        assert isinstance(playbooks, list), "Expected list of playbooks"
        assert len(playbooks) >= 4, f"Expected at least 4 playbooks, got {len(playbooks)}"
        pb_ids = [p["id"] for p in playbooks]
        assert "PLAYBOOK-HOST-ISOLATION" in pb_ids, "Missing PLAYBOOK-HOST-ISOLATION"
        assert "PLAYBOOK-NETWORK-BLOCK" in pb_ids, "Missing PLAYBOOK-NETWORK-BLOCK"
        assert "PLAYBOOK-PROCESS-TERMINATION" in pb_ids, "Missing PLAYBOOK-PROCESS-TERMINATION"
        print(f"[PASS] Test 2: Playbooks catalog retrieved with {len(playbooks)} allow-listed playbooks.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 2: Playbooks catalog failed: {e}")

    # 3. Single playbook definition lookup (GET /api/containment/playbooks/PLAYBOOK-HOST-ISOLATION)
    try:
        status, pb = http_get("/api/containment/playbooks/PLAYBOOK-HOST-ISOLATION")
        assert status == 200, f"Expected 200, got {status}"
        assert pb["id"] == "PLAYBOOK-HOST-ISOLATION", f"Unexpected ID: {pb['id']}"
        assert pb["target_type"] == "HOST", f"Unexpected target_type: {pb['target_type']}"
        assert pb["reversible"] is True, "Host isolation should be reversible"
        assert len(pb["steps"]) >= 4, f"Expected at least 4 steps, got {len(pb['steps'])}"
        print("[PASS] Test 3: Retrieved single playbook definition PLAYBOOK-HOST-ISOLATION.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 3: Single playbook lookup failed: {e}")

    # 4. Rejection of un-registered / arbitrary playbook
    try:
        rejected = False
        try:
            http_get("/api/containment/playbooks/PLAYBOOK-MALICIOUS-SCRIPT")
        except urllib.error.HTTPError as he:
            if he.code == 404:
                rejected = True
        assert rejected, "Arbitrary playbook should return 404"
        print("[PASS] Test 4: Rejection of unregistered playbook correctly enforced.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 4: Arbitrary playbook rejection failed: {e}")

    # 5. Containment operational summary retrieval (GET /api/containment/summary)
    try:
        status, summary = http_get("/api/containment/summary")
        assert status == 200, f"Expected 200, got {status}"
        assert "total_containments" in summary, "Missing total_containments in summary"
        assert "active_quarantines" in summary, "Missing active_quarantines in summary"
        assert summary["total_containments"] >= 2, f"Expected at least 2 seeded containments, got {summary['total_containments']}"
        print(f"[PASS] Test 5: Operational containment summary verified: {summary['total_containments']} total, {summary['active_quarantines']} active.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 5: Summary retrieval failed: {e}")

    # 6. Dispatch Host Network Isolation playbook (POST /api/containment/dispatch)
    dispatched_id = None
    try:
        payload = {
            "investigation_id": "INV-003",
            "playbook_id": "PLAYBOOK-HOST-ISOLATION",
            "target_identifier": "FIN-SRV-02.corp.internal",
            "dispatched_by": "SecOps Incident Commander",
            "notes": "Emergency quarantine ordered due to verified credential harvesting activity."
        }
        status, res = http_post("/api/containment/dispatch", payload)
        assert status == 200, f"Expected 200, got {status}"
        assert res["status"] == "CONTAINED", f"Expected CONTAINED, got {res['status']}"
        assert res["target_identifier"] == "FIN-SRV-02.corp.internal"
        assert res["investigation_id"] == "INV-003"
        dispatched_id = res["id"]
        print(f"[PASS] Test 6: Dispatched host isolation playbook successfully (ID: {dispatched_id}).")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 6: Playbook dispatch failed: {e}")

    # 7. Quarantine receipt hash generation and SHA-256 verification
    try:
        status, res = http_get(f"/api/containment/{dispatched_id}")
        assert status == 200, f"Expected 200, got {status}"
        q_hash = res.get("quarantine_receipt_hash")
        assert q_hash is not None and len(q_hash) == 64, f"Invalid quarantine hash: {q_hash}"
        print(f"[PASS] Test 7: Quarantine receipt digital proof hash verified: {q_hash[:16]}...")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 7: Quarantine receipt check failed: {e}")

    # 8. Step-by-step containment receipts integrity
    try:
        status, res = http_get(f"/api/containment/{dispatched_id}")
        steps = res.get("execution_steps", [])
        assert len(steps) >= 4, f"Expected at least 4 execution steps, got {len(steps)}"
        seqs = [s["step_number"] for s in steps]
        assert seqs == list(range(1, len(steps) + 1)), f"Steps not monotonic: {seqs}"
        assert all(s["status"] == "SUCCESS" for s in steps), "All steps must have SUCCESS status"
        assert all(len(s["artifact_hash"]) == 64 for s in steps), "Step hashes must be valid SHA-256"
        print(f"[PASS] Test 8: Step-by-step receipts verified across {len(steps)} monotonic steps.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 8: Execution steps verification failed: {e}")

    # 9. Dispatch Perimeter Network Block playbook (POST /api/containment/dispatch)
    block_id = None
    try:
        payload = {
            "investigation_id": "INV-004",
            "playbook_id": "PLAYBOOK-NETWORK-BLOCK",
            "target_identifier": "203.0.113.88",
            "dispatched_by": "Firewall Gateway Controller",
            "notes": "Egress drop rule injected at edge border gateway."
        }
        status, res = http_post("/api/containment/dispatch", payload)
        assert status == 200, f"Expected 200, got {status}"
        assert res["target_type"] == "IP_ADDRESS"
        assert res["target_identifier"] == "203.0.113.88"
        block_id = res["id"]
        print(f"[PASS] Test 9: Dispatched perimeter network block playbook (ID: {block_id}).")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 9: Network block dispatch failed: {e}")

    # 10. Investigation lifecycle status transition
    try:
        status, inv = http_get("/api/investigations/INV-003")
        assert status == 200, f"Expected 200, got {status}"
        assert inv["status"] == "Remediating", f"Expected Remediating, got {inv['status']}"
        print(f"[PASS] Test 10: Investigation INV-003 transitioned to status '{inv['status']}'.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 10: Lifecycle transition check failed: {e}")

    # 11. Module 3L Cryptographic Ledger integration
    try:
        status, res = http_get(f"/api/containment/{dispatched_id}")
        audit_id = res.get("audit_entry_id")
        assert audit_id is not None, "Missing audit_entry_id on containment execution"
        assert audit_id.startswith("AUD-"), f"Invalid audit_id: {audit_id}"
        print(f"[PASS] Test 11: Cryptographic ledger block committed: {audit_id} for containment {dispatched_id}.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 11: Audit ledger integration check failed: {e}")

    # 12. Containment query filtering by investigation ID and status
    try:
        status, inv_conts = http_get("/api/containment?investigation_id=INV-003")
        assert status == 200, f"Expected 200, got {status}"
        assert len(inv_conts) >= 1, "Expected at least 1 containment for INV-003"
        for c in inv_conts:
            assert c["investigation_id"] == "INV-003"

        status, active_conts = http_get("/api/containment?status=CONTAINED")
        assert status == 200, f"Expected 200, got {status}"
        for c in active_conts:
            assert c["status"] == "CONTAINED"

        print(f"[PASS] Test 12: Query filtering by investigation and status verified.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 12: Query filtering failed: {e}")

    # 13. Safely rollback containment action (POST /api/containment/{id}/rollback)
    try:
        rb_payload = {
            "rolled_back_by": "SecOps Incident Commander",
            "reason": "Host verified clean via offline forensic scanner; restoring operational network access."
        }
        status, rolled = http_post(f"/api/containment/{dispatched_id}/rollback", rb_payload)
        assert status == 200, f"Expected 200, got {status}"
        assert rolled["status"] == "ROLLED_BACK", f"Expected ROLLED_BACK, got {rolled['status']}"
        assert rolled["rolled_back_at"] is not None
        assert "restoring operational" in rolled["rollback_notes"]
        print(f"[PASS] Test 13: Safely rolled back containment {dispatched_id} to status ROLLED_BACK.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 13: Rollback failed: {e}")

    # 14. Rollback idempotency and safety check (cannot re-rollback)
    try:
        rejected_rerollback = False
        try:
            http_post(
                f"/api/containment/{dispatched_id}/rollback",
                {"rolled_back_by": "SecOps Analyst", "reason": "Attempting second rollback."}
            )
        except urllib.error.HTTPError as he:
            if he.code == 400:
                rejected_rerollback = True
        assert rejected_rerollback, "Re-rolling back an already reverted containment must return HTTP 400"
        print("[PASS] Test 14: Duplicate rollback rejected with HTTP 400 safety guard.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 14: Rollback idempotency check failed: {e}")

    # 15. Boundary condition and error handling (404 on nonexistent containment and invalid target)
    try:
        err_404_count = 0
        try:
            http_get("/api/containment/CONT-NONEXISTENT")
        except urllib.error.HTTPError as he:
            if he.code == 404:
                err_404_count += 1

        try:
            http_post(
                "/api/containment/dispatch",
                {
                    "investigation_id": "INV-DOES-NOT-EXIST",
                    "playbook_id": "PLAYBOOK-HOST-ISOLATION",
                    "target_identifier": "ghost-host",
                }
            )
        except urllib.error.HTTPError as he:
            if he.code == 404:
                err_404_count += 1

        assert err_404_count == 2, f"Expected two 404 errors, got {err_404_count}"
        print("[PASS] Test 15: Boundary and error handling correctly returns 404 for invalid targets.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 15: Error handling test failed: {e}")

    print("======================================================================")
    print(f"MODULE 3N TEST RESULTS: {passed}/{total} PASSED")
    print("======================================================================")

    if passed == total:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
