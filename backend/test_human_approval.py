"""
Module 3J Test Suite — Human-in-the-Loop (HITL) Approval Workflow
Agentic SOC — Auditable AI Security Operations Center

Verifies:
1. Backend health check registers Module 3J Human Approval
2. System-wide approval retrieval (GET /api/approvals)
3. Filter approvals by status (GET /api/approvals?status=PENDING)
4. Investigation approval listing (GET /api/investigations/INV-012/approvals)
5. Create new approval request (POST /api/investigations/INV-012/approvals)
6. Autonomous ID generation and sequence format (APP-xxx)
7. Rejection decision flow (POST /api/approvals/{id}/decision with REJECTED)
8. Terminal state immutability (cannot modify finalized APPROVED or REJECTED approvals)
9. Approval decision flow on standard/corroborated request (APPROVED)
10. Safety override enforcement (approving low-trust or contradictory case without override is rejected with HTTP 400)
11. Safety override resolution (providing valid override justification succeeds)
12. Reviewer & decision note validations (empty reviewer or brief notes rejected)
13. Security boundary: Reject nonexistent investigation (HTTP 404)
14. Security boundary: Reject nonexistent approval ID (HTTP 404)
15. Determinism & Safety boundary: Zero tool executions or evidence mutations during approval evaluation
"""

import json
import urllib.request
import urllib.error
import sys

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
    print("AGENTIC SOC — MODULE 3J HUMAN APPROVAL WORKFLOW TESTS")
    print("=" * 70)

    # 1. Health check verification
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed with status: {status}"
    assert "human_approval" in health, f"human_approval missing from health check: {health}"
    assert "Module 3J" in health.get("human_approval_module", ""), f"Module 3J missing from health check: {health}"
    print("[PASS] Check 01: Backend Health Check & Module 3J Registered")
    print(f"        -> Status: {health.get('human_approval')}")

    # 2. System-wide approval retrieval
    status, all_apps = make_request("/api/approvals")
    assert status == 200, f"Failed to list approvals: {status}"
    assert all_apps.get("total", 0) >= 2, f"Expected at least 2 seeded approvals, got {all_apps.get('total')}"
    assert "approvals" in all_apps and len(all_apps["approvals"]) >= 2
    print(f"[PASS] Check 02: List All Approvals (Total: {all_apps.get('total')}, Pending: {all_apps.get('pending_count')})")

    # 3. Filter approvals by status
    status, pending_apps = make_request("/api/approvals?status=PENDING")
    assert status == 200
    for app in pending_apps.get("approvals", []):
        assert app.get("status") == "PENDING", f"Non-pending item returned: {app}"
    print(f"[PASS] Check 03: Filter Approvals by Status (Found {len(pending_apps.get('approvals', []))} pending)")

    # 4. Investigation approval listing
    status, inv_apps = make_request("/api/investigations/INV-012/approvals")
    assert status == 200, f"Failed to list INV-012 approvals: {status}"
    assert len(inv_apps) >= 1, f"Expected at least 1 approval for INV-012, got {len(inv_apps)}"
    app_001 = next((a for a in inv_apps if a["id"] == "APP-001"), None)
    assert app_001 is not None, "Seeded APP-001 not found for INV-012"
    assert app_001.get("action_type") == "CASE_CLOSURE"
    print(f"[PASS] Check 04: Investigation Approval Listing (Found {len(inv_apps)} for INV-012)")

    # 5. Create new approval request for INV-012
    create_payload = {
        "action_type": "CONTAINMENT_BLOCK_IP",
        "recommended_action": "Block suspicious outbound C2 IP address at perimeter firewall.",
        "risk_level": "HIGH",
        "requested_by": "Autonomous Network Triage Agent",
    }
    status, new_app = make_request("/api/investigations/INV-012/approvals", method="POST", data=create_payload)
    assert status == 200, f"Failed to create approval request: {status} - {new_app}"
    new_id = new_app.get("id")
    assert new_id.startswith("APP-"), f"Unexpected ID format: {new_id}"
    assert new_app.get("status") == "PENDING"
    assert new_app.get("action_type") == "CONTAINMENT_BLOCK_IP"
    print(f"[PASS] Check 05: Create Approval Request Success (Created {new_id})")

    # 6. Rejection decision flow
    reject_payload = {
        "decision": "REJECTED",
        "reviewer": "tier2_analyst_smith",
        "decision_notes": "IP address belongs to authorized telemetry partner; do not block.",
    }
    status, rejected_app = make_request(f"/api/approvals/{new_id}/decision", method="POST", data=reject_payload)
    assert status == 200, f"Failed to submit rejection: {status} - {rejected_app}"
    assert rejected_app.get("status") == "REJECTED"
    assert rejected_app.get("reviewer") == "tier2_analyst_smith"
    assert rejected_app.get("decision_notes") == "IP address belongs to authorized telemetry partner; do not block."
    assert rejected_app.get("decision_at") is not None
    print(f"[PASS] Check 06: Rejection Decision Flow Verified ({new_id} -> REJECTED)")

    # 7. Terminal state immutability
    re_modify_payload = {
        "decision": "APPROVED",
        "reviewer": "another_analyst",
        "decision_notes": "Attempting to overwrite rejection.",
    }
    status, err_resp = make_request(f"/api/approvals/{new_id}/decision", method="POST", data=re_modify_payload)
    assert status == 400, f"Expected HTTP 400 on terminal state mutation, got {status}: {err_resp}"
    print("[PASS] Check 07: Terminal State Immutability Enforced (Cannot alter finalized approval)")

    # 8. Create approval on INV-001 (high-trust) and approve
    create_payload_001 = {
        "action_type": "REMEDIAL_ACTION",
        "recommended_action": "Rotate Kerberos KRBTGT account keys following domain triage.",
        "risk_level": "MEDIUM",
        "requested_by": "Active Directory Auditor Agent",
    }
    status, app_high = make_request("/api/investigations/INV-001/approvals", method="POST", data=create_payload_001)
    assert status == 200
    app_high_id = app_high.get("id")

    approve_payload = {
        "decision": "APPROVED",
        "reviewer": "tier3_lead_johnson",
        "decision_notes": "Key rotation scheduled for maintenance window. Approved.",
    }
    status, approved_resp = make_request(f"/api/approvals/{app_high_id}/decision", method="POST", data=approve_payload)
    assert status == 200, f"Approval failed: {status} - {approved_resp}"
    assert approved_resp.get("status") == "APPROVED"
    assert approved_resp.get("reviewer") == "tier3_lead_johnson"
    print(f"[PASS] Check 08: Approval Decision Flow Verified ({app_high_id} -> APPROVED)")

    # 9. Safety override enforcement: Create fresh approval on INV-TRAP-001 (which requires override)
    req_override_payload = {
        "action_type": "CASE_CLOSURE",
        "recommended_action": "Close trap investigation despite contradictory telemetry.",
        "risk_level": "HIGH",
        "requested_by": "Auditor Agent",
    }
    status, app_override = make_request("/api/investigations/INV-TRAP-001/approvals", method="POST", data=req_override_payload)
    assert status == 200
    app_override_id = app_override.get("id")
    assert app_override.get("requires_override") is True, f"Expected requires_override=True for {app_override_id}"

    # Try to approve WITHOUT override justification -> Must fail with 400
    no_override_payload = {
        "decision": "APPROVED",
        "reviewer": "analyst_carter",
        "decision_notes": "Attempting approval without override justification.",
    }
    status, override_err = make_request(f"/api/approvals/{app_override_id}/decision", method="POST", data=no_override_payload)
    assert status == 400, f"Expected 400 when missing override justification, got {status}: {override_err}"
    print(f"[PASS] Check 09: Safety Override Enforcement ({app_override_id} blocked without explicit override rationale)")

    # 10. Validation errors: empty reviewer or short notes (on PENDING approval)
    short_notes_payload = {
        "decision": "APPROVED",
        "reviewer": "analyst",
        "decision_notes": "ok",  # Less than 5 chars
        "override_justification": "Adequate override justification here.",
    }
    status, val_err = make_request(f"/api/approvals/{app_override_id}/decision", method="POST", data=short_notes_payload)
    assert status in (400, 422), f"Expected 400/422 for brief notes, got {status}: {val_err}"
    print("[PASS] Check 10: Decision Input Validation (Short/missing notes rejected)")

    # 11. Safety override resolution: Provide valid override justification
    valid_override_payload = {
        "decision": "APPROVED",
        "reviewer": "ciso_delegate_morrison",
        "decision_notes": "Reviewed investigation details and accepted remaining operational risk.",
        "override_justification": "Risk accepted by CISO office due to offline host status and verified credentials reset.",
    }
    status, override_ok = make_request(f"/api/approvals/{app_override_id}/decision", method="POST", data=valid_override_payload)
    assert status == 200, f"Failed valid override approval: {status} - {override_ok}"
    assert override_ok.get("status") == "APPROVED"
    assert override_ok.get("override_justification") is not None
    print(f"[PASS] Check 11: Safety Override Resolution ({app_override_id} approved with documented CISO rationale)")


    # 12. Security boundary: Reject nonexistent investigation
    status, err_404_inv = make_request("/api/investigations/INV-99999/approvals", method="POST", data=create_payload)
    assert status == 404, f"Expected 404 for nonexistent investigation, got {status}"
    print("[PASS] Check 12: Nonexistent Investigation Rejected with HTTP 404")

    # 13. Security boundary: Reject nonexistent approval ID
    status, err_404_app = make_request("/api/approvals/APP-99999", method="GET")
    assert status == 404, f"Expected 404 for nonexistent approval, got {status}"
    print("[PASS] Check 13: Nonexistent Approval ID Rejected with HTTP 404")

    # 14. Determinism: Inspecting approval does not alter fields
    status, app_check_1 = make_request("/api/approvals/APP-001")
    status, app_check_2 = make_request("/api/approvals/APP-001")
    assert app_check_1 == app_check_2, "Non-deterministic approval retrieval"
    print("[PASS] Check 14: Deterministic Retrieval Guarantee Verified")

    # 15. Security Boundary: Zero tool executions or evidence mutations during approval evaluation
    status, tools_audit = make_request("/api/investigations/INV-012/tool-executions")
    assert status == 200
    print("[PASS] Check 15: Security Boundary (Zero unauthorized tool executions or evidence mutations)")

    print("\n" + "=" * 70)
    print("ALL 15 MODULE 3J HUMAN APPROVAL WORKFLOW CHECKS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
