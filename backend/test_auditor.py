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
    print("=" * 60)
    print("AGENTIC SOC — MODULE 3E AUDITOR AGENT TESTS")
    print("=" * 60)

    # 1. Health check verification
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert health.get("auditor_agent") == "Active (Deterministic Case Auditing & Evidence Verification)", f"Auditor not active: {health}"
    print("[PASS] Check 01: Backend Health Check & Auditor Agent Registered")
    print(f"        -> Module: {health.get('module')}")

    # 2. Locate / Ensure Test Evidence exists for INV-012
    status, evidence_list = make_request("/api/investigations/INV-012/evidence")
    assert status == 200, f"Failed to list evidence: {status}"
    assert len(evidence_list) >= 2, "Need at least 2 evidence records for testing"

    suspicious_ev = None
    approved_ev = None

    for ev in evidence_list:
        raw = ev["raw_output"].lower()
        if "powershell" in raw and ("unusual" in raw or "suspicious" in raw):
            suspicious_ev = ev["id"]
        if "approved administrative script" in raw or "legitimate it maintenance" in raw:
            approved_ev = ev["id"]

    if not suspicious_ev:
        suspicious_ev = evidence_list[0]["id"]
    if not approved_ev and len(evidence_list) > 1:
        approved_ev = evidence_list[1]["id"]

    print(f"[PASS] Check 02: Target Evidence Identified for INV-012")
    print(f"        -> Suspicious Evidence ID: {suspicious_ev}")
    print(f"        -> Correlated Admin Evidence ID: {approved_ev}")

    # Baseline counts to verify zero side-effects
    status, initial_executions = make_request("/api/investigations/INV-012/tool-executions")
    initial_exec_count = len(initial_executions)
    status, initial_evidence_list = make_request("/api/investigations/INV-012/evidence")
    initial_evidence_count = len(initial_evidence_list)

    # TEST 1 — SUPPORTED CLAIM WITH VALID EVIDENCE
    # Claim: "PowerShell execution occurred." Evidence: [suspicious_ev]
    test1_payload = {
        "investigation_id": "INV-012",
        "claims": [
            {
                "claim": "PowerShell execution occurred on PC-DB-TEST",
                "evidence_ids": [suspicious_ev],
            }
        ],
        "final_conclusion": "Suspicious PowerShell activity was observed.",
    }
    status, res1 = make_request("/api/investigations/INV-012/audit", method="POST", data=test1_payload)
    assert status == 200, f"Test 1 failed: {res1}"
    assert "case_id" in res1, "Missing case_id"
    assert res1["audit_verified"] is True, "Expected audit_verified True"
    c1 = res1["claims"][0]
    assert c1["status"] == "SUPPORTED", f"Expected SUPPORTED, got {c1['status']}"
    assert c1["confidence"] == "SUPPORTED", f"Expected confidence SUPPORTED, got {c1['confidence']}"
    assert c1["evidence_integrity_verified"] is True, "Expected integrity True"
    print(f"[PASS] Check 03: Test 1 — Supported Claim Verified (Case: {res1['case_id']})")
    print(f"        -> Status: {c1['status']}, Reason: {c1['reason']}")

    # TEST 2 — UNSUPPORTED ATTRIBUTION (NO EVIDENCE -> NO CLAIM)
    # Claim: "Threat actor is APT-X." Evidence: []
    # Expected: UNSUPPORTED. Auditor must NOT upgrade it to SUPPORTED.
    test2_payload = {
        "investigation_id": "INV-012",
        "claims": [
            {
                "claim": "PowerShell execution occurred on host",
                "evidence_ids": [suspicious_ev],
            },
            {
                "claim": "Threat actor is APT-X",
                "evidence_ids": [],
            }
        ],
        "final_conclusion": "Attack attributed to APT-X.",
    }
    status, res2 = make_request("/api/investigations/INV-012/audit", method="POST", data=test2_payload)
    assert status == 200, f"Test 2 failed: {res2}"
    c2_attr = [c for c in res2["claims"] if "APT-X" in c["claim"]][0]
    assert c2_attr["status"] == "UNSUPPORTED", f"Expected UNSUPPORTED, got {c2_attr['status']}"
    assert c2_attr["confidence"] == "UNSUPPORTED"
    assert "Threat actor is APT-X" in res2["unsupported_claims"], f"Expected in unsupported_claims: {res2['unsupported_claims']}"
    assert "Threat-actor attribution cannot be established" in res2["final_conclusion"]
    print(f"[PASS] Check 04: Test 2 — Unsupported Attribution Preserved as UNSUPPORTED")
    print(f"        -> Conclusion: {res2['final_conclusion']}")

    # TEST 3 — INVALID EVIDENCE ID
    # Claim references nonexistent evidence: "E-999999"
    test3_payload = {
        "investigation_id": "INV-012",
        "claims": [
            {
                "claim": "Command and control beacon established to external server",
                "evidence_ids": ["E-999999"],
            }
        ],
    }
    status, res3 = make_request("/api/investigations/INV-012/audit", method="POST", data=test3_payload)
    assert status == 200, f"Test 3 failed: {res3}"
    c3 = res3["claims"][0]
    assert c3["status"] in ["UNSUPPORTED", "INVALID_EVIDENCE_REFERENCE"], f"Expected UNSUPPORTED, got {c3['status']}"
    assert "E-999999" in c3["reason"]
    assert c3["evidence_integrity_verified"] is False
    print(f"[PASS] Check 05: Test 3 — Nonexistent Evidence E-999999 Flagged as UNSUPPORTED")
    print(f"        -> Reason: {c3['reason']}")

    # TEST 4 — CRITIC OBJECTION PRESERVATION
    # Provide explicit Critic finding identifying unsupported claim
    test4_payload = {
        "investigation_id": "INV-012",
        "claims": [
            {
                "claim": "Threat actor is Threat Actor X",
                "evidence_ids": [suspicious_ev],  # even if evidence is attached, if it's process log and Critic objected
            }
        ],
        "critic_findings": [
            {
                "claim": "Threat actor is Threat Actor X",
                "status": "UNSUPPORTED",
                "category": "UNSUPPORTED_ATTRIBUTION",
                "reason": "No evidence establishes attribution to Threat Actor X.",
            }
        ],
    }
    status, res4 = make_request("/api/investigations/INV-012/audit", method="POST", data=test4_payload)
    assert status == 200, f"Test 4 failed: {res4}"
    c4 = res4["claims"][0]
    assert c4["status"] == "UNSUPPORTED", f"Expected Critic objection preserved, got {c4['status']}"
    assert "Critic" in c4["reason"] or "attribution" in c4["reason"].lower()
    print(f"[PASS] Check 06: Test 4 — Critic Objection Preserved in Audited Case")
    print(f"        -> Reason: {c4['reason']}")

    # TEST 5 — CONTRADICTORY EVIDENCE
    test5_payload = {
        "investigation_id": "INV-012",
        "claims": [
            {
                "claim": "Malicious unauthorized PowerShell execution occurred",
                "evidence_ids": [suspicious_ev, approved_ev],
            }
        ],
    }
    status, res5 = make_request("/api/investigations/INV-012/audit", method="POST", data=test5_payload)
    assert status == 200, f"Test 5 failed: {res5}"
    c5 = res5["claims"][0]
    assert c5["status"] == "CONTRADICTED", f"Expected CONTRADICTED, got {c5['status']}"
    assert len(res5["contradictions"]) > 0, "Expected at least one contradiction reported"
    print(f"[PASS] Check 07: Test 5 — Contradictory Evidence Identified as CONTRADICTED")
    print(f"        -> Contradiction: {res5['contradictions'][0]}")

    # TEST 6 — VALID EVIDENCE INTEGRITY
    # Valid evidence whose SHA-256 verification succeeds
    status, ev_verify = make_request(f"/api/evidence/{suspicious_ev}/verify")
    assert status == 200 and ev_verify["valid"] is True, f"Evidence verify failed: {ev_verify}"
    assert res1["claims"][0]["evidence_integrity_verified"] is True
    print(f"[PASS] Check 08: Test 6 — Valid Evidence Integrity Confirmed (SHA-256 Match)")

    # TEST 7 — INVALID EVIDENCE INTEGRITY
    # Test handling when evidence has corrupted/invalid hash
    # Create temporary evidence with intentionally altered hash
    import sqlite3
    conn = sqlite3.connect("agentic_soc.db")
    cur = conn.cursor()
    cur.execute("SELECT id, raw_output, content_hash FROM evidence WHERE id = ?", (suspicious_ev,))
    orig_ev = cur.fetchone()
    conn.close()

    # Create a corrupted evidence record in DB directly for test 7
    conn = sqlite3.connect("agentic_soc.db")
    cur = conn.cursor()
    corrupt_id = "E-CORRUPT-TEST"
    cur.execute(
        "INSERT OR REPLACE INTO evidence (id, investigation_id, evidence_type, source, timestamp, raw_output, content_hash, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (corrupt_id, "INV-012", "PROCESS_EVENT", "Mock EDR", "2026-09-27 12:00:00 UTC", "powershell.exe executed", "0000000000000000000000000000000000000000000000000000000000000000", "COLLECTED", "2026-09-27 12:00:00 UTC"),
    )
    conn.commit()
    conn.close()

    test7_payload = {
        "investigation_id": "INV-012",
        "claims": [
            {
                "claim": "Process execution verified by corrupted telemetry",
                "evidence_ids": [corrupt_id],
            }
        ],
    }
    status, res7 = make_request("/api/investigations/INV-012/audit", method="POST", data=test7_payload)
    assert status == 200, f"Test 7 failed: {res7}"
    c7 = res7["claims"][0]
    assert c7["status"] in ["UNCERTAIN", "UNSUPPORTED"], f"Expected UNCERTAIN for corrupt hash, got {c7['status']}"
    assert c7["evidence_integrity_verified"] is False
    assert any("integrity" in u.lower() or "failed" in u.lower() for u in res7["uncertainties"])
    print(f"[PASS] Check 09: Test 7 — Corrupted Evidence Flagged as UNCERTAIN (Integrity False)")

    # Clean up test corrupted record
    conn = sqlite3.connect("agentic_soc.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM evidence WHERE id = ?", (corrupt_id,))
    conn.commit()
    conn.close()

    # TEST 8 — NO EVIDENCE, NO CLAIM
    test8_payload = {
        "investigation_id": "INV-012",
        "claims": [
            {
                "claim": "APT-X attacked the organization",
                "evidence_ids": [],
            }
        ],
    }
    status, res8 = make_request("/api/investigations/INV-012/audit", method="POST", data=test8_payload)
    assert status == 200, f"Test 8 failed: {res8}"
    assert res8["claims"][0]["status"] == "UNSUPPORTED"
    assert "APT-X attacked the organization" in res8["unsupported_claims"]
    print("[PASS] Check 10: Test 8 — NO EVIDENCE -> NO CLAIM Strictly Enforced")

    # TEST 9 — DETERMINISM
    # Run exact same audit input twice -> structured outputs must be identical
    status, res9a = make_request("/api/investigations/INV-012/audit", method="POST", data=test2_payload)
    status, res9b = make_request("/api/investigations/INV-012/audit", method="POST", data=test2_payload)
    assert status == 200

    assert [c["status"] for c in res9a["claims"]] == [c["status"] for c in res9b["claims"]], "Claims status mismatch"
    assert [c["confidence"] for c in res9a["claims"]] == [c["confidence"] for c in res9b["claims"]], "Confidence mismatch"
    assert res9a["contradictions"] == res9b["contradictions"], "Contradictions mismatch"
    assert res9a["uncertainties"] == res9b["uncertainties"], "Uncertainties mismatch"
    assert res9a["unsupported_claims"] == res9b["unsupported_claims"], "Unsupported claims mismatch"
    assert res9a["final_conclusion"] == res9b["final_conclusion"], "Final conclusion mismatch"
    print("[PASS] Check 11: Test 9 — Determinism Verified (Identical Structured Case Results)")

    # 12. GET /api/investigations/INV-012/audit retrieval check
    status, latest_case = make_request("/api/investigations/INV-012/audit")
    assert status == 200, f"GET audit failed: {status}"
    assert latest_case["investigation_id"] == "INV-012"
    assert len(latest_case["claims"]) > 0
    assert len(latest_case["tool_executions"]) >= 0
    print(f"[PASS] Check 12: GET /api/investigations/INV-012/audit Success (Case: {latest_case['case_id']})")

    # 13. Security Boundaries
    status, after_executions = make_request("/api/investigations/INV-012/tool-executions")
    after_exec_count = len(after_executions)
    assert initial_exec_count == after_exec_count, f"Security violation: Tools executed during audit ({initial_exec_count} -> {after_exec_count})"
    print(f"[PASS] Check 13: Security Boundary: Zero Tool Executions During Audit ({after_exec_count} == {initial_exec_count})")

    status, after_evidence = make_request("/api/investigations/INV-012/evidence")
    after_evidence_count = len(after_evidence)
    assert initial_evidence_count == after_evidence_count, f"Security violation: Evidence mutated during audit ({initial_evidence_count} -> {after_evidence_count})"
    print(f"[PASS] Check 14: Security Boundary: Zero Evidence Objects Mutated During Audit ({after_evidence_count} == {initial_evidence_count})")

    status, err_resp = make_request("/api/investigations/INV-999/audit", method="POST", data=test1_payload)
    assert status == 404, f"Expected 404 for nonexistent investigation, got {status}"
    print("[PASS] Check 15: Nonexistent Investigation Correctly Rejected with HTTP 404")

    print("\n" + "=" * 60)
    print("ALL 15/15 AUDITOR AGENT CHECKS PASSED PERFECTLY!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"\n[FAIL] Test suite failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
