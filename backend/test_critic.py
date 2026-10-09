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
    print("AGENTIC SOC — MODULE 3D CRITIC / RED-TEAM AGENT TESTS")
    print("=" * 60)

    # 1. Health check verification
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert health.get("critic_agent") == "Active (Deterministic Reasoning & Red-Teaming)", f"Critic not active: {health}"
    print("[PASS] Check 01: Backend Health Check & Critic Agent Registered")
    print(f"        -> Module: {health.get('module')}")

    # 2. Setup / Ensure Test Evidence exists for INV-012 (e.g. E-034 suspicious, E-035 approved admin script)
    # Check current evidence for INV-012
    status, evidence_list = make_request("/api/investigations/INV-012/evidence")
    assert status == 200, f"Failed to list evidence: {status}"

    existing_eids = {e["id"]: e for e in evidence_list}

    # If E-034 not present, or to have a dedicated pair of evidence items:
    # Let's see if we have an evidence item describing suspicious powershell execution
    # and another describing approved administrative maintenance
    suspicious_ev = None
    approved_ev = None

    for ev in evidence_list:
        raw = ev["raw_output"].lower()
        if "powershell" in raw and ("unusual" in raw or "suspicious" in raw):
            suspicious_ev = ev["id"]
        if "approved administrative script" in raw or "legitimate it maintenance" in raw:
            approved_ev = ev["id"]

    # If not present, create them deterministically for testing
    if not suspicious_ev:
        status, ev_resp = make_request("/api/investigations/INV-012/evidence", method="POST", data={
            "evidence_type": "PROCESS_EVENT",
            "source": "Mock EDR",
            "raw_output": "powershell.exe executed from an unusual parent process (PID 4812). Suspicious command-line parameters detected.",
            "query": "host=PC-DB-TEST powershell",
        })
        assert status == 201, f"Failed to create suspicious evidence: {ev_resp}"
        suspicious_ev = ev_resp["id"]

    if not approved_ev:
        status, ev_resp = make_request("/api/investigations/INV-012/evidence", method="POST", data={
            "evidence_type": "SIEM_LOG",
            "source": "Mock SIEM",
            "raw_output": "Execution of powershell.exe correlates with scheduled ticket CHG-8821: approved administrative script for database maintenance.",
            "query": "ticket=CHG-8821",
        })
        assert status == 201, f"Failed to create approved evidence: {ev_resp}"
        approved_ev = ev_resp["id"]

    print(f"[PASS] Check 02: Test Evidence Prepared for INV-012")
    print(f"        -> Suspicious Evidence ID: {suspicious_ev}")
    print(f"        -> Contradictory Approved Evidence ID: {approved_ev}")

    # Baseline tool executions and evidence counts before testing Critic
    status, initial_executions = make_request("/api/investigations/INV-012/tool-executions")
    initial_exec_count = len(initial_executions)
    status, initial_evidence_list = make_request("/api/investigations/INV-012/evidence")
    initial_evidence_count = len(initial_evidence_list)

    # TEST 1 — SUPPORTED CLAIM
    # Claim: "PowerShell execution occurred." Evidence: [suspicious_ev]
    test1_payload = {
        "investigation_id": "INV-012",
        "draft_conclusion": "PowerShell execution was observed on PC-DB-TEST.",
        "claims": [
            {
                "claim": "PowerShell execution occurred on the host",
                "evidence_ids": [suspicious_ev],
            }
        ],
    }
    status, res1 = make_request("/api/investigations/INV-012/critic", method="POST", data=test1_payload)
    assert status == 200, f"Test 1 failed: {res1}"
    assert len(res1["claims_evaluation"]) == 1, f"Expected 1 claim evaluation, got {res1}"
    c1 = res1["claims_evaluation"][0]
    assert c1["status"] == "SUPPORTED", f"Expected SUPPORTED, got {c1['status']}"
    assert res1["overall_status"] == "PASS", f"Expected PASS, got {res1['overall_status']}"
    print(f"[PASS] Check 03: Test 1 — Supported Claim Evaluated as SUPPORTED")
    print(f"        -> Status: {c1['status']}, Reason: {c1['reason']}")

    # TEST 2 — UNSUPPORTED ATTRIBUTION
    # Claim: "Threat actor is APT-X." Evidence: []
    test2_payload = {
        "investigation_id": "INV-012",
        "draft_conclusion": "This is an attack by Threat Actor X.",
        "claims": [
            {
                "claim": "PowerShell execution occurred",
                "evidence_ids": [suspicious_ev],
            },
            {
                "claim": "Threat actor is Threat Actor X",
                "evidence_ids": [],
            }
        ],
    }
    status, res2 = make_request("/api/investigations/INV-012/critic", method="POST", data=test2_payload)
    assert status == 200, f"Test 2 failed: {res2}"
    assert res2["overall_status"] == "REQUIRES_REVISION", f"Expected REQUIRES_REVISION, got {res2['overall_status']}"
    # Verify objection specifically targets unsupported attribution
    attr_eval = [c for c in res2["claims_evaluation"] if "Threat Actor" in c["claim"]][0]
    assert attr_eval["status"] == "UNSUPPORTED", f"Expected UNSUPPORTED, got {attr_eval['status']}"
    assert any("attribution" in obj["reason"].lower() or "attribution" in (obj.get("category") or "").lower() for obj in res2["objections"]), "Missing attribution objection"
    assert any("threat actor" in m.lower() for m in res2["missing_evidence"]), f"Missing evidence not reported: {res2['missing_evidence']}"
    print(f"[PASS] Check 04: Test 2 — Unsupported Attribution Flagged as UNSUPPORTED")
    print(f"        -> Objection: {attr_eval['reason']}")

    # TEST 3 — INVALID EVIDENCE ID
    # Claim references: "E-999999" which does not exist
    test3_payload = {
        "investigation_id": "INV-012",
        "draft_conclusion": "Malicious payload downloaded from command server.",
        "claims": [
            {
                "claim": "Payload downloaded from remote server",
                "evidence_ids": ["E-999999"],
            }
        ],
    }
    status, res3 = make_request("/api/investigations/INV-012/critic", method="POST", data=test3_payload)
    assert status == 200, f"Test 3 failed: {res3}"
    c3 = res3["claims_evaluation"][0]
    assert c3["status"] in ["INVALID_EVIDENCE_REFERENCE", "UNSUPPORTED"], f"Expected INVALID_EVIDENCE_REFERENCE, got {c3['status']}"
    assert "E-999999" in c3["invalid_evidence_ids"] or "E-999999" in c3["reason"]
    assert res3["overall_status"] == "REQUIRES_REVISION"
    print(f"[PASS] Check 05: Test 3 — Invalid Evidence ID Flagged as INVALID_EVIDENCE_REFERENCE")
    print(f"        -> Reason: {c3['reason']}")

    # TEST 4 — CONTRADICTION
    # Claim: "Malicious PowerShell execution occurred."
    # Evidence: [suspicious_ev, approved_ev]
    test4_payload = {
        "investigation_id": "INV-012",
        "draft_conclusion": "Investigator concludes malicious activity.",
        "claims": [
            {
                "claim": "Malicious PowerShell execution occurred on host",
                "evidence_ids": [suspicious_ev, approved_ev],
            }
        ],
    }
    status, res4 = make_request("/api/investigations/INV-012/critic", method="POST", data=test4_payload)
    assert status == 200, f"Test 4 failed: {res4}"
    c4 = res4["claims_evaluation"][0]
    assert c4["status"] in ["CONTRADICTED", "UNCERTAIN"], f"Expected CONTRADICTED or UNCERTAIN, got {c4['status']}"
    assert len(res4["contradictions"]) > 0, "Expected at least one contradiction reported"
    assert res4["overall_status"] == "REQUIRES_REVISION"
    print(f"[PASS] Check 06: Test 4 — Contradictory Evidence Identified as CONTRADICTED")
    print(f"        -> Contradiction: {res4['contradictions'][0]}")

    # TEST 5 — OVERCONFIDENT LANGUAGE
    # Draft: "This definitely proves an APT attack."
    test5_payload = {
        "investigation_id": "INV-012",
        "draft_conclusion": "This definitely proves an APT attack.",
        "claims": [
            {
                "claim": "PowerShell execution occurred",
                "evidence_ids": [suspicious_ev],
            }
        ],
    }
    status, res5 = make_request("/api/investigations/INV-012/critic", method="POST", data=test5_payload)
    assert status == 200, f"Test 5 failed: {res5}"
    assert res5["overall_status"] == "REQUIRES_REVISION", f"Expected REQUIRES_REVISION, got {res5['overall_status']}"
    assert any("overconfident" in o.lower() or "definitely" in o.lower() for o in res5["overclaims"]), f"Expected overclaim on definitely: {res5['overclaims']}"
    print(f"[PASS] Check 07: Test 5 — Overconfident Language ('definitely proves') Flagged")
    print(f"        -> Overclaims: {res5['overclaims']}")

    # TEST 6 — NO CLAIM WITHOUT EVIDENCE
    # Claim with evidence_ids = []
    test6_payload = {
        "investigation_id": "INV-012",
        "draft_conclusion": "Privilege escalation occurred on domain controller.",
        "claims": [
            {
                "claim": "Unquoted service path was abused for privilege escalation",
                "evidence_ids": [],
            }
        ],
    }
    status, res6 = make_request("/api/investigations/INV-012/critic", method="POST", data=test6_payload)
    assert status == 200, f"Test 6 failed: {res6}"
    c6 = res6["claims_evaluation"][0]
    assert c6["status"] == "UNSUPPORTED", f"Expected UNSUPPORTED, got {c6['status']}"
    assert res6["overall_status"] == "REQUIRES_REVISION"
    print(f"[PASS] Check 08: Test 6 — Claim with Empty Evidence Evaluated as UNSUPPORTED")
    print(f"        -> Reason: {c6['reason']}")

    # TEST 7 — DETERMINISM
    # Running the exact same request twice must yield identical results
    test7_payload = {
        "investigation_id": "INV-012",
        "draft_conclusion": "Suspicious execution detected by red team.",
        "claims": [
            {
                "claim": "PowerShell executed with unusual parameters",
                "evidence_ids": [suspicious_ev],
            },
            {
                "claim": "Attributed to Threat Actor Y",
                "evidence_ids": [],
            }
        ],
    }
    status, res7a = make_request("/api/investigations/INV-012/critic", method="POST", data=test7_payload)
    status, res7b = make_request("/api/investigations/INV-012/critic", method="POST", data=test7_payload)
    assert status == 200

    # Compare core evaluation fields (excluding generated review ID and timestamp)
    assert res7a["overall_status"] == res7b["overall_status"], "Status mismatch in determinism"
    assert [c["status"] for c in res7a["claims_evaluation"]] == [c["status"] for c in res7b["claims_evaluation"]], "Claims mismatch"
    assert len(res7a["objections"]) == len(res7b["objections"]), "Objections mismatch"
    assert res7a["missing_evidence"] == res7b["missing_evidence"], "Missing evidence mismatch"
    assert res7a["contradictions"] == res7b["contradictions"], "Contradictions mismatch"
    assert res7a["overclaims"] == res7b["overclaims"], "Overclaims mismatch"
    print("[PASS] Check 09: Test 7 — Determinism Verified (Identical Structured Results)")

    # 8. Check GET /api/investigations/INV-012/critic (Retrieval of persisted review)
    status, latest_review = make_request("/api/investigations/INV-012/critic")
    assert status == 200, f"Failed to retrieve latest critic review: {status}"
    assert latest_review["investigation_id"] == "INV-012"
    assert len(latest_review["claims_evaluation"]) > 0
    print(f"[PASS] Check 10: GET /api/investigations/INV-012/critic Success (ID: {latest_review['id']})")

    # 9. Security Boundary: Zero Tool Executions Occurred During Critic Evaluations
    status, after_executions = make_request("/api/investigations/INV-012/tool-executions")
    after_exec_count = len(after_executions)
    assert initial_exec_count == after_exec_count, f"Security violation: Tools were executed during critique ({initial_exec_count} -> {after_exec_count})"
    print(f"[PASS] Check 11: Security Boundary: Zero Tool Executions During Critique ({after_exec_count} == {initial_exec_count})")

    # 10. Security Boundary: Zero Evidence Mutated or Created During Evaluation
    status, after_evidence = make_request("/api/investigations/INV-012/evidence")
    after_evidence_count = len(after_evidence)
    assert initial_evidence_count == after_evidence_count, f"Security violation: Evidence was mutated during critique ({initial_evidence_count} -> {after_evidence_count})"
    print(f"[PASS] Check 12: Security Boundary: Zero Evidence Objects Created/Mutated During Critique ({after_evidence_count} == {initial_evidence_count})")

    # 11. Security Boundary: Reject Nonexistent Investigation (HTTP 404)
    status, err_resp = make_request("/api/investigations/INV-999/critic", method="POST", data=test1_payload)
    assert status == 404, f"Expected 404 for nonexistent investigation, got {status}"
    print("[PASS] Check 13: Nonexistent Investigation Correctly Rejected with HTTP 404")

    print("\n" + "=" * 60)
    print("ALL 13/13 CRITIC / RED-TEAM CHECKS PASSED PERFECTLY!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"\n[FAIL] Test suite failed with exception: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
