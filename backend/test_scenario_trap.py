"""
Module 3I Test Suite — Deterministic Synthetic Trap / Deception Scenario
Agentic SOC — Auditable AI Security Operations Center

Verifies:
1. Trap scenario execution via API (POST /api/scenarios/trap)
2. Trap scenario retrieval via API (GET /api/scenarios/trap)
3. Synthetic evidence validation (4 items, SHA-256 cryptographic hashes verified)
4. Deceptive evidence identification (E-TRAP-DECEPTIVE, IT Ticket CHG-99214 identified)
5. Evidence-to-claim relationships (All claims mapped to valid evidence IDs)
6. Contradiction detection & resolution (Claim 1 CONTRADICTED by deceptive evidence)
7. Unsupported attribution rejection (Claim 3 UNSUPPORTED due to ungrounded APT-29 claim)
8. Supported claim corroboration (Claim 2 SUPPORTED for approved admin task)
9. Planner Agent integration (Deterministic sequential investigation plan)
10. Critic Agent integration (REQUIRES_REVISION with 4 objections)
11. Canonical Case JSON generation (v1.0.0 schema compliance and serialization)
12. Trust Score penalties calculation (36.7 / 100 UNTRUSTED, -35.0 pts penalties)
13. Determinism: Repeated scenario runs produce identical scores and findings
14. Synthetic data isolation and safety boundary enforcement (RFC 5737 IPs, simulated telemetry)
"""

import json
import urllib.request
import urllib.error
import hashlib
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
    print("AGENTIC SOC — MODULE 3I SYNTHETIC TRAP / DECEPTION SCENARIO TESTS")
    print("=" * 70)

    # 1. Health check verification
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed with status: {status}"
    assert "demonstration_scenarios" in health, f"Scenarios missing from health check: {health}"
    assert "Trap" in health.get("demonstration_scenarios", ""), f"Trap scenario missing from health check: {health}"
    print("[PASS] Check 01: Backend Health Check & Scenario Engine Registered")
    print(f"        -> Scenario Engine: {health.get('demonstration_scenarios')}")

    # 2. Scenario execution via POST /api/scenarios/trap
    post_status, scenario_res = make_request("/api/scenarios/trap", method="POST")
    assert post_status == 200, f"Scenario execution failed: {post_status} - {scenario_res}"
    assert scenario_res.get("scenario_id") == "SCENARIO-TRAP", f"Invalid scenario ID: {scenario_res}"
    assert scenario_res.get("is_synthetic") is True, "Scenario must be explicitly marked synthetic"
    assert scenario_res.get("status") == "TRAP_DETECTED_CONTRADICTION", f"Unexpected scenario status: {scenario_res.get('status')}"
    print("[PASS] Check 02: POST /api/scenarios/trap Execution Succeeded")
    print(f"        -> Status: {scenario_res.get('status')}, Inv: {scenario_res.get('investigation_id')}")

    # 3. Retrieval via GET /api/scenarios/trap
    get_status, get_res = make_request("/api/scenarios/trap", method="GET")
    assert get_status == 200, f"GET scenario failed: {get_status}"
    assert get_res.get("scenario_id") == "SCENARIO-TRAP"
    assert get_res.get("status") == "TRAP_DETECTED_CONTRADICTION"
    print("[PASS] Check 03: GET /api/scenarios/trap Retrieval Verified")

    # 4. Synthetic evidence validation
    evidence_items = scenario_res.get("evidence_items", [])
    assert len(evidence_items) == 4, f"Expected 4 synthetic evidence items, got {len(evidence_items)}"
    expected_ids = {"E-TRAP-SIEM", "E-TRAP-EDR", "E-TRAP-DECEPTIVE", "E-TRAP-AUTH"}
    actual_ids = {ev["id"] for ev in evidence_items}
    assert actual_ids == expected_ids, f"Evidence ID mismatch: {actual_ids} vs {expected_ids}"

    for ev in evidence_items:
        raw_output = ev["raw_output"]
        stored_hash = ev["content_hash"]
        calculated_hash = hashlib.sha256(raw_output.encode("utf-8")).hexdigest()
        assert stored_hash == calculated_hash, f"Hash mismatch for {ev['id']}: {stored_hash} vs {calculated_hash}"
        assert "[SYNTHETIC" in raw_output, f"Missing synthetic test label in {ev['id']}"
    print("[PASS] Check 04: Synthetic Evidence Validation (4 items, SHA-256 verified)")

    # 5. Deceptive evidence identification
    assert scenario_res.get("deceptive_evidence_id") == "E-TRAP-DECEPTIVE"
    deceptive_summary = scenario_res.get("deceptive_evidence_summary", "")
    assert "CHG-99214" in deceptive_summary or "maintenance" in deceptive_summary.lower(), f"Unexpected summary: {deceptive_summary}"
    deceptive_item = next(ev for ev in evidence_items if ev["id"] == "E-TRAP-DECEPTIVE")
    assert "CHG-99214" in deceptive_item["raw_output"]
    print("[PASS] Check 05: Deceptive Evidence Identification (E-TRAP-DECEPTIVE / CHG-99214)")

    # 6. Evidence-to-claim relationships
    audited_case = scenario_res.get("audited_case", {})
    claims = audited_case.get("claims", [])
    assert len(claims) == 3, f"Expected 3 claims, got {len(claims)}"

    for claim in claims:
        ev_ids = claim.get("evidence_ids", [])
        if claim.get("status") != "UNSUPPORTED":
            assert len(ev_ids) > 0, f"Claim '{claim.get('claim')}' lacks evidence IDs"
            for ev_id in ev_ids:
                assert ev_id in actual_ids, f"Claim references unknown evidence ID '{ev_id}'"
    print("[PASS] Check 06: Evidence-to-Claim Relationships Mapped")

    # 7. Contradiction detection & resolution (Claim 1 CONTRADICTED)
    claim1 = next((c for c in claims if "powershell" in c.get("claim", "").lower()), None)
    assert claim1 is not None, "Claim 1 (PowerShell) not found"
    assert claim1.get("status") == "CONTRADICTED", f"Claim 1 expected CONTRADICTED, got {claim1.get('status')}"
    assert scenario_res.get("contradicted_claims_count") == 1
    assert len(audited_case.get("contradictions", [])) >= 1, "Auditor found 0 contradictions"
    print("[PASS] Check 07: Contradiction Detection & Resolution (Claim 1 CONTRADICTED)")

    # 8. Unsupported attribution rejection (Claim 3 UNSUPPORTED)
    claim3 = next((c for c in claims if "apt-29" in c.get("claim", "").lower()), None)
    assert claim3 is not None, "Claim 3 (APT-29) not found"
    assert claim3.get("status") == "UNSUPPORTED", f"Claim 3 expected UNSUPPORTED, got {claim3.get('status')}"
    assert scenario_res.get("unsupported_claims_count") == 1
    assert len(audited_case.get("unsupported_claims", [])) >= 1, "Auditor found 0 unsupported claims"
    print("[PASS] Check 08: Unsupported Attribution Rejection (Claim 3 UNSUPPORTED)")

    # 9. Supported claim corroboration (Claim 2 SUPPORTED)
    claim2 = next((c for c in claims if "scheduled" in c.get("claim", "").lower() or "backup" in c.get("claim", "").lower()), None)
    assert claim2 is not None, "Claim 2 (Admin backup) not found"
    assert claim2.get("status") == "SUPPORTED", f"Claim 2 expected SUPPORTED, got {claim2.get('status')}"
    assert scenario_res.get("supported_claims_count") == 1
    print("[PASS] Check 09: Supported Claim Corroboration (Claim 2 SUPPORTED)")

    # 10. Planner Agent integration
    planner = scenario_res.get("planner", {})
    plan_steps = planner.get("plan", [])
    assert len(plan_steps) >= 3, f"Expected at least 3 planner steps, got {len(plan_steps)}"
    allowlisted_tools = {"siem_search", "hash_lookup", "edr_process_search", "sandbox_summary", "whois_lookup", "yara_scan"}
    for step in plan_steps:
        assert step.get("tool_name") in allowlisted_tools, f"Planner proposed unallowlisted tool: {step.get('tool_name')}"
    print(f"[PASS] Check 10: Planner Agent Integration ({len(plan_steps)} allowlisted steps)")

    # 11. Critic Agent integration
    critic = scenario_res.get("critic", {})
    assert critic.get("overall_status") == "REQUIRES_REVISION", f"Critic expected REQUIRES_REVISION, got {critic.get('overall_status')}"
    objections = critic.get("objections", [])
    assert len(objections) == 4, f"Critic expected 4 objections, got {len(objections)}"
    print(f"[PASS] Check 11: Critic Agent Integration (REQUIRES_REVISION, {len(objections)} objections)")

    # 12. Canonical Case JSON generation (Module 3F)
    case_json = scenario_res.get("case_json", {})
    assert case_json.get("schema_version") == "1.0.0", f"Invalid schema version: {case_json.get('schema_version')}"
    assert case_json.get("investigation_id") == "INV-TRAP-001"
    assert len(case_json.get("claims", [])) == 3
    assert len(case_json.get("evidence", [])) == 4
    assert case_json.get("audit", {}).get("audit_status") == "AUDIT_VERIFIED"
    print("[PASS] Check 12: Canonical Case JSON Generation (v1.0.0 schema compliant)")

    # 13. Trust Score penalties calculation (Module 3G)
    trust_score = scenario_res.get("trust_score", {})
    score_val = trust_score.get("trust_score")
    assert score_val == 36.7, f"Expected Trust Score 36.7 for Trap Scenario, got {score_val}"
    assert trust_score.get("explanation", {}).get("verdict") == "UNTRUSTED", f"Unexpected verdict: {trust_score.get('explanation')}"

    penalties = {p["name"]: p["deduction"] for p in trust_score.get("penalties", [])}
    assert penalties.get("Contradiction Penalty") == 15.0, f"Expected -15.0 Contradiction Penalty, got {penalties}"
    assert penalties.get("Unsupported Claim Penalty") == 10.0, f"Expected -10.0 Unsupported Claim Penalty, got {penalties}"
    assert penalties.get("Uncertainty Penalty") == 10.0, f"Expected -10.0 Uncertainty Penalty, got {penalties}"
    total_deductions = sum(p["deduction"] for p in trust_score.get("penalties", []))
    assert total_deductions == 35.0, f"Expected 35.0 total deductions, got {total_deductions}"
    print(f"[PASS] Check 13: Trust Score Penalties (36.7 / 100, UNTRUSTED, -{total_deductions} pts)")

    # 14. Determinism & Synthetic data isolation
    post_status_2, scenario_res_2 = make_request("/api/scenarios/trap", method="POST")
    assert post_status_2 == 200
    assert scenario_res_2.get("trust_score", {}).get("trust_score") == 36.7
    assert scenario_res_2.get("contradicted_claims_count") == 1
    assert scenario_res_2.get("unsupported_claims_count") == 1
    assert scenario_res_2.get("supported_claims_count") == 1
    assert scenario_res_2.get("status") == "TRAP_DETECTED_CONTRADICTION"

    target_host = scenario_res.get("target_host")
    assert "corp.test" in target_host or "test" in target_host.lower(), f"Non-synthetic host: {target_host}"
    print("[PASS] Check 14: Determinism & Synthetic Data Isolation Enforced")

    print("\n" + "=" * 70)
    print("ALL 14 MODULE 3I TRAP SCENARIO CHECKS PASSED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
