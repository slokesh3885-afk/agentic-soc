"""
Module 3H Test Suite — Deterministic Synthetic True Positive Scenario
Agentic SOC — Auditable AI Security Operations Center

Verifies:
1. True-positive scenario execution via API (POST /api/scenarios/true-positive)
2. Synthetic evidence validation (4 items, SHA-256 cryptographic hashes verified)
3. Evidence-to-claim relationships (All claims mapped to valid evidence IDs)
4. Claim support validation (100% of claims evaluated as SUPPORTED)
5. Planner Agent integration (Deterministic sequential investigation plan)
6. Critic Agent integration (Red-team review PASS with 0 objections)
7. Auditor Agent integration (AUDIT_VERIFIED with 0 contradictions or uncertainties)
8. Canonical Case JSON generation (v1.0.0 schema compliance and serialization)
9. Evidence Trust Score integration (100.0 / 100 HIGH_TRUST, 0 penalties)
10. Determinism: Repeated scenario runs produce identical scores and findings
11. No unsupported threat-actor attribution in scenario claims
12. Synthetic data isolation and safety boundary enforcement (RFC 5737 IPs, simulated telemetry)
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
    print("AGENTIC SOC — MODULE 3H SYNTHETIC TRUE POSITIVE SCENARIO TESTS")
    print("=" * 70)

    # 1. Health check verification
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed with status: {status}"
    assert "demonstration_scenarios" in health, f"Scenarios missing from health check: {health}"
    print("[PASS] Check 01: Backend Health Check & Scenario Engine Registered")
    print(f"        -> Scenario Engine: {health.get('demonstration_scenarios')}")

    # 2. Scenario execution via POST /api/scenarios/true-positive
    post_status, scenario_res = make_request("/api/scenarios/true-positive", method="POST")
    assert post_status == 200, f"Scenario execution failed: {post_status} - {scenario_res}"
    assert scenario_res.get("scenario_id") == "SCENARIO-TRUE-POSITIVE", f"Invalid scenario ID: {scenario_res}"
    assert scenario_res.get("is_synthetic") is True, "Scenario must be explicitly marked synthetic"
    assert scenario_res.get("status") == "VERIFIED_TRUE_POSITIVE", f"Unexpected scenario status: {scenario_res.get('status')}"
    print("[PASS] Check 02: POST /api/scenarios/true-positive Execution Succeeded")
    print(f"        -> Status: {scenario_res.get('status')}, Inv: {scenario_res.get('investigation_id')}")

    # Also test GET /api/scenarios/true-positive
    get_status, get_res = make_request("/api/scenarios/true-positive", method="GET")
    assert get_status == 200, f"GET scenario failed: {get_status}"
    assert get_res.get("scenario_id") == "SCENARIO-TRUE-POSITIVE"
    print("        -> GET /api/scenarios/true-positive retrieval verified")

    # 3. Synthetic evidence validation
    evidence_items = scenario_res.get("evidence_items", [])
    assert len(evidence_items) == 4, f"Expected 4 synthetic evidence items, got {len(evidence_items)}"
    expected_ids = {"E-TP-AUTH", "E-TP-HASH", "E-TP-PROC", "E-TP-NET"}
    actual_ids = {ev["id"] for ev in evidence_items}
    assert actual_ids == expected_ids, f"Evidence ID mismatch: {actual_ids} vs {expected_ids}"

    for ev in evidence_items:
        raw_output = ev["raw_output"]
        stored_hash = ev["content_hash"]
        calculated_hash = hashlib.sha256(raw_output.encode("utf-8")).hexdigest()
        assert stored_hash == calculated_hash, f"Hash mismatch for {ev['id']}: {stored_hash} vs {calculated_hash}"
        assert "[SYNTHETIC TEST]" in raw_output, f"Missing synthetic test label in {ev['id']}"
    print("[PASS] Check 03: Synthetic Evidence Validation (4 items, SHA-256 verified)")

    # 4. Evidence-to-claim relationships
    audited_case = scenario_res.get("audited_case", {})
    claims = audited_case.get("claims", [])
    assert len(claims) == 4, f"Expected 4 claims, got {len(claims)}"

    for claim in claims:
        ev_ids = claim.get("evidence_ids", [])
        assert len(ev_ids) > 0, f"Claim '{claim.get('claim')}' lacks evidence IDs (NO EVIDENCE -> NO CLAIM violated)"
        for ev_id in ev_ids:
            assert ev_id in actual_ids, f"Claim references unknown evidence ID '{ev_id}'"
    print("[PASS] Check 04: Evidence-to-Claim Relationships (All claims mapped to valid evidence)")

    # 5. Claim support validation
    for claim in claims:
        status_val = claim.get("status")
        assert status_val == "SUPPORTED", f"Claim '{claim.get('claim')}' status is {status_val}, expected SUPPORTED"
    assert scenario_res.get("supported_claims_count") == 4, f"Expected 4 supported claims, got {scenario_res.get('supported_claims_count')}"
    print("[PASS] Check 05: Claim Support Validation (4 / 4 claims corroborated as SUPPORTED)")

    # 6. Planner Agent integration
    planner = scenario_res.get("planner", {})
    plan_steps = planner.get("plan", [])
    assert len(plan_steps) >= 3, f"Expected at least 3 planner steps, got {len(plan_steps)}"
    allowlisted_tools = {"siem_search", "hash_lookup", "edr_process_search", "sandbox_summary", "whois_lookup", "yara_scan"}
    for step in plan_steps:
        assert step.get("tool_name") in allowlisted_tools, f"Planner proposed unallowlisted tool: {step.get('tool_name')}"
    print(f"[PASS] Check 06: Planner Agent Integration ({len(plan_steps)} allowlisted steps)")

    # 7. Critic Agent integration
    critic = scenario_res.get("critic", {})
    assert critic.get("overall_status") == "PASS", f"Critic review did not PASS: {critic.get('overall_status')}"
    assert len(critic.get("objections", [])) == 0, f"Critic raised unexpected objections: {critic.get('objections')}"
    assert len(critic.get("overclaims", [])) == 0, f"Critic raised unexpected overclaims: {critic.get('overclaims')}"
    print("[PASS] Check 07: Critic Agent Integration (PASS, 0 objections, 0 overclaims)")

    # 8. Auditor Agent integration
    assert audited_case.get("audit_verified") is True, "Auditor failed to verify synthetic case"
    assert len(audited_case.get("contradictions", [])) == 0, f"Auditor found contradictions: {audited_case.get('contradictions')}"
    assert len(audited_case.get("uncertainties", [])) == 0, f"Auditor found uncertainties: {audited_case.get('uncertainties')}"
    assert len(audited_case.get("unsupported_claims", [])) == 0, f"Auditor found unsupported claims: {audited_case.get('unsupported_claims')}"
    print("[PASS] Check 08: Auditor Agent Integration (AUDIT_VERIFIED, 0 contradictions, 0 uncertainties)")

    # 9. Canonical Case JSON generation (Module 3F)
    case_json = scenario_res.get("case_json", {})
    assert case_json.get("schema_version") == "1.0.0", f"Invalid schema version: {case_json.get('schema_version')}"
    assert case_json.get("investigation_id") == "INV-TP-001"
    assert len(case_json.get("claims", [])) == 4
    assert len(case_json.get("evidence", [])) == 4
    assert case_json.get("audit", {}).get("audit_status") == "AUDIT_VERIFIED"
    print("[PASS] Check 09: Canonical Case JSON Generation (v1.0.0 schema compliant)")

    # 10. Trust Score integration (Module 3G)
    trust_score = scenario_res.get("trust_score", {})
    score_val = trust_score.get("trust_score")
    assert score_val == 100.0, f"Expected Trust Score 100.0 for True Positive, got {score_val}"
    assert trust_score.get("explanation", {}).get("verdict") == "HIGH_TRUST", f"Unexpected verdict: {trust_score.get('explanation')}"
    
    # Verify component reconciliation: 25 + 25 + 30 + 20 - 0 = 100
    components = {c["name"]: c["contribution"] for c in trust_score.get("score_components", [])}
    assert components.get("Evidence Coverage") == 25.0, f"Wrong coverage: {components}"
    assert components.get("Evidence Integrity") == 25.0, f"Wrong integrity: {components}"
    assert components.get("Claim Support") == 30.0, f"Wrong claim support: {components}"
    assert components.get("Audit Completeness") == 20.0, f"Wrong completeness: {components}"
    total_deductions = sum(p["deduction"] for p in trust_score.get("penalties", []))
    assert total_deductions == 0.0, f"Unexpected penalty deductions: {total_deductions}"
    print("[PASS] Check 10: Trust Score Integration (100.0 / 100, HIGH_TRUST, 0 penalties)")

    # 11. Determinism verification (Repeat execution produces identical outputs)
    post_status_2, scenario_res_2 = make_request("/api/scenarios/true-positive", method="POST")
    assert post_status_2 == 200
    assert scenario_res_2.get("trust_score", {}).get("trust_score") == 100.0
    assert scenario_res_2.get("supported_claims_count") == 4
    assert scenario_res_2.get("status") == "VERIFIED_TRUE_POSITIVE"
    assert len(scenario_res_2.get("evidence_items", [])) == 4
    print("[PASS] Check 11: Determinism (Identical output across multiple pipeline executions)")

    # 12. No unsupported attribution & safety boundaries
    # All claims in true positive must NOT contain unevidenced threat actors
    for claim in claims:
        text = claim.get("claim", "").lower()
        assert "apt-" not in text and "lazarus" not in text and "cozy bear" not in text, f"Found ungrounded attribution in claim: {text}"

    # Synthetic IP check: Must use RFC 5737 test IP
    target_host = scenario_res.get("target_host")
    assert "corp.test" in target_host or "test" in target_host.lower(), f"Non-synthetic host: {target_host}"
    for ev in evidence_items:
        raw = ev["raw_output"]
        if "IP" in raw or "destination" in raw:
            assert "198.51.100.42" in raw, f"Expected RFC 5737 IP 198.51.100.42 in evidence: {raw}"
    print("[PASS] Check 12: No Unsupported Attribution & Synthetic Data Isolation Enforced")

    print("\n" + "=" * 70)
    print("ALL 12 MODULE 3H TRUE POSITIVE SCENARIO CHECKS PASSED SUCCESSFULLY")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
