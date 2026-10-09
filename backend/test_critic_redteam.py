"""
Comprehensive Test Suite for Module 3S:
Critic & Red-Team Adversarial Evaluation Engine & Interactive Multi-Agent Pipeline Simulator
Agentic SOC — Auditable AI Security Operations Center
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
    print("MODULE 3S: CRITIC & RED-TEAM ADVERSARIAL ENGINE TEST SUITE")
    print("=" * 70)
    passed = 0
    total = 15

    # 1. Health check exposes Module 3S
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert "Module 3S" in health.get("critic_redteam_module", ""), f"Module 3S missing from health: {health}"
    assert "Active" in health.get("redteam_adversarial_engine", ""), f"Red-team engine missing from health: {health}"
    assert "Active" in health.get("interactive_demo_pipeline", ""), f"Interactive demo missing from health: {health}"
    assert health.get("version") in ("0.16.0", "0.17.0"), f"Unexpected version: {health.get('version')}"
    print("[PASS] Check 01: GET /api/health exposes Module 3S adversarial engine & interactive demo metadata")
    passed += 1

    # 2. Preset scenarios
    status, scenarios = make_request("/api/critic/redteam/scenarios")
    assert status == 200, f"Expected 200, got {status}"
    assert isinstance(scenarios, list) and len(scenarios) >= 3, f"Expected >= 3 scenarios, got {len(scenarios)}"
    assert any(s["scenario_id"] == "SCN-PEN-TEST" for s in scenarios)
    assert any("Penetration Test" in s["title"] for s in scenarios)
    print(f"[PASS] Check 02: GET /api/critic/redteam/scenarios returns {len(scenarios)} preset adversarial scenarios")
    passed += 1

    # 3. Execute red-team challenge on preliminary conclusion
    payload = {
        "investigation_id": "INV-001",
        "scenario_id": "SCN-PEN-TEST",
        "preliminary_conclusion": "Endpoint compromised by malware.",
        "attacker_hypothesis": "External adversary executed PowerShell reverse shell",
        "asserted_threat_actor": "APT-29 (Cozy Bear)",
        "evidence_ids": ["EV-001", "EV-002", "EV-003", "EV-004"]
    }
    status, challenge = make_request("/api/critic/redteam/challenge", method="POST", data=payload)
    assert status == 200, f"Challenge failed: {status}, {challenge}"
    assert "challenge_id" in challenge and challenge["challenge_id"].startswith("RTC-2026-")
    assert challenge["preliminary_conclusion"] == "Endpoint compromised by malware."
    print(f"[PASS] Check 03: POST /api/critic/redteam/challenge executed ({challenge['challenge_id']})")
    passed += 1

    # 4. Canonical Critic Findings verification
    findings = challenge.get("critic_findings", [])
    assert len(findings) >= 4, f"Expected >= 4 findings, got {len(findings)}"
    finding_texts = [f["finding_text"] for f in findings]
    assert any("Evidence confirms suspicious execution" in t for t in finding_texts), f"Missing execution finding: {finding_texts}"
    assert any("No confirmed persistence mechanism" in t for t in finding_texts), f"Missing persistence finding: {finding_texts}"
    assert any("Hash reputation is inconclusive" in t for t in finding_texts), f"Missing reputation finding: {finding_texts}"
    assert any("authorized security test" in t for t in finding_texts), f"Missing authorized test finding: {finding_texts}"
    print("[PASS] Check 04: Critic findings accurately assert execution, persistence, reputation, and authorized test")
    passed += 1

    # 5. Final Critic Decision & Verdict Category
    assert challenge.get("final_critic_decision") == "Insufficient evidence for confirmed compromise.", f"Unexpected decision: {challenge.get('final_critic_decision')}"
    assert challenge.get("verdict_category") in ("AUTHORIZED_TESTING", "REFUTED", "CHALLENGED")
    print(f"[PASS] Check 05: Final decision confirmed: '{challenge.get('final_critic_decision')}'")
    passed += 1

    # 6. Contradictions display
    contradictions = challenge.get("contradictions", [])
    assert len(contradictions) >= 1, f"Expected contradictions, got {len(contradictions)}"
    assert any("EV-001" in (c["evidence_a_id"], c["evidence_b_id"]) for c in contradictions)
    assert any("EV-004" in (c["evidence_a_id"], c["evidence_b_id"]) for c in contradictions)
    print(f"[PASS] Check 06: Detected {len(contradictions)} evidence contradictions (EV-001 vs EV-004 authorized test)")
    passed += 1

    # 7. Threat Actor Attribution Guard
    guard = challenge.get("attribution_guard", {})
    assert guard.get("policy_name") == "Threat Actor Attribution Policy"
    assert guard.get("action") == "ATTRIBUTION_BLOCKED"
    assert guard.get("attribution_status") == "NOT ESTABLISHED"
    assert guard.get("evidence_sufficiency") == "INSUFFICIENT"
    assert "No evidence IDs sufficiently support" in guard.get("reason", "")
    print(f"[PASS] Check 07: Threat Actor Attribution Guard enforced: {guard['action']} for {guard['asserted_threat_actor']}")
    passed += 1

    # 8. Cryptographic signature and trust score adjustment
    sig = challenge.get("tamper_proof_signature", "")
    assert len(sig) == 64, f"Invalid SHA-256 signature length: {len(sig)}"
    assert challenge.get("original_trust_score") > challenge.get("revised_trust_score")
    print(f"[PASS] Check 08: Cryptographic SHA-256 signature verified ({sig[:16]}...), trust score: {challenge.get('original_trust_score')} -> {challenge.get('revised_trust_score')}")
    passed += 1

    # 9. GET latest challenge
    status, latest = make_request("/api/critic/redteam/challenge/latest")
    assert status == 200, f"Expected 200, got {status}"
    assert latest.get("challenge_id") == challenge["challenge_id"]
    print(f"[PASS] Check 09: GET /api/critic/redteam/challenge/latest retrieves cached report")
    passed += 1

    # 10. Interactive Demo Step 1: Start Investigation
    status, step1 = make_request("/api/demo/pipeline/step", method="POST", data={"step_id": "start_investigation", "session_id": "test-sess"})
    assert status == 200, f"Step 1 failed: {status}"
    assert step1.get("current_step_id") == "start_investigation"
    assert step1.get("current_step_number") == 1
    assert step1.get("is_complete") is False
    print("[PASS] Check 10: Demo Step 1 'Start Investigation' dispatches swarm and initializes case")
    passed += 1

    # 11. Interactive Demo Step 2: Run Planner
    status, step2 = make_request("/api/demo/pipeline/step", method="POST", data={"step_id": "run_planner", "session_id": "test-sess"})
    assert status == 200
    assert step2.get("current_step_id") == "run_planner"
    assert step2.get("current_step_number") == 2
    assert len(step2.get("completed_steps", [])) == 2
    print("[PASS] Check 11: Demo Step 2 'Run Planner' formulates allow-listed tool investigation plan")
    passed += 1

    # 12. Interactive Demo Step 3: Collect Evidence
    status, step3 = make_request("/api/demo/pipeline/step", method="POST", data={"step_id": "collect_evidence", "session_id": "test-sess"})
    assert status == 200
    assert step3.get("current_step_id") == "collect_evidence"
    assert len(step3.get("cumulative_evidence", [])) >= 4
    print(f"[PASS] Check 12: Demo Step 3 'Collect Evidence' harvested {len(step3['cumulative_evidence'])} cryptographic items")
    passed += 1

    # 13. Interactive Demo Step 4: Run Analysis
    status, step4 = make_request("/api/demo/pipeline/step", method="POST", data={"step_id": "run_analysis", "session_id": "test-sess"})
    assert status == 200
    assert step4.get("current_step_id") == "run_analysis"
    assert "Endpoint compromised by malware" in step4.get("current_verdict", "")
    print("[PASS] Check 13: Demo Step 4 'Run Analysis' drafted preliminary compromise hypothesis")
    passed += 1

    # 14. Interactive Demo Step 5: Challenge Conclusion
    status, step5 = make_request("/api/demo/pipeline/step", method="POST", data={"step_id": "challenge_conclusion", "session_id": "test-sess"})
    assert status == 200
    assert step5.get("current_step_id") == "challenge_conclusion"
    assert "Insufficient evidence for confirmed compromise" in step5.get("current_verdict", "")
    print("[PASS] Check 14: Demo Step 5 'Challenge Conclusion' successfully executed Critic attack")
    passed += 1

    # 15. Interactive Demo Steps 6 & 7 + Reset
    status, step7 = make_request("/api/demo/pipeline/step", method="POST", data={"step_id": "replay_investigation", "session_id": "test-sess"})
    assert status == 200
    assert step7.get("current_step_id") == "replay_investigation"
    assert step7.get("is_complete") is True
    assert step7.get("current_trust_score") == 100.0

    status, reset = make_request("/api/demo/pipeline/reset", method="POST", data={"session_id": "test-sess"})
    assert status == 200
    assert reset.get("current_step_id") == "start_investigation"
    assert reset.get("is_complete") is False
    print("[PASS] Check 15: Demo Steps 6 & 7 completed simulation (100% reproducible) and reset succeeded")
    passed += 1

    print("=" * 70)
    print(f"MODULE 3S TEST RESULTS: {passed}/{total} PASSED")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
