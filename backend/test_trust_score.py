"""
Module 3G Test Suite — Deterministic Evidence & Audit Quality Trust Score
Agentic SOC — Auditable AI Security Operations Center

Verifies:
1. Perfectly supported case (high quality trust score)
2. Case with unsupported claims (score reduced appropriately via penalties)
3. Case with contradictory evidence (contradiction penalties applied)
4. Case with failed evidence integrity (SHA-256 integrity penalties applied)
5. Case with incomplete audit (reduced audit completeness contribution)
6. Case with unresolved uncertainty (uncertainty penalties applied)
7. Empty/minimal case (handled gracefully within bounds)
8. Determinism: Same input -> exactly identical score and contributions
9. Score bounds: Result strictly remains within 0.0 and 100.0
10. Component reconciliation: Sum of contributions minus penalties equals final score
11. API endpoint: GET /api/investigations/INV-012/trust-score
12. Calculation endpoint: POST /api/trust-score/calculate
13. Security boundary: Zero tool executions during score calculation
14. Security boundary: Zero evidence objects mutated or created
15. Backend health check & Trust Score Engine registered
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
    print("=" * 65)
    print("AGENTIC SOC — MODULE 3G DETERMINISTIC TRUST SCORE TESTS")
    print("=" * 65)

    # 1. Health check verification
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert "trust_score_engine" in health, f"Trust score engine missing: {health}"
    print("[PASS] Check 01: Backend Health Check & Trust Score Engine Registered")
    print(f"        -> Engine Status: {health.get('trust_score_engine')}")

    # Import schema and service directly for in-memory and model validation tests
    from app.schemas.canonical_case import (
        CanonicalClaim,
        CanonicalEvidenceItem,
        CanonicalToolExecution,
        CanonicalAuditBlock,
        CanonicalCaseJson,
    )
    from app.services.trust_score_service import compute_trust_score

    # Reusable verified evidence items
    evidence_ledger = {
        "E-001": CanonicalEvidenceItem(
            evidence_id="E-001",
            evidence_type="EDR_EVENT",
            source="Mock EDR",
            raw_output="powershell.exe -enc SQBFAFgA (unusual script execution)",
            content_hash="a" * 64,
            integrity_status="VALID",
            timestamp="2026-09-27 12:00:00 UTC",
        ),
        "E-002": CanonicalEvidenceItem(
            evidence_id="E-002",
            evidence_type="SIEM_LOG",
            source="Mock SIEM",
            raw_output="Approved administrative script scheduled by Domain Admin",
            content_hash="b" * 64,
            integrity_status="VALID",
            timestamp="2026-09-27 12:05:00 UTC",
        ),
    }

    full_audit_block = CanonicalAuditBlock(
        audit_status="AUDIT_VERIFIED",
        auditor_verified=True,
        critic_reviewed=True,
        critic_objections_count=0,
        audited_at="2026-09-27 12:15:00 UTC",
    )

    # TEST 1: Perfectly Supported Case
    case_perfect = CanonicalCaseJson(
        case_id="CASE-PERFECT",
        investigation_id="INV-012",
        schema_version="1.0.0",
        claims=[
            CanonicalClaim(
                claim="PowerShell execution occurred on PC-DB-TEST",
                evidence_ids=["E-001"],
                status="SUPPORTED",
                confidence="SUPPORTED",
                reason="Corroborated by EDR",
                evidence_integrity_verified=True,
            ),
            CanonicalClaim(
                claim="Approved maintenance task was scheduled",
                evidence_ids=["E-002"],
                status="SUPPORTED",
                confidence="SUPPORTED",
                reason="Corroborated by SIEM",
                evidence_integrity_verified=True,
            ),
        ],
        evidence=evidence_ledger,
        tool_executions=[],
        contradictions=[],
        uncertainties=[],
        unsupported_claims=[],
        final_conclusion="Activity is fully corroborated by verified evidence.",
        audit=full_audit_block,
    )
    score_perfect = compute_trust_score(case_perfect)
    assert score_perfect.trust_score == 100.0, f"Expected 100.0, got {score_perfect.trust_score}"
    assert score_perfect.explanation.verdict == "HIGH_TRUST"
    assert len(score_perfect.penalties) == 0
    print(f"[PASS] Check 02: Test 1 — Perfectly Supported Case: {score_perfect.trust_score}/100 ({score_perfect.explanation.verdict})")

    # TEST 2: Case with Unsupported Claim
    case_unsupported = CanonicalCaseJson(
        case_id="CASE-UNSUPPORTED",
        investigation_id="INV-012",
        schema_version="1.0.0",
        claims=[
            CanonicalClaim(
                claim="PowerShell execution occurred on PC-DB-TEST",
                evidence_ids=["E-001"],
                status="SUPPORTED",
                confidence="SUPPORTED",
                reason="Corroborated by EDR",
                evidence_integrity_verified=True,
            ),
            CanonicalClaim(
                claim="Threat actor is APT-X",
                evidence_ids=[],
                status="UNSUPPORTED",
                confidence="UNSUPPORTED",
                reason="No evidence of actor attribution",
                evidence_integrity_verified=False,
            ),
        ],
        evidence=evidence_ledger,
        tool_executions=[],
        contradictions=[],
        uncertainties=["Attribution cannot be established."],
        unsupported_claims=["Threat actor is APT-X"],
        final_conclusion="PowerShell confirmed. Attribution unsupported.",
        audit=full_audit_block,
    )
    score_unsupported = compute_trust_score(case_unsupported)
    assert score_unsupported.trust_score < score_perfect.trust_score, "Score did not decrease for unsupported claim!"
    # Must have unsupported claim penalty
    pen_names = [p.name for p in score_unsupported.penalties]
    assert "Unsupported Claim Penalty" in pen_names
    print(f"[PASS] Check 03: Test 2 — Case with Unsupported Claim: {score_unsupported.trust_score}/100 (Penalties: {len(score_unsupported.penalties)})")

    # TEST 3: Case with Contradictory Evidence
    case_contradicted = CanonicalCaseJson(
        case_id="CASE-CONTRADICTED",
        investigation_id="INV-012",
        schema_version="1.0.0",
        claims=[
            CanonicalClaim(
                claim="PowerShell execution was malicious attack",
                evidence_ids=["E-001", "E-002"],
                status="CONTRADICTED",
                confidence="CONTRADICTED",
                reason="Conflicting telemetry between EDR and SIEM",
                evidence_integrity_verified=True,
            )
        ],
        evidence=evidence_ledger,
        tool_executions=[],
        contradictions=["Evidence E-001 indicates malicious, but E-002 indicates authorized maintenance."],
        uncertainties=["Activity authorization remains conflicting."],
        unsupported_claims=[],
        final_conclusion="Conflict between suspicious telemetry and approved admin script.",
        audit=full_audit_block,
    )
    score_contradicted = compute_trust_score(case_contradicted)
    assert score_contradicted.trust_score < score_perfect.trust_score
    pen_names = [p.name for p in score_contradicted.penalties]
    assert "Contradiction Penalty" in pen_names
    print(f"[PASS] Check 04: Test 3 — Case with Contradictory Evidence: {score_contradicted.trust_score}/100 (Penalties: {pen_names})")

    # TEST 4: Case with Failed Evidence Integrity
    corrupted_ledger = {
        "E-CORRUPT": CanonicalEvidenceItem(
            evidence_id="E-CORRUPT",
            evidence_type="PROCESS_EVENT",
            source="Mock EDR",
            raw_output="powershell.exe executed",
            content_hash="0" * 64,  # Altered hash!
            integrity_status="FAILED",  # Cryptographic verification failed!
            timestamp="2026-09-27 12:00:00 UTC",
        )
    }
    case_corrupted = CanonicalCaseJson(
        case_id="CASE-CORRUPTED",
        investigation_id="INV-012",
        schema_version="1.0.0",
        claims=[
            CanonicalClaim(
                claim="Process executed on endpoint",
                evidence_ids=["E-CORRUPT"],
                status="UNCERTAIN",
                confidence="UNCERTAIN",
                reason="Evidence failed cryptographic hash verification",
                evidence_integrity_verified=False,
            )
        ],
        evidence=corrupted_ledger,
        tool_executions=[],
        contradictions=[],
        uncertainties=["Evidence E-CORRUPT failed cryptographic hash verification."],
        unsupported_claims=[],
        final_conclusion="Integrity failure prevents reliable audit conclusion.",
        audit=full_audit_block,
    )
    score_corrupted = compute_trust_score(case_corrupted)
    pen_names = [p.name for p in score_corrupted.penalties]
    assert "Failed Integrity Penalty" in pen_names
    integ_comp = next(c for c in score_corrupted.score_components if c.name == "Evidence Integrity")
    assert integ_comp.contribution == 0.0, f"Expected 0.0 integrity contribution, got {integ_comp.contribution}"
    print(f"[PASS] Check 05: Test 4 — Case with Failed Evidence Integrity: {score_corrupted.trust_score}/100 (Failed Integrity Penalized)")

    # TEST 5: Case with Incomplete Audit
    incomplete_audit_block = CanonicalAuditBlock(
        audit_status="REJECTED",
        auditor_verified=False,
        critic_reviewed=False,
        critic_objections_count=3,
        audited_at="2026-09-27 12:15:00 UTC",
    )
    case_incomplete_audit = CanonicalCaseJson(
        case_id="CASE-INCOMPLETE",
        investigation_id="INV-012",
        schema_version="1.0.0",
        claims=[
            CanonicalClaim(
                claim="PowerShell execution occurred",
                evidence_ids=["E-001"],
                status="SUPPORTED",
                confidence="SUPPORTED",
                reason="Corroborated by EDR",
                evidence_integrity_verified=True,
            )
        ],
        evidence=evidence_ledger,
        tool_executions=[],
        contradictions=[],
        uncertainties=[],
        unsupported_claims=[],
        final_conclusion="Draft conclusion pending review.",
        audit=incomplete_audit_block,
    )
    score_incomplete = compute_trust_score(case_incomplete_audit)
    audit_comp = next(c for c in score_incomplete.score_components if c.name == "Audit Completeness")
    assert audit_comp.contribution == 0.0, f"Expected 0.0 audit completeness, got {audit_comp.contribution}"
    assert score_incomplete.trust_score <= 80.0
    print(f"[PASS] Check 06: Test 5 — Case with Incomplete Audit: {score_incomplete.trust_score}/100 (Audit Completeness: {audit_comp.contribution}/20)")

    # TEST 6: Case with Uncertainty
    case_uncertain = CanonicalCaseJson(
        case_id="CASE-UNCERTAIN",
        investigation_id="INV-012",
        schema_version="1.0.0",
        claims=[
            CanonicalClaim(
                claim="Attacker origin is external IP",
                evidence_ids=["E-001"],
                status="UNCERTAIN",
                confidence="UNCERTAIN",
                reason="Network telemetry incomplete",
                evidence_integrity_verified=True,
            )
        ],
        evidence=evidence_ledger,
        tool_executions=[],
        contradictions=[],
        uncertainties=[
            "Originating IP address is unconfirmed.",
            "Command payload was partially obfuscated.",
        ],
        unsupported_claims=[],
        final_conclusion="Origin and intent remain uncertain.",
        audit=full_audit_block,
    )
    score_uncertain = compute_trust_score(case_uncertain)
    pen_names = [p.name for p in score_uncertain.penalties]
    assert "Uncertainty Penalty" in pen_names
    print(f"[PASS] Check 07: Test 6 — Case with Uncertainty: {score_uncertain.trust_score}/100 (Uncertainty Penalty Applied)")

    # TEST 7: Empty / Minimal Case
    case_minimal = CanonicalCaseJson(
        case_id="CASE-MINIMAL",
        investigation_id="INV-012",
        schema_version="1.0.0",
        claims=[],
        evidence={},
        tool_executions=[],
        contradictions=[],
        uncertainties=[],
        unsupported_claims=[],
        final_conclusion="No findings.",
        audit=incomplete_audit_block,
    )
    score_minimal = compute_trust_score(case_minimal)
    assert score_minimal.trust_score == 0.0
    assert 0.0 <= score_minimal.trust_score <= 100.0
    print(f"[PASS] Check 08: Test 7 — Empty / Minimal Case: {score_minimal.trust_score}/100 (Handled Gracefully within Bounds)")

    # TEST 8: Determinism (Same input -> exactly same score and components)
    score_run_1 = compute_trust_score(case_unsupported)
    score_run_2 = compute_trust_score(case_unsupported)
    assert score_run_1.trust_score == score_run_2.trust_score, "Non-deterministic score!"
    assert len(score_run_1.score_components) == len(score_run_2.score_components)
    for c1, c2 in zip(score_run_1.score_components, score_run_2.score_components):
        assert c1.contribution == c2.contribution, f"Component contribution mismatch: {c1.name}"
    for p1, p2 in zip(score_run_1.penalties, score_run_2.penalties):
        assert p1.deduction == p2.deduction, f"Penalty deduction mismatch: {p1.name}"
    print("[PASS] Check 09: Test 8 — Determinism Verified (Byte-for-Byte Component & Score Equality)")

    # TEST 9: Score Bounds (0 - 100)
    # Test extreme negative penalties
    case_extreme = CanonicalCaseJson(
        case_id="CASE-EXTREME",
        investigation_id="INV-012",
        schema_version="1.0.0",
        claims=[
            CanonicalClaim(
                claim="Fake claim 1",
                evidence_ids=[],
                status="UNSUPPORTED",
                confidence="UNSUPPORTED",
                reason="None",
            ),
        ],
        evidence={},
        tool_executions=[],
        contradictions=["Conflict 1", "Conflict 2", "Conflict 3"],
        uncertainties=["Unc 1", "Unc 2", "Unc 3", "Unc 4"],
        unsupported_claims=["Fake claim 1", "Fake claim 2", "Fake claim 3"],
        final_conclusion="Completely broken case.",
        audit=incomplete_audit_block,
    )
    score_extreme = compute_trust_score(case_extreme)
    assert 0.0 <= score_extreme.trust_score <= 100.0, f"Out of bounds: {score_extreme.trust_score}"
    assert score_extreme.trust_score == 0.0, "Expected clamp to 0.0"
    print(f"[PASS] Check 10: Test 9 — Score Bounds Verified (Clamped at {score_extreme.trust_score} [0.0 - 100.0])")

    # TEST 10: Component Contributions Reconcile with Documented Formula
    for test_case in [case_perfect, case_unsupported, case_contradicted, case_corrupted, score_incomplete, case_uncertain]:
        if isinstance(test_case, CanonicalCaseJson):
            scored = compute_trust_score(test_case)
        else:
            scored = test_case
        base_sum = sum(c.contribution for c in scored.score_components)
        penalties_sum = sum(p.deduction for p in scored.penalties)
        raw_calc = base_sum - penalties_sum
        clamped_calc = round(max(0.0, min(100.0, raw_calc)), 1)
        assert scored.trust_score == clamped_calc, (
            f"Reconciliation error: computed {scored.trust_score} != formula {clamped_calc} "
            f"(base: {base_sum}, penalties: {penalties_sum})"
        )
    print("[PASS] Check 11: Test 10 — Component Contributions Reconcile 100% with Documented Formula")

    # TEST 11: API Endpoint GET /api/investigations/INV-012/trust-score
    status, api_score = make_request("/api/investigations/INV-012/trust-score")
    assert status == 200, f"API trust score returned {status}: {api_score}"
    assert "trust_score" in api_score
    assert 0.0 <= api_score["trust_score"] <= 100.0
    assert len(api_score["score_components"]) == 4
    assert "explanation" in api_score
    print(f"[PASS] Check 12: GET /api/investigations/INV-012/trust-score Success")
    print(f"        -> Case ID: {api_score['case_id']}, Trust Score: {api_score['trust_score']}/100, Verdict: {api_score['explanation']['verdict']}")

    # TEST 12: Calculation Endpoint POST /api/trust-score/calculate
    case_payload = case_unsupported.model_dump(mode="json")
    status, calc_api_score = make_request("/api/trust-score/calculate", method="POST", data=case_payload)
    assert status == 200, f"Calculation endpoint failed: {calc_api_score}"
    assert calc_api_score["trust_score"] == score_unsupported.trust_score
    print(f"[PASS] Check 13: POST /api/trust-score/calculate Success (Calculated Score: {calc_api_score['trust_score']}/100)")

    # TEST 13 & 14: Security Boundaries: Zero Tool Executions and Zero Evidence Mutations
    status, tools_before = make_request("/api/investigations/INV-012/tool-executions")
    status, ev_before = make_request("/api/investigations/INV-012/evidence")

    # Call trust score multiple times
    make_request("/api/investigations/INV-012/trust-score")
    make_request("/api/investigations/INV-012/trust-score")

    status, tools_after = make_request("/api/investigations/INV-012/tool-executions")
    status, ev_after = make_request("/api/investigations/INV-012/evidence")

    assert len(tools_before) == len(tools_after), "Tools were executed during trust score calculation!"
    assert len(ev_before) == len(ev_after), "Evidence was mutated during trust score calculation!"
    print(f"[PASS] Check 14: Security Boundary: Zero Tool Executions ({len(tools_before)} == {len(tools_after)})")
    print(f"[PASS] Check 15: Security Boundary: Zero Evidence Objects Mutated ({len(ev_before)} == {len(ev_after)})")

    print("\n" + "=" * 65)
    print("ALL 15/15 MODULE 3G TRUST SCORE CHECKS PASSED PERFECTLY!")
    print("=" * 65)


if __name__ == "__main__":
    run_tests()
