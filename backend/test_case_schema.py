"""
Module 3F Test Suite — Canonical Case JSON Schema Verification
Agentic SOC — Auditable AI Security Operations Center

Verifies:
1. Backend health check & schema registration
2. Canonical Case JSON validation with complete valid payload
3. SUPPORTED claims validation (with valid evidence IDs)
4. UNSUPPORTED claims validation (empty and populated evidence IDs)
5. CONTRADICTED claims validation
6. UNCERTAIN claims validation
7. Rejection of invalid evidence references (referenced ID not in evidence ledger)
8. Rejection of SUPPORTED claims without evidence (NO EVIDENCE -> NO CLAIM)
9. Rejection of missing required fields (e.g., case_id, audit)
10. Rejection of invalid claim status literals
11. Deterministic canonical JSON serialization (byte-for-byte sorted keys)
12. Auditor integration: GET /api/investigations/INV-012/case-json
13. Case validation endpoint: POST /api/case-json/validate
14. Investigation validation endpoint: POST /api/investigations/INV-012/case-json/validate
15. Zero side-effects boundary (read-only case export)
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
    print("AGENTIC SOC — MODULE 3F CANONICAL CASE JSON SCHEMA TESTS")
    print("=" * 65)

    # 1. Health check verification
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert health.get("module") == "Module 3F: Case JSON Schema", f"Wrong module: {health}"
    assert "Canonical Deterministic Case JSON" in health.get("case_json_schema", ""), f"Schema not active: {health}"
    print("[PASS] Check 01: Backend Health Check & Case JSON Schema Registered")
    print(f"        -> Version: {health.get('version')}, Module: {health.get('module')}")

    # Import schema directly for in-memory and model validation tests
    from app.schemas.canonical_case import (
        CanonicalClaim,
        CanonicalEvidenceItem,
        CanonicalToolExecution,
        CanonicalAuditBlock,
        CanonicalCaseJson,
        CaseJsonValidationResponse,
    )
    from pydantic import ValidationError

    # Sample verified evidence items
    sample_evidence = {
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

    sample_tools = [
        CanonicalToolExecution(
            execution_id="EXEC-001",
            tool_name="edr_process_search",
            input={"host": "PC-DB-TEST", "process": "powershell.exe"},
            output={"found": True, "pid": 4820},
            success=True,
            timestamp="2026-09-27 12:00:00 UTC",
            evidence_id="E-001",
        )
    ]

    sample_audit = CanonicalAuditBlock(
        audit_status="AUDIT_VERIFIED",
        auditor_verified=True,
        critic_reviewed=True,
        critic_objections_count=1,
        audited_at="2026-09-27 12:15:00 UTC",
    )

    # 2. Complete Valid Canonical Case JSON
    valid_claims = [
        CanonicalClaim(
            claim="PowerShell execution occurred on PC-DB-TEST",
            evidence_ids=["E-001"],
            status="SUPPORTED",
            confidence="SUPPORTED",
            reason="Verified by EDR telemetry (E-001).",
            evidence_integrity_verified=True,
        ),
        CanonicalClaim(
            claim="Threat actor is APT-X",
            evidence_ids=[],
            status="UNSUPPORTED",
            confidence="UNSUPPORTED",
            reason="No evidence provided to support threat-actor attribution.",
            evidence_integrity_verified=False,
        ),
    ]

    case1 = CanonicalCaseJson(
        case_id="CASE-001",
        investigation_id="INV-012",
        schema_version="1.0.0",
        claims=valid_claims,
        evidence=sample_evidence,
        tool_executions=sample_tools,
        contradictions=[],
        uncertainties=["Attribution cannot be established."],
        unsupported_claims=["Threat actor is APT-X"],
        final_conclusion="Suspicious PowerShell activity confirmed. Attribution unsupported.",
        audit=sample_audit,
    )
    assert case1.case_id == "CASE-001"
    assert case1.schema_version == "1.0.0"
    print("[PASS] Check 02: Valid Canonical Case JSON Instantiated & Validated")

    # 3. Check SUPPORTED Claims Work
    claim_supported = CanonicalClaim(
        claim="Endpoint established suspicious connection",
        evidence_ids=["E-001"],
        status="SUPPORTED",
        confidence="SUPPORTED",
        reason="corroborated by E-001",
        evidence_integrity_verified=True,
    )
    assert claim_supported.status == "SUPPORTED"
    assert len(claim_supported.evidence_ids) == 1
    print("[PASS] Check 03: SUPPORTED Claims Work with Evidence Reference")

    # 4. Check UNSUPPORTED Claims Work (empty and non-empty evidence IDs)
    claim_unsupported_empty = CanonicalClaim(
        claim="Lateral movement occurred across domain",
        evidence_ids=[],
        status="UNSUPPORTED",
        confidence="UNSUPPORTED",
        reason="No evidence of lateral movement found.",
        evidence_integrity_verified=False,
    )
    assert claim_unsupported_empty.status == "UNSUPPORTED"
    assert len(claim_unsupported_empty.evidence_ids) == 0

    claim_unsupported_with_ev = CanonicalClaim(
        claim="Attribution to Lazarus group",
        evidence_ids=["E-001"],
        status="UNSUPPORTED",
        confidence="UNSUPPORTED",
        reason="Evidence E-001 shows script execution but does not establish Lazarus attribution.",
        evidence_integrity_verified=True,
    )
    assert claim_unsupported_with_ev.status == "UNSUPPORTED"
    print("[PASS] Check 04: UNSUPPORTED Claims Work (Both Empty & Evaluated Evidence IDs)")

    # 5. Check CONTRADICTED Claims Work
    claim_contradicted = CanonicalClaim(
        claim="Execution was malicious unauthorized attack",
        evidence_ids=["E-001", "E-002"],
        status="CONTRADICTED",
        confidence="CONTRADICTED",
        reason="Conflict between suspicious EDR (E-001) and approved administrative log (E-002).",
        evidence_integrity_verified=True,
    )
    assert claim_contradicted.status == "CONTRADICTED"
    print("[PASS] Check 05: CONTRADICTED Claims Work with Conflicting Evidence References")

    # 6. Check UNCERTAIN Claims Work
    claim_uncertain = CanonicalClaim(
        claim="Command payload originated from external web server",
        evidence_ids=["E-001"],
        status="UNCERTAIN",
        confidence="UNCERTAIN",
        reason="Network telemetry incomplete; origin remains unconfirmed.",
        evidence_integrity_verified=True,
    )
    assert claim_uncertain.status == "UNCERTAIN"
    print("[PASS] Check 06: UNCERTAIN Claims Work with Ambiguous Telemetry")

    # 7. Check Invalid Evidence References Are Rejected
    # Claim references 'E-9999' which is NOT in sample_evidence
    try:
        CanonicalCaseJson(
            case_id="CASE-002",
            investigation_id="INV-012",
            schema_version="1.0.0",
            claims=[
                CanonicalClaim(
                    claim="Nonexistent evidence claim",
                    evidence_ids=["E-9999"],
                    status="UNSUPPORTED",
                    confidence="UNSUPPORTED",
                    reason="References missing evidence",
                )
            ],
            evidence=sample_evidence,
            final_conclusion="Test conclusion",
            audit=sample_audit,
        )
        assert False, "Failed to reject invalid evidence reference E-9999!"
    except ValidationError as e:
        assert "E-9999" in str(e), f"Expected E-9999 in error: {e}"
        print("[PASS] Check 07: Invalid Evidence Reference (E-9999) Strictly Rejected")
        print(f"        -> Rejection Detail: {e.errors()[0]['msg']}")

    # 8. Check NO EVIDENCE -> NO CLAIM Rule (SUPPORTED claim with evidence_ids=[])
    try:
        CanonicalClaim(
            claim="PowerShell was used by attacker",
            evidence_ids=[],
            status="SUPPORTED",
            confidence="SUPPORTED",
            reason="Investigator asserts this is true",
        )
        assert False, "Failed to enforce NO EVIDENCE -> NO CLAIM on SUPPORTED claim!"
    except ValidationError as e:
        assert "NO EVIDENCE -> NO CLAIM" in str(e), f"Expected NO EVIDENCE -> NO CLAIM in error: {e}"
        print("[PASS] Check 08: NO EVIDENCE -> NO CLAIM Strictly Enforced for SUPPORTED Claim")
        print(f"        -> Rejection Detail: {e.errors()[0]['msg']}")

    # 9. Check Missing Required Fields Are Rejected
    try:
        CanonicalCaseJson.model_validate({
            "investigation_id": "INV-012",
            "claims": [],
            # Missing case_id, evidence, final_conclusion, audit
        })
        assert False, "Failed to reject missing required fields!"
    except ValidationError as e:
        missing_fields = {err["loc"][0] for err in e.errors()}
        assert "case_id" in missing_fields, "Expected case_id in missing fields"
        assert "evidence" in missing_fields, "Expected evidence in missing fields"
        assert "final_conclusion" in missing_fields, "Expected final_conclusion in missing fields"
        assert "audit" in missing_fields, "Expected audit in missing fields"
        print("[PASS] Check 09: Missing Required Fields (case_id, evidence, audit, etc.) Strictly Rejected")

    # 10. Check Invalid Status Literals Are Rejected
    try:
        CanonicalClaim(
            claim="Attacker achieved persistence",
            evidence_ids=["E-001"],
            status="PLAUSIBLE",  # Invalid status literal!
            confidence="PLAUSIBLE",
            reason="Seems likely",
        )
        assert False, "Failed to reject invalid status 'PLAUSIBLE'!"
    except ValidationError as e:
        print("[PASS] Check 10: Invalid Status Literal ('PLAUSIBLE') Strictly Rejected")

    # 11. Deterministic Serialization Verification
    # Call to_canonical_json() multiple times and verify byte-for-byte identical output with sorted keys
    json_str_1 = case1.to_canonical_json(indent=2)
    json_str_2 = case1.to_canonical_json(indent=2)
    assert json_str_1 == json_str_2, "Non-deterministic JSON output detected!"

    # Verify keys are sorted alphabetically
    parsed = json.loads(json_str_1)
    keys_list = list(parsed.keys())
    assert keys_list == sorted(keys_list), f"Keys not sorted: {keys_list}"
    print("[PASS] Check 11: Deterministic Serialization Verified (Byte-for-Byte Identical, Sorted Keys)")

    # 12. Auditor Integration: GET /api/investigations/INV-012/case-json
    # First, make sure an audited case exists for INV-012
    status, evidence_list = make_request("/api/investigations/INV-012/evidence")
    assert status == 200 and len(evidence_list) > 0, "No evidence for INV-012"
    ev_id = evidence_list[0]["id"]

    audit_payload = {
        "investigation_id": "INV-012",
        "claims": [
            {"claim": "PowerShell execution occurred on PC-DB-TEST", "evidence_ids": [ev_id]},
            {"claim": "Threat actor is APT-X", "evidence_ids": []},
        ],
        "final_conclusion": "Suspicious PowerShell activity observed.",
    }
    status, audit_res = make_request("/api/investigations/INV-012/audit", method="POST", data=audit_payload)
    assert status == 200, f"Failed to run audit: {audit_res}"

    status, case_json_res = make_request("/api/investigations/INV-012/case-json")
    assert status == 200, f"Failed to export case JSON: {case_json_res}"
    assert case_json_res["case_id"] == audit_res["case_id"]
    assert case_json_res["schema_version"] == "1.0.0"
    assert "evidence" in case_json_res
    assert ev_id in case_json_res["evidence"]
    assert case_json_res["audit"]["audit_status"] == "AUDIT_VERIFIED"
    assert case_json_res["audit"]["auditor_verified"] is True
    print(f"[PASS] Check 12: Auditor -> Case JSON Integration (Case: {case_json_res['case_id']}, Schema: {case_json_res['schema_version']})")

    # 13. Case Validation Endpoint: POST /api/case-json/validate
    # Valid payload test
    status, val_res = make_request("/api/case-json/validate", method="POST", data=case_json_res)
    assert status == 200, f"Validation endpoint returned {status}: {val_res}"
    assert val_res["valid"] is True
    assert val_res["case_id"] == case_json_res["case_id"]

    # Invalid payload test (missing evidence ID referenced in claim)
    bad_case = json.loads(json.dumps(case_json_res))
    bad_case["claims"].append({
        "claim": "Fake claim referencing non-existent E-99999",
        "evidence_ids": ["E-99999"],
        "status": "UNSUPPORTED",
        "confidence": "UNSUPPORTED",
        "reason": "Missing evidence test",
        "evidence_integrity_verified": False,
    })
    status, bad_val_res = make_request("/api/case-json/validate", method="POST", data=bad_case)
    assert status == 422, f"Expected 422 for invalid case reference, got {status}: {bad_val_res}"
    print("[PASS] Check 13: POST /api/case-json/validate Validates Valid Cases & Rejects Tampered Payloads (422)")

    # 14. Investigation-specific Validation Endpoint: POST /api/investigations/INV-012/case-json/validate
    status, val_inv_res = make_request("/api/investigations/INV-012/case-json/validate", method="POST", data=case_json_res)
    assert status == 200, f"Investigation validation endpoint returned {status}: {val_inv_res}"
    assert val_inv_res["valid"] is True
    print("[PASS] Check 14: POST /api/investigations/INV-012/case-json/validate Endpoint Verified")

    # 15. Security Boundaries: Read-only export has zero side-effects
    status, tools_before = make_request("/api/investigations/INV-012/tool-executions")
    status, ev_before = make_request("/api/investigations/INV-012/evidence")

    # Export canonical case twice
    make_request("/api/investigations/INV-012/case-json")
    make_request("/api/investigations/INV-012/case-json")

    status, tools_after = make_request("/api/investigations/INV-012/tool-executions")
    status, ev_after = make_request("/api/investigations/INV-012/evidence")

    assert len(tools_before) == len(tools_after), "Tools executed during case JSON export!"
    assert len(ev_before) == len(ev_after), "Evidence mutated during case JSON export!"
    print(f"[PASS] Check 15: Security Boundary: Zero Tool Executions ({len(tools_before)} == {len(tools_after)}) & Zero Evidence Mutations")

    print("\n" + "=" * 65)
    print("ALL 15/15 MODULE 3F CANONICAL CASE JSON SCHEMA CHECKS PASSED!")
    print("=" * 65)


if __name__ == "__main__":
    run_tests()
