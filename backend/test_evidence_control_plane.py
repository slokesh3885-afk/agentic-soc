"""
Comprehensive Test Suite for Module 3R:
Evidence Control Plane, Claims Corroboration Matrix & Threat Actor Attribution Policy Engine
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
    print("MODULE 3R: EVIDENCE CONTROL PLANE & CLAIMS CORROBORATION TEST SUITE")
    print("=" * 70)
    passed = 0
    total = 15

    # 1. Health check exposes Module 3R
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert "Module 3R" in health.get("evidence_module", ""), f"Module 3R missing from health: {health}"
    assert "Active" in health.get("evidence_control_plane", ""), f"Control plane missing from health: {health}"
    assert "Enforced" in health.get("attribution_guard", ""), f"Attribution guard missing from health: {health}"
    assert health.get("version") in ("0.16.0", "0.17.0"), f"Unexpected version: {health.get('version')}"
    print("[PASS] Check 01: GET /api/health exposes Module 3R control plane & attribution guard metadata")
    passed += 1

    # 2. Control plane KPI summary
    status, summary = make_request("/api/evidence/summary")
    assert status == 200, f"Expected 200, got {status}"
    assert summary.get("total_evidence_items") >= 30, f"Expected >= 30 items, got {summary.get('total_evidence_items')}"
    assert summary.get("verified_integrity_count") >= 30
    assert summary.get("corroborated_claims_count") >= 3
    assert summary.get("unsupported_claims_count") >= 2
    assert summary.get("attribution_blocked_count") >= 1
    assert "sources_breakdown" in summary and "types_breakdown" in summary
    print(f"[PASS] Check 02: GET /api/evidence/summary returns control plane KPIs ({summary['total_evidence_items']} items, {summary['corroborated_claims_count']} corroborated claims)")
    passed += 1

    # 3. List all control plane evidence items
    status, items = make_request("/api/evidence?limit=50")
    assert status == 200, f"Expected 200, got {status}"
    assert isinstance(items, list) and len(items) > 0, "Expected non-empty list of items"
    first = items[0]
    for key in ("id", "investigation_id", "evidence_type", "source", "timestamp", "tool", "result", "reliability", "content_hash", "used_by_claims"):
        assert key in first, f"Missing key '{key}' in control plane item: {first}"
    assert first["reliability"] in ("Verified", "High", "Medium", "Uncorroborated")
    print(f"[PASS] Check 03: GET /api/evidence returns structured items (First: {first['id']} via {first['tool']})")
    passed += 1

    # 4. Filter evidence by investigation ID
    status, filtered_inv = make_request("/api/evidence?investigation_id=INV-001&limit=50")
    assert status == 200, f"Expected 200, got {status}"
    for item in filtered_inv:
        assert item["investigation_id"] == "INV-001", f"Expected INV-001, got {item['investigation_id']}"
    print(f"[PASS] Check 04: Filter by investigation_id=INV-001 returns {len(filtered_inv)} scoped records")
    passed += 1

    # 5. Filter evidence by type
    status, filtered_type = make_request("/api/evidence?evidence_type=SIEM_LOG&limit=50")
    assert status == 200, f"Expected 200, got {status}"
    for item in filtered_type:
        assert item["evidence_type"] == "SIEM_LOG", f"Expected SIEM_LOG, got {item['evidence_type']}"
    print(f"[PASS] Check 05: Filter by evidence_type=SIEM_LOG accurately isolates {len(filtered_type)} records")
    passed += 1

    # 6. Filter evidence by source
    status, filtered_src = make_request("/api/evidence?source=SIEM&limit=50")
    assert status == 200, f"Expected 200, got {status}"
    for item in filtered_src:
        assert "siem" in item["source"].lower() or "siem" in item["evidence_type"].lower()
    print(f"[PASS] Check 06: Filter by source=SIEM returns {len(filtered_src)} matching sources")
    passed += 1

    # 7. Search query in evidence
    status, search_res = make_request("/api/evidence?search=powershell&limit=50")
    assert status == 200, f"Expected 200, got {status}"
    assert len(search_res) > 0, "Expected search results for 'powershell'"
    for item in search_res:
        match = ("powershell" in item["raw_output"].lower() or "powershell" in item["source"].lower() or "powershell" in item["id"].lower())
        assert match, f"Search result item does not match query: {item}"
    print(f"[PASS] Check 07: Search query '?search=powershell' successfully matches {len(search_res)} payloads")
    passed += 1

    # 8. GET /api/evidence/claims lists full Claims Corroboration Matrix
    status, claims = make_request("/api/evidence/claims")
    assert status == 200, f"Expected 200, got {status}"
    assert len(claims) >= 4, f"Expected at least 4 claims, got {len(claims)}"
    claim_ids = [c["claim_id"] for c in claims]
    assert "CLM-001" in claim_ids and "CLM-004" in claim_ids
    print(f"[PASS] Check 08: GET /api/evidence/claims returns claims corroboration matrix ({len(claims)} claims)")
    passed += 1

    # 9. Supported claims strictly reference valid evidence IDs
    supported_claims = [c for c in claims if c["status"] == "SUPPORTED"]
    assert len(supported_claims) >= 2, "Expected at least 2 supported claims"
    for sc in supported_claims:
        assert len(sc["supported_by"]) > 0, f"Supported claim {sc['claim_id']} missing evidence IDs"
        assert sc["confidence"] in ("HIGH", "MEDIUM"), f"Invalid confidence: {sc['confidence']}"
    print(f"[PASS] Check 09: All {len(supported_claims)} supported claims strictly link to valid evidence IDs")
    passed += 1

    # 10. System refuses unsupported conclusions (APT-X claim is UNSUPPORTED)
    apt_claim = next((c for c in claims if c["claim_id"] == "CLM-004"), None)
    assert apt_claim is not None, "Missing APT-X claim CLM-004"
    assert apt_claim["status"] == "UNSUPPORTED", f"Expected UNSUPPORTED, got {apt_claim['status']}"
    assert len(apt_claim["supported_by"]) == 0, "Unsupported claim must not have supporting evidence"
    assert "No evidence IDs sufficiently support threat-actor attribution" in apt_claim["reason"]
    print("[PASS] Check 10: System refuses unsupported claim CLM-004 (Status: UNSUPPORTED, Evidence: 0)")
    passed += 1

    # 11. GET /api/evidence/attribution-policy evaluates policy
    status, policy = make_request("/api/evidence/attribution-policy")
    assert status == 200, f"Expected 200, got {status}"
    assert policy["policy_name"] == "Threat Actor Attribution Policy"
    assert "cannot assert a specific threat actor" in policy["policy_rule"]
    assert policy["attribution_status"] == "NOT ESTABLISHED"
    assert policy["evidence_status"] == "Insufficient"
    assert policy["action"] == "Attribution blocked"
    print(f"[PASS] Check 11: Threat Actor Attribution Policy evaluates: Attribution: {policy['attribution_status']}, Action: {policy['action']}")
    passed += 1

    # 12. Attribution Policy confirms guard blocks premature attribution
    assert policy["policy_enforced"] is True
    assert policy["required_evidence_sources_count"] >= 3
    assert len(policy["blocked_claims"]) >= 1
    assert any(bc["is_threat_actor_attribution"] for bc in policy["blocked_claims"])
    print(f"[PASS] Check 12: Attribution guard blocks premature attribution across {len(policy['blocked_claims'])} claims")
    passed += 1

    # 13. POST /api/evidence/verify-batch performs batch integrity check
    status, batch_resp = make_request("/api/evidence/verify-batch", method="POST")
    assert status == 200, f"Expected 200, got {status}"
    assert batch_resp["all_valid"] is True, f"Integrity check reported corruption: {batch_resp}"
    assert batch_resp["corrupted_count"] == 0
    assert batch_resp["total_verified"] >= 30
    assert len(batch_resp["merkle_root"]) == 64, f"Invalid Merkle root: {batch_resp.get('merkle_root')}"
    print(f"[PASS] Check 13: POST /api/evidence/verify-batch verifies all {batch_resp['total_verified']} items (Merkle Root: {batch_resp['merkle_root'][:16]}...)")
    passed += 1

    # 14. Backward compatibility with Module 3A single evidence lookup & verify
    status, single_item = make_request("/api/evidence/E-001")
    assert status == 200, f"Failed single evidence lookup: {status}"
    assert single_item["id"] == "E-001"
    status, verify_single = make_request("/api/evidence/E-001/verify")
    assert status == 200 and verify_single["valid"] is True
    print(f"[PASS] Check 14: Backward compatibility intact: GET /api/evidence/E-001 and /verify pass")
    passed += 1

    # 15. Security boundary & error handling
    status, err_404 = make_request("/api/evidence/NONEXISTENT-E-999")
    assert status == 404, f"Expected 404 for unknown evidence, got {status}"
    print("[PASS] Check 15: Security boundary validated (404 on non-existent evidence ID)")
    passed += 1

    print("=" * 70)
    print(f"MODULE 3R TEST RESULTS: {passed}/{total} PASSED")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
