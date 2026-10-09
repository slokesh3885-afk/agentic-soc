"""
Module 3O: Forensic Timeline Replay & Investigation Reproducibility Engine — Test Suite
Agentic SOC — Auditable AI Security Operations Center

15 tests verifying:
1. Health check exposes Module 3O Replay & Reproducibility Engine.
2. Replay summary metrics calculation (average consistency, total replays).
3. Unified chronological timeline extraction for an investigation.
4. Timeline ordering monotonicity (sequential step_index and timestamps).
5. Event categorization coverage across multi-agent milestones.
6. Cumulative state snapshot presence across timeline milestones.
7. Execute deterministic replay on INV-001 with 100% consistency.
8. Replay verdict matching verification (original vs replayed).
9. Evidence snapshot SHA-256 fingerprint verification (64 hex characters).
10. Comparison matrix structure (claims match rate 100%, divergence count 0).
11. Cryptographic ledger block commitment (INVESTIGATION_REPLAYED in audit trail).
12. Single replay session retrieval by ID with full timeline.
13. Replay listing and query filtering by investigation ID.
14. Replay execution across additional investigations.
15. Boundary and error handling (404 for non-existent investigation).
"""

import json
import sys
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"


def http_get(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "Module3O-Tester"})
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())


def http_post(path, data=None):
    url = f"{BASE_URL}{path}"
    payload = json.dumps(data or {}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Module3O-Tester"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())


def run_tests():
    passed = 0
    total = 15

    print("======================================================================")
    print("MODULE 3O: FORENSIC TIMELINE REPLAY & REPRODUCIBILITY TEST SUITE")
    print("======================================================================")

    # 1. Health check exposes Module 3O
    try:
        status, health = http_get("/api/health")
        assert status == 200, f"Expected 200, got {status}"
        assert health.get("replay_module") == "Module 3O: Forensic Timeline Replay & Investigation Reproducibility Engine", (
            f"Unexpected replay_module: {health.get('replay_module')}"
        )
        assert "Active" in health.get("reproducibility_engine", ""), "reproducibility_engine not active"
        assert health.get("version") in ("0.14.0", "0.15.0", "0.16.0", "0.17.0"), f"Expected valid version, got {health.get('version')}"
        print("[PASS] Test 1: Health check exposes Module 3O Replay & Reproducibility Engine.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 1: Health check failed: {e}")

    # 2. Replay summary metrics
    try:
        status, summary = http_get("/api/replay/summary")
        assert status == 200, f"Expected 200, got {status}"
        assert "total_replays" in summary, "Missing total_replays"
        assert "average_consistency" in summary, "Missing average_consistency"
        assert "perfect_replays_count" in summary, "Missing perfect_replays_count"
        assert "divergent_replays_count" in summary, "Missing divergent_replays_count"
        assert "by_verdict" in summary, "Missing by_verdict"
        assert summary["average_consistency"] >= 90.0, f"Low avg consistency: {summary['average_consistency']}"
        print(f"[PASS] Test 2: Replay summary metrics verified: {summary['total_replays']} replays, {summary['average_consistency']}% avg consistency.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 2: Replay summary metrics failed: {e}")

    # 3. Unified chronological timeline extraction
    try:
        status, timeline = http_get("/api/investigations/INV-001/timeline")
        assert status == 200, f"Expected 200, got {status}"
        assert isinstance(timeline, list), "Timeline must be a list"
        assert len(timeline) >= 4, f"Expected at least 4 timeline events for INV-001, got {len(timeline)}"
        print(f"[PASS] Test 3: Reconstructed unified chronological timeline with {len(timeline)} events.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 3: Unified timeline extraction failed: {e}")

    # 4. Timeline ordering monotonicity
    try:
        status, timeline = http_get("/api/investigations/INV-001/timeline")
        indices = [e["step_index"] for e in timeline]
        assert indices == list(range(1, len(timeline) + 1)), f"Step indices not strictly monotonic: {indices}"
        timestamps = [e["timestamp"] for e in timeline]
        for i in range(len(timestamps) - 1):
            assert timestamps[i] <= timestamps[i + 1] or timestamps[i][:10] <= timestamps[i + 1][:10], (
                f"Non-monotonic timestamps: {timestamps[i]} > {timestamps[i+1]}"
            )
        print(f"[PASS] Test 4: Monotonic 1-based chronological step sequence verified ({len(timeline)} steps).")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 4: Monotonicity verification failed: {e}")

    # 5. Event categorization coverage
    try:
        status, timeline = http_get("/api/investigations/INV-001/timeline")
        event_types = {e["event_type"] for e in timeline}
        assert "ALERT_RECEIVED" in event_types, "ALERT_RECEIVED missing"
        assert "TRUST_SCORED" in event_types, "TRUST_SCORED missing"
        print(f"[PASS] Test 5: Event types verified: {sorted(list(event_types))}.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 5: Event categorization failed: {e}")

    # 6. Cumulative state snapshot presence
    try:
        status, timeline = http_get("/api/investigations/INV-001/timeline")
        for event in timeline:
            assert "state_snapshot" in event and event["state_snapshot"] is not None, f"Missing state_snapshot in step {event['step_index']}"
            snap = event["state_snapshot"]
            assert "step" in snap, "Missing step in snapshot"
            assert "cumulative_evidence_count" in snap, "Missing cumulative_evidence_count"
            assert "investigation_status" in snap, "Missing investigation_status"
        print("[PASS] Test 6: Cumulative state snapshots validated across all timeline milestones.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 6: State snapshot validation failed: {e}")

    # 7. Execute deterministic replay on INV-001
    created_replay_id = None
    try:
        payload = {
            "investigation_id": "INV-001",
            "notes": "Automated verification test run for Suspicious PowerShell Execution",
            "strict_verification": True,
        }
        status, replay = http_post("/api/replay/execute", payload)
        assert status == 200, f"Expected 200, got {status}"
        assert replay["investigation_id"] == "INV-001"
        assert replay["consistency_score"] == 100.0, f"Expected 100.0% consistency, got {replay['consistency_score']}"
        assert replay["status"] == "COMPLETED"
        created_replay_id = replay["id"]
        print(f"[PASS] Test 7: Deterministic replay executed on INV-001 with 100% consistency (ID: {replay['id']}).")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 7: Execute replay failed: {e}")

    # 8. Replay verdict matching verification
    try:
        assert created_replay_id is not None
        status, replay = http_get(f"/api/replay/{created_replay_id}")
        assert replay["verdict_match"] is True, "verdict_match must be True"
        assert replay["original_verdict"] == replay["replayed_verdict"], (
            f"Verdict mismatch: original '{replay['original_verdict']}' != replayed '{replay['replayed_verdict']}'"
        )
        print(f"[PASS] Test 8: Replay verdict matching verified: {replay['original_verdict']}.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 8: Verdict matching failed: {e}")

    # 9. Evidence snapshot SHA-256 fingerprint verification
    try:
        status, replay = http_get(f"/api/replay/{created_replay_id}")
        snap_hash = replay["evidence_snapshot_hash"]
        assert isinstance(snap_hash, str) and len(snap_hash) == 64, f"Invalid evidence snapshot hash: {snap_hash}"
        assert all(c in "0123456789abcdefABCDEF" for c in snap_hash), "Hash must be hexadecimal"
        print(f"[PASS] Test 9: Cryptographic evidence snapshot hash verified: {snap_hash[:16]}...")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 9: Evidence snapshot hash failed: {e}")

    # 10. Comparison matrix structure
    try:
        status, replay = http_get(f"/api/replay/{created_replay_id}")
        comp = replay["comparison"]
        assert comp["verdict_match"] is True
        assert comp["claims_match_rate"] == 100.0
        assert comp["trust_score_delta"] == 0.0
        assert comp["divergence_count"] == 0
        assert comp["divergence_notes"] == []
        print("[PASS] Test 10: Comparison matrix verified: 0 divergences, 100% claims match rate.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 10: Comparison matrix validation failed: {e}")

    # 11. Cryptographic ledger block commitment
    try:
        status, replay = http_get(f"/api/replay/{created_replay_id}")
        assert replay.get("audit_entry_id") is not None, "Missing audit_entry_id in replay"
        audit_id = replay["audit_entry_id"]
        assert audit_id.startswith("AUD-"), f"Unexpected audit entry format: {audit_id}"
        status_audit, entries = http_get("/api/audit-trail")
        assert status_audit == 200
        replay_entries = [e for e in entries if e["event_type"] == "INVESTIGATION_REPLAYED"]
        assert len(replay_entries) > 0, "No INVESTIGATION_REPLAYED entries in audit ledger"
        print(f"[PASS] Test 11: Ledger block {audit_id} committed with event_type 'INVESTIGATION_REPLAYED'.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 11: Audit trail integration failed: {e}")

    # 12. Single replay session retrieval by ID
    try:
        status, fetched = http_get(f"/api/replay/{created_replay_id}")
        assert status == 200
        assert fetched["id"] == created_replay_id
        assert fetched["investigation_id"] == "INV-001"
        assert len(fetched["timeline"]) > 0
        print(f"[PASS] Test 12: Retrieved replay session {created_replay_id} with complete timeline.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 12: Single replay retrieval failed: {e}")

    # 13. Query filtering replays by investigation ID
    try:
        status, filtered = http_get("/api/replay?investigation_id=INV-001")
        assert status == 200
        assert len(filtered) >= 1
        for r in filtered:
            assert r["investigation_id"] == "INV-001"
        status_nest, nested = http_get("/api/investigations/INV-001/replays")
        assert status_nest == 200
        assert len(nested) == len(filtered)
        print(f"[PASS] Test 13: Query filtering verified ({len(filtered)} replays found for INV-001).")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 13: Query filtering failed: {e}")

    # 14. Replay execution across additional investigations
    try:
        status_inv, all_invs = http_get("/api/investigations")
        other_invs = [i["id"] for i in all_invs if i["id"] != "INV-001"]
        if other_invs:
            target_inv = other_invs[0]
            status_rep, rep_other = http_post("/api/replay/execute", {"investigation_id": target_inv})
            assert status_rep == 200, f"Replay failed on {target_inv}"
            assert rep_other["consistency_score"] == 100.0
            assert rep_other["verdict_match"] is True
            print(f"[PASS] Test 14: Replay executed on {target_inv} with 100% consistency.")
        else:
            status_rep, rep_again = http_post("/api/replay/execute", {"investigation_id": "INV-001"})
            assert status_rep == 200
            print("[PASS] Test 14: Replay repeated on INV-001 successfully.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 14: Multi-investigation replay failed: {e}")

    # 15. Boundary and error handling
    try:
        err_404_count = 0
        try:
            http_post("/api/replay/execute", {"investigation_id": "INV-NONEXISTENT-999"})
        except urllib.error.HTTPError as he:
            if he.code == 404:
                err_404_count += 1

        try:
            http_get("/api/replay/RPL-INVALID-999")
        except urllib.error.HTTPError as he:
            if he.code == 404:
                err_404_count += 1

        try:
            http_get("/api/investigations/INV-INVALID/timeline")
        except urllib.error.HTTPError as he:
            if he.code == 404:
                err_404_count += 1

        assert err_404_count == 3, f"Expected three 404 errors, got {err_404_count}"
        print("[PASS] Test 15: Boundary and error handling validated (404 returned for non-existent IDs).")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 15: Error handling test failed: {e}")

    print("======================================================================")
    print(f"MODULE 3O TEST RESULTS: {passed}/{total} PASSED")
    print("======================================================================")

    if passed == total:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
