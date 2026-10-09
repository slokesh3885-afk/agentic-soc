"""
Comprehensive Test Suite for Module 3U:
Enterprise SOC Control Plane, Universal Omnibar Search & Real-Time Notification Center
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
    print("MODULE 3U: ENTERPRISE SOC CONTROL PLANE & UNIVERSAL SEARCH TEST SUITE")
    print("=" * 70)
    passed = 0
    total = 15

    # 1. Health check exposes Module 3U
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert "Module 3U" in health.get("system_control_plane_module", ""), f"Module 3U missing: {health}"
    assert "Active" in health.get("omnibar_search_engine", ""), f"Omnibar missing: {health}"
    assert "Active" in health.get("notification_center", ""), f"Notification center missing: {health}"
    assert "Active" in health.get("system_settings_engine", ""), f"System settings engine missing: {health}"
    print("[PASS] Check 01: GET /api/health exposes Module 3U control plane & omnibar metadata")
    passed += 1

    # 2. Retrieve SOC System Settings
    status, settings = make_request("/api/system/settings")
    assert status == 200, f"Failed to get settings: {status}, {settings}"
    assert settings.get("platform_name") == "Agentic SOC", f"Unexpected title: {settings}"
    assert settings.get("tool_registry_enforcement") is True, f"Tool registry enforcement: {settings}"
    assert settings.get("attribution_policy_strictness") in ("STRICT", "MEDIUM", "ADVISORY")
    assert "trust_score_weights" in settings, f"Missing trust weights: {settings}"
    print("[PASS] Check 02: GET /api/system/settings returns active enterprise SOC configuration")
    passed += 1

    # 3. Update SOC System Settings
    update_payload = {
        "attribution_policy_strictness": "STRICT",
        "min_attribution_evidence_count": 4,
        "max_tool_execution_timeout_sec": 90,
        "trust_score_weights": {
            "evidence_coverage": 0.30,
            "evidence_quality": 0.30,
            "contradiction_handling": 0.20,
            "attribution_support": 0.10,
            "replay_consistency": 0.10,
        },
    }
    status, updated = make_request("/api/system/settings", method="PUT", data=update_payload)
    assert status == 200, f"Failed to update settings: {status}, {updated}"
    assert updated.get("min_attribution_evidence_count") == 4, f"Mismatch: {updated}"
    assert updated.get("max_tool_execution_timeout_sec") == 90, f"Mismatch: {updated}"
    print("[PASS] Check 03: PUT /api/system/settings successfully updates control plane policies")
    passed += 1

    # 4. Verify Persistence of Updated Settings
    status, persisted = make_request("/api/system/settings")
    assert status == 200, f"Failed to verify settings: {status}"
    assert persisted.get("min_attribution_evidence_count") == 4
    assert persisted.get("max_tool_execution_timeout_sec") == 90
    print("[PASS] Check 04: GET /api/system/settings confirms persistent update retention")
    passed += 1

    # 5. Universal Search for 'powershell'
    status, search_ps = make_request("/api/system/search?q=powershell")
    assert status == 200, f"Search failed: {status}, {search_ps}"
    assert search_ps.get("total_matches", 0) > 0, f"No matches found for powershell: {search_ps}"
    assert len(search_ps.get("results", [])) > 0
    print(f"[PASS] Check 05: GET /api/system/search?q=powershell returned {search_ps['total_matches']} items")
    passed += 1

    # 6. Universal Search for 'critic'
    status, search_critic = make_request("/api/system/search?q=critic")
    assert status == 200, f"Search failed: {status}, {search_critic}"
    assert search_critic.get("total_matches", 0) > 0, f"No matches found for critic: {search_critic}"
    agent_matches = [r for r in search_critic.get("results", []) if r["category"] == "agents"]
    assert len(agent_matches) > 0, f"No agent match for critic: {search_critic}"
    print(f"[PASS] Check 06: GET /api/system/search?q=critic discovered agent: {agent_matches[0]['title']}")
    passed += 1

    # 7. Universal Search for Specific Evidence 'E-001' and 'EV-001'
    status, search_ev = make_request("/api/system/search?q=E-001")
    assert status == 200, f"Search failed: {status}, {search_ev}"
    assert search_ev.get("total_matches", 0) > 0, f"No match for E-001: {search_ev}"
    ev_item = next((r for r in search_ev["results"] if "E-001" in r["id"]), None)
    assert ev_item is not None, f"E-001 item missing from results: {search_ev}"
    assert ev_item["category"] == "evidence"

    # Also test EV-001 alias
    _, search_alias = make_request("/api/system/search?q=EV-001")
    assert search_alias.get("total_matches", 0) > 0, f"Alias EV-001 search failed: {search_alias}"
    print(f"[PASS] Check 07: GET /api/system/search?q=E-001 resolved evidence object: {ev_item['id']}")
    passed += 1

    # 8. Universal Search for Investigation 'INV-001'
    status, search_inv = make_request("/api/system/search?q=INV-001")
    assert status == 200, f"Search failed: {status}, {search_inv}"
    assert search_inv.get("total_matches", 0) > 0, f"No match for INV-001: {search_inv}"
    inv_item = next((r for r in search_inv["results"] if "INV-001" in r["id"]), None)
    assert inv_item is not None, f"INV-001 item missing: {search_inv}"
    print(f"[PASS] Check 08: GET /api/system/search?q=INV-001 resolved investigation entity: {inv_item['id']}")
    passed += 1

    # 9. Categorized Breakdown in Search Response
    categories = search_inv.get("categories", {})
    assert "investigations" in categories
    assert "evidence" in categories
    assert "agents" in categories
    print(f"[PASS] Check 09: Universal omnibar categories aggregated correctly: {categories}")
    passed += 1

    # 10. Clean Empty Result on Nonexistent Query
    status, search_empty = make_request("/api/system/search?q=nonexistent_entropy_xyz_9999")
    assert status == 200, f"Search empty failed: {status}"
    assert search_empty.get("total_matches") == 0
    assert len(search_empty.get("results")) == 0
    print("[PASS] Check 10: GET /api/system/search with empty query gracefully returns 0 matches")
    passed += 1

    # 11. Retrieve Notifications Feed
    status, notifs = make_request("/api/system/notifications")
    assert status == 200, f"Notifications failed: {status}, {notifs}"
    assert notifs.get("total_notifications", 0) >= 4, f"Unexpected count: {notifs}"
    assert "unread_count" in notifs
    print(f"[PASS] Check 11: GET /api/system/notifications retrieved {notifs['total_notifications']} notifications ({notifs['unread_count']} unread)")
    passed += 1

    # 12. Notification Schema Structure Verification
    items = notifs.get("notifications", [])
    assert len(items) > 0
    first = items[0]
    for required in ["id", "title", "message", "severity", "category", "timestamp"]:
        assert required in first, f"Missing required notification field '{required}': {first}"
    print(f"[PASS] Check 12: Notification objects adhere to canonical schema: {first['id']} ({first['severity']})")
    passed += 1

    # 13. Mark Individual Notification as Read
    status, mark_res = make_request(f"/api/system/notifications/{first['id']}/read", method="POST")
    assert status == 200, f"Failed to mark read: {status}, {mark_res}"
    assert mark_res.get("read") is True
    print(f"[PASS] Check 13: POST /api/system/notifications/{first['id']}/read marked notification read")
    passed += 1

    # 14. 404 on Invalid Notification ID
    status, error_res = make_request("/api/system/notifications/NOTIF-DOES-NOT-EXIST/read", method="POST")
    assert status == 404, f"Expected 404 for invalid ID, got {status}: {error_res}"
    print("[PASS] Check 14: POST /api/system/notifications/invalid/read cleanly returns HTTP 404 Not Found")
    passed += 1

    # 15. Mark All Notifications as Read
    status, mark_all_res = make_request("/api/system/notifications/mark-all-read", method="POST")
    assert status == 200, f"Failed mark all read: {status}, {mark_all_res}"
    status, after_notifs = make_request("/api/system/notifications")
    assert status == 200
    assert after_notifs.get("unread_count") == 0, f"Expected 0 unread, got: {after_notifs}"
    print(f"[PASS] Check 15: POST /api/system/notifications/mark-all-read cleared unread counter to 0")
    passed += 1

    print("=" * 70)
    print(f"MODULE 3U VERIFICATION SUCCESSFUL: {passed}/{total} CHECKS PASSED")
    print("=" * 70)
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    if not success:
        sys.exit(1)
