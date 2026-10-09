"""
Module 3W: Enterprise SOC Control Plane Integration & Universal Omnibar Test Suite
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
    print("MODULE 3W: CONTROL PLANE INTEGRATION & UNIVERSAL OMNIBAR TEST SUITE")
    print("=" * 70)
    passed = 0
    total = 15

    # 1. Health check exposes Module 3W integration metadata
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert "Module 3W" in health.get("control_plane_ui_module", ""), f"Module 3W missing: {health}"
    assert "Active" in health.get("omnibar_integration", ""), f"Omnibar integration missing: {health}"
    assert "Active" in health.get("settings_control_plane", ""), f"Settings control plane missing: {health}"
    print("[PASS] Check 01: GET /api/health exposes Module 3W control plane & omnibar integration metadata")
    passed += 1

    # 2. Retrieve SOC System Settings
    status, settings = make_request("/api/system/settings")
    assert status == 200, f"Failed to get settings: {status}, {settings}"
    assert settings.get("platform_name") == "Agentic SOC", f"Unexpected title: {settings}"
    assert settings.get("tool_registry_enforcement") is True
    assert settings.get("attribution_policy_strictness") in ("STRICT", "MEDIUM", "ADVISORY")
    print("[PASS] Check 02: GET /api/system/settings returns active enterprise SOC configuration")
    passed += 1

    # 3. Reset settings to factory defaults
    status, reset_res = make_request("/api/system/settings/reset", method="POST")
    assert status == 200, f"Failed to reset settings: {status}, {reset_res}"
    assert reset_res.get("attribution_policy_strictness") == "STRICT"
    assert reset_res.get("max_tool_execution_timeout_sec") == 120
    print("[PASS] Check 03: POST /api/system/settings/reset restores factory defaults")
    passed += 1

    # 4. Update attribution policy strictness and tool timeout
    update_payload = {
        "attribution_policy_strictness": "MEDIUM",
        "min_attribution_evidence_count": 2,
        "max_tool_execution_timeout_sec": 60,
    }
    status, updated = make_request("/api/system/settings", method="PUT", data=update_payload)
    assert status == 200, f"Failed to update settings: {status}, {updated}"
    assert updated.get("attribution_policy_strictness") == "MEDIUM"
    assert updated.get("min_attribution_evidence_count") == 2
    assert updated.get("max_tool_execution_timeout_sec") == 60
    print("[PASS] Check 04: PUT /api/system/settings updates attribution policy and execution timeout")
    passed += 1

    # 5. Calibrate custom trust score weights
    weights_payload = {
        "trust_score_weights": {
            "evidence_coverage": 0.30,
            "evidence_quality": 0.30,
            "contradiction_handling": 0.20,
            "attribution_support": 0.10,
            "replay_consistency": 0.10,
        }
    }
    status, updated_w = make_request("/api/system/settings", method="PUT", data=weights_payload)
    assert status == 200, f"Failed to update weights: {status}, {updated_w}"
    weights = updated_w.get("trust_score_weights", {})
    assert weights.get("evidence_coverage") == 0.30
    assert weights.get("evidence_quality") == 0.30
    print("[PASS] Check 05: PUT /api/system/settings calibrates explainable trust score weights")
    passed += 1

    # 6. Universal omnibar search for 'powershell'
    status, search_ps = make_request("/api/system/search?q=powershell")
    assert status == 200, f"Search failed: {status}, {search_ps}"
    assert search_ps.get("total_matches", 0) > 0, f"No matches for powershell: {search_ps}"
    categories = search_ps.get("categories", {})
    assert "investigations" in categories or "alerts" in categories or "evidence" in categories
    print(f"[PASS] Check 06: GET /api/system/search?q=powershell returned {search_ps['total_matches']} matches")
    passed += 1

    # 7. Universal search for targeted investigation 'INV-001'
    status, search_inv = make_request("/api/system/search?q=INV-001")
    assert status == 200, f"Search failed: {status}, {search_inv}"
    assert search_inv.get("total_matches", 0) > 0
    inv_item = next((r for r in search_inv.get("results", []) if "INV-001" in r["id"]), None)
    assert inv_item is not None, f"INV-001 not found: {search_inv}"
    print(f"[PASS] Check 07: GET /api/system/search?q=INV-001 resolved investigation entity: {inv_item['id']}")
    passed += 1

    # 8. Universal search for targeted evidence 'EV-001'
    status, search_ev = make_request("/api/system/search?q=EV-001")
    assert status == 200, f"Search failed: {status}, {search_ev}"
    assert search_ev.get("total_matches", 0) > 0
    ev_item = next((r for r in search_ev.get("results", []) if "001" in r["id"]), None)
    assert ev_item is not None, f"EV-001 not found: {search_ev}"
    print(f"[PASS] Check 08: GET /api/system/search?q=EV-001 resolved evidence entity: {ev_item['id']}")
    passed += 1

    # 9. Universal search for agent entities 'critic'
    status, search_critic = make_request("/api/system/search?q=critic")
    assert status == 200, f"Search failed: {status}, {search_critic}"
    assert search_critic.get("total_matches", 0) > 0
    agent_match = next((r for r in search_critic.get("results", []) if r["category"] == "agents"), None)
    assert agent_match is not None, f"Critic agent missing: {search_critic}"
    print(f"[PASS] Check 09: GET /api/system/search?q=critic resolved agent entity: {agent_match['title']}")
    passed += 1

    # 10. Seed notification store
    status, notifs_seed = make_request("/api/system/notifications/seed", method="POST")
    assert status == 200, f"Failed to seed notifications: {status}, {notifs_seed}"
    assert notifs_seed.get("total_notifications", 0) >= 4
    print(f"[PASS] Check 10: POST /api/system/notifications/seed initialized {notifs_seed['total_notifications']} notifications")
    passed += 1

    # 11. Retrieve notifications feed and verify unread count
    status, notifs = make_request("/api/system/notifications")
    assert status == 200, f"Notifications failed: {status}, {notifs}"
    assert notifs.get("unread_count", 0) >= 1
    items = notifs.get("notifications", [])
    assert len(items) >= 4
    print(f"[PASS] Check 11: GET /api/system/notifications retrieved feed with {notifs['unread_count']} unread")
    passed += 1

    # 12. Mark specific notification as read
    first_unread = next((n for n in items if not n.get("read")), items[0])
    status, mark_res = make_request(f"/api/system/notifications/{first_unread['id']}/read", method="POST")
    assert status == 200, f"Failed to mark notification: {status}, {mark_res}"
    assert mark_res.get("read") is True
    print(f"[PASS] Check 12: POST /api/system/notifications/{first_unread['id']}/read marked notification read")
    passed += 1

    # 13. Mark all notifications as read and verify unread count is 0
    status, mark_all = make_request("/api/system/notifications/mark-all-read", method="POST")
    assert status == 200, f"Failed mark all: {status}, {mark_all}"
    status, after_notifs = make_request("/api/system/notifications")
    assert status == 200
    assert after_notifs.get("unread_count") == 0, f"Expected 0 unread: {after_notifs}"
    print("[PASS] Check 13: POST /api/system/notifications/mark-all-read cleared unread counter to 0")
    passed += 1

    # 14. Active investigation context verification for TopBar indicator
    status, inv = make_request("/api/investigations/INV-001")
    assert status == 200, f"Failed to fetch INV-001: {status}, {inv}"
    assert inv.get("id") == "INV-001"
    assert "power" in (inv.get("title") or inv.get("alert_name", "")).lower()
    print(f"[PASS] Check 14: Active investigation context validated: {inv['id']} ({inv.get('severity', 'HIGH')})")
    passed += 1

    # 15. Cross-module integrity: Overview Analytics and Audit Trail operational
    status, analytics = make_request("/api/analytics/overview")
    assert status == 200, f"Analytics overview failed: {status}"
    assert "posture" in analytics
    status, audit = make_request("/api/audit-trail")
    assert status == 200, f"Audit trail failed: {status}"
    print("[PASS] Check 15: Cross-module integrity verified: analytics overview and audit trail online")
    passed += 1

    print("=" * 70)
    print(f"MODULE 3W VERIFICATION SUCCESSFUL: {passed}/{total} CHECKS PASSED")
    print("=" * 70)
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    if not success:
        sys.exit(1)
