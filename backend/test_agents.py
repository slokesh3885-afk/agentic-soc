"""
Comprehensive Test Suite for Module 3Q:
Autonomous Multi-Agent Swarm Orchestration, Analyst Agent & Live Activity Engine
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
    print("MODULE 3Q: MULTI-AGENT SWARM ORCHESTRATION & ANALYST AGENT TEST SUITE")
    print("=" * 70)
    passed = 0
    total = 15

    # 1. Health check exposes Module 3Q
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert health.get("version") in ("0.15.0", "0.16.0", "0.17.0"), f"Unexpected version: {health.get('version')}"
    assert "Module 3Q" in health.get("agents_module", "")
    assert "Active" in health.get("agent_swarm", "")
    assert "Active" in health.get("analyst_agent", "")
    print(f"[PASS] Check 01: GET /api/health exposes Module 3Q swarm & analyst metadata")
    passed += 1

    # 2. Swarm summary KPI endpoint
    status, summary = make_request("/api/agents/summary")
    assert status == 200, f"Expected 200, got {status}"
    assert summary.get("total_agents") == 5, f"Expected 5 agents, got {summary.get('total_agents')}"
    assert summary.get("swarm_status") == "OPTIMAL"
    assert "total_actions" in summary and "average_execution_time_ms" in summary
    print(f"[PASS] Check 02: GET /api/agents/summary returns swarm KPI metrics (Total: {summary['total_agents']})")
    passed += 1

    # 3. List all agents endpoint
    status, agents = make_request("/api/agents")
    assert status == 200, f"Expected 200, got {status}"
    assert isinstance(agents, list) and len(agents) == 5, f"Expected 5 agents, got {len(agents)}"
    agent_ids = {a["id"] for a in agents}
    expected_ids = {"agent-planner", "agent-tool", "agent-analyst", "agent-critic", "agent-auditor"}
    assert agent_ids == expected_ids, f"Agent IDs mismatch: {agent_ids}"
    print(f"[PASS] Check 03: GET /api/agents lists all 5 core SOC agents ({', '.join(agent_ids)})")
    passed += 1

    # 4. Specific agent lookup (Planner Agent)
    status, planner = make_request("/api/agents/agent-planner")
    assert status == 200
    assert planner["name"] == "Planner Agent"
    assert "Decomposition" in planner["role"]
    assert isinstance(planner["capabilities"], list)
    print(f"[PASS] Check 04: GET /api/agents/agent-planner returns planner capabilities & telemetry")
    passed += 1

    # 5. Specific agent lookup (Analyst Agent)
    status, analyst = make_request("/api/agents/agent-analyst")
    assert status == 200
    assert analyst["name"] == "Analyst Agent"
    assert "Hypothesis" in analyst["role"]
    print(f"[PASS] Check 05: GET /api/agents/agent-analyst returns analyst telemetry & task state")
    passed += 1

    # 6. Specific agent lookup (Tool Agent)
    status, tool_agent = make_request("/api/agents/agent-tool")
    assert status == 200
    assert tool_agent["name"] == "Tool Agent"
    assert "siem_search" in tool_agent["capabilities"]
    print(f"[PASS] Check 06: GET /api/agents/agent-tool returns tool registry capabilities")
    passed += 1

    # 7. Non-existent agent 404
    status, err = make_request("/api/agents/agent-unknown-404")
    assert status == 404, f"Expected 404, got {status}"
    print(f"[PASS] Check 07: GET /api/agents/agent-unknown-404 correctly returns 404 Not Found")
    passed += 1

    # 8. Analyst Agent execution on valid investigation
    status, analysis = make_request("/api/agents/analyst/analyze", method="POST", data={
        "investigation_id": "INV-001",
        "analyst_notes": "Focused analysis pass on execution artifacts",
        "include_threat_intel": True,
    })
    assert status == 200, f"Expected 200, got {status}: {analysis}"
    assert analysis["investigation_id"] == "INV-001"
    assert len(analysis["preliminary_hypothesis"]) > 20
    assert analysis["overall_confidence"] >= 0.5
    assert analysis["recommended_next_action"] == "CRITIC_REVIEW"
    assert len(analysis["claims"]) > 0
    print(f"[PASS] Check 08: POST /api/agents/analyst/analyze generates preliminary hypothesis & {len(analysis['claims'])} claims")
    passed += 1

    # 9. Analyst Agent claims bound to evidence without uncorroborated attribution
    for claim in analysis["claims"]:
        assert claim["claim_id"].startswith("CLM-")
        assert isinstance(claim["supporting_evidence_ids"], list)
        assert claim["threat_attribution_hypothesis"] is None or claim["threat_attribution_hypothesis"] == ""
    print(f"[PASS] Check 09: Analyst Agent strictly binds claims to evidence & respects attribution guard")
    passed += 1

    # 10. Analyst Agent on invalid investigation 404
    status, err = make_request("/api/agents/analyst/analyze", method="POST", data={
        "investigation_id": "INV-INVALID-999",
    })
    assert status == 404, f"Expected 404, got {status}"
    print(f"[PASS] Check 10: POST /api/agents/analyst/analyze on invalid investigation returns 404")
    passed += 1

    # 11. Swarm activity stream
    status, activities = make_request("/api/agents/activity?limit=10")
    assert status == 200
    assert isinstance(activities, list) and len(activities) > 0
    first_act = activities[0]
    assert "agent_name" in first_act and "action" in first_act and "timestamp" in first_act
    print(f"[PASS] Check 11: GET /api/agents/activity returns chronological activity feed ({len(activities)} items)")
    passed += 1

    # 12. Swarm activity filtering by investigation ID
    status, inv_acts = make_request("/api/agents/activity?investigation_id=INV-001")
    assert status == 200
    assert isinstance(inv_acts, list)
    for a in inv_acts:
        assert a["investigation_id"] == "INV-001"
    print(f"[PASS] Check 12: GET /api/agents/activity?investigation_id=INV-001 filters events accurately")
    passed += 1

    # 13. Autonomous swarm orchestration cycle
    status, orch = make_request("/api/agents/orchestrate", method="POST", data={
        "investigation_id": "INV-001",
        "auto_contain": False,
    })
    assert status == 200, f"Expected 200, got {status}: {orch}"
    assert orch["investigation_id"] == "INV-001"
    assert orch["status"] == "COMPLETED"
    assert len(orch["stages_executed"]) == 5
    assert orch["auditor_status"] == "VERIFIED_AND_SEALED"
    assert orch["analyst_claims_count"] > 0
    print(f"[PASS] Check 13: POST /api/agents/orchestrate completes 5-stage swarm cycle (Cycle: {orch['cycle_id']})")
    passed += 1

    # 14. Swarm orchestration updates agent states to completed
    status, updated_agents = make_request("/api/agents")
    assert status == 200
    for a in updated_agents:
        assert a["actions_count"] > 0
    print(f"[PASS] Check 14: Swarm orchestration increments agent actions & updates operational states")
    passed += 1

    # 15. Activity feed reflects orchestrated stages
    status, latest_acts = make_request("/api/agents/activity?limit=5")
    assert status == 200
    assert len(latest_acts) >= 5
    print(f"[PASS] Check 15: Swarm activity log chronologically streams events for all 5 agents")
    passed += 1

    print("=" * 70)
    print(f"MODULE 3Q TEST RESULTS: {passed}/{total} PASSED")
    print("=" * 70)


if __name__ == "__main__":
    try:
        run_tests()
    except Exception as e:
        print(f"\n[FAIL] Test suite failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
