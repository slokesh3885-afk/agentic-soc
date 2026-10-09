"""
Comprehensive Test Suite for Module 3V:
Overview Dashboard Analytics, Multi-Chart Engine & Security Posture Service
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
    print("MODULE 3V: OVERVIEW DASHBOARD ANALYTICS & MULTI-CHART TEST SUITE")
    print("=" * 70)
    passed = 0
    total = 15

    # 1. Health check exposes Module 3V metadata
    status, health = make_request("/api/health")
    assert status == 200, f"Health check failed: {status}"
    assert "Module 3V" in health.get("analytics_module", ""), f"Module 3V missing from health: {health}"
    assert "Active" in health.get("posture_engine", ""), f"Posture engine missing: {health}"
    assert "Active" in health.get("charts_engine", ""), f"Charts engine missing: {health}"
    print("[PASS] Check 01: GET /api/health exposes Module 3V analytics & multi-chart metadata")
    passed += 1

    # 2. Retrieve Complete Overview Analytics Payload
    status, overview = make_request("/api/analytics/overview")
    assert status == 200, f"Overview analytics request failed: {status}, {overview}"
    for section in ["posture", "alerts_over_time", "investigation_outcomes", "evidence_sources", "trust_score_history", "generated_at"]:
        assert section in overview, f"Missing section '{section}' in overview: {overview.keys()}"
    print("[PASS] Check 02: GET /api/analytics/overview returns composite payload with all required sections")
    passed += 1

    # 3. Retrieve Security Posture Summary
    status, posture = make_request("/api/analytics/posture")
    assert status == 200, f"Posture request failed: {status}, {posture}"
    assert posture.get("posture_status") in ("SECURE", "ELEVATED", "HIGH_RISK", "UNDER_ATTACK"), f"Invalid posture status: {posture}"
    assert posture.get("active_investigations", -1) >= 0
    assert posture.get("high_severity_cases", -1) >= 0
    assert posture.get("evidence_collected", -1) >= 0
    print(f"[PASS] Check 03: GET /api/analytics/posture returns valid posture status: {posture['posture_status']} (Score: {posture['posture_score']})")
    passed += 1

    # 4. Philosophy string in posture summary
    assert posture.get("philosophy") == "Investigate → Challenge → Prove → Audit", f"Philosophy mismatch: {posture}"
    assert posture.get("audit_integrity_status") == "100% VERIFIED"
    print("[PASS] Check 04: Posture summary communicates core philosophy 'Investigate -> Challenge -> Prove -> Audit'")
    passed += 1

    # 5. Average Trust Score and Evidence Coverage Bounded
    avg_trust = posture.get("average_trust_score", -1)
    cov_pct = posture.get("evidence_coverage_pct", -1)
    assert 0 <= avg_trust <= 100, f"Average trust score out of bounds: {avg_trust}"
    assert 0 <= cov_pct <= 100, f"Evidence coverage out of bounds: {cov_pct}"
    print(f"[PASS] Check 05: Posture metrics valid: Average Trust {avg_trust}/100, Coverage {cov_pct}%")
    passed += 1

    # 6. Retrieve Raw Charts Data Dictionary
    status, charts = make_request("/api/analytics/charts")
    assert status == 200, f"Charts request failed: {status}, {charts}"
    assert "alerts_over_time" in charts
    assert "investigation_outcomes" in charts
    assert "evidence_sources" in charts
    assert "trust_score_history" in charts
    print("[PASS] Check 06: GET /api/analytics/charts aggregates 4 foundational chart datasets")
    passed += 1

    # 7. Alerts Over Time Progression
    status, timeline = make_request("/api/analytics/alerts-timeline")
    assert status == 200, f"Timeline request failed: {status}, {timeline}"
    assert isinstance(timeline, list) and len(timeline) >= 4, f"Timeline too short: {timeline}"
    first_point = timeline[0]
    for key in ["timestamp", "alerts", "confirmed_threats", "inconclusive"]:
        assert key in first_point, f"Missing key '{key}' in timeline point: {first_point}"
    print(f"[PASS] Check 07: GET /api/analytics/alerts-timeline returns {len(timeline)} time intervals")
    passed += 1

    # 8. Non-negative Counts in Alerts Over Time
    for pt in timeline:
        assert pt["alerts"] >= 0 and pt["confirmed_threats"] >= 0 and pt["inconclusive"] >= 0
    print("[PASS] Check 08: Chronological timeline counters strictly non-negative")
    passed += 1

    # 9. Investigation Outcomes Distribution
    status, outcomes = make_request("/api/analytics/outcomes")
    assert status == 200, f"Outcomes request failed: {status}, {outcomes}"
    assert isinstance(outcomes, list) and len(outcomes) >= 3, f"Unexpected outcomes: {outcomes}"
    first_outcome = outcomes[0]
    for key in ["outcome", "count", "percentage", "color"]:
        assert key in first_outcome, f"Missing key '{key}' in outcome: {first_outcome}"
    print(f"[PASS] Check 09: GET /api/analytics/outcomes returns {len(outcomes)} outcome categories")
    passed += 1

    # 10. Outcomes Percentages Sum to ~100%
    total_pct = sum(o["percentage"] for o in outcomes)
    assert 98.0 <= total_pct <= 102.0, f"Outcomes percentages do not sum near 100%: {total_pct}"
    print(f"[PASS] Check 10: Investigation outcome percentages sum to {total_pct:.1f}%")
    passed += 1

    # 11. Evidence Sources Distribution
    status, sources = make_request("/api/analytics/evidence-sources")
    assert status == 200, f"Evidence sources failed: {status}, {sources}"
    assert isinstance(sources, list) and len(sources) >= 4, f"Too few evidence sources: {sources}"
    first_src = sources[0]
    for key in ["source_type", "count", "percentage", "reliability_avg"]:
        assert key in first_src, f"Missing key '{key}' in evidence source: {first_src}"
    print(f"[PASS] Check 11: GET /api/analytics/evidence-sources returns {len(sources)} source categories")
    passed += 1

    # 12. Standard SOC Source Types Represented
    source_names = [s["source_type"] for s in sources]
    for expected in ["SIEM_LOG", "EDR_EVENT", "SANDBOX_RESULT", "HASH_LOOKUP"]:
        assert expected in source_names, f"Expected source '{expected}' missing from: {source_names}"
    print("[PASS] Check 12: Standard SOC telemetry sources (SIEM, EDR, Sandbox, Hash) verified")
    passed += 1

    # 13. Reliability Metric Bounds
    for s in sources:
        rel = s.get("reliability_avg", 0)
        assert 0.0 <= rel <= 1.0, f"Reliability average out of range: {rel} in {s}"
    print("[PASS] Check 13: Sensor reliability averages bounded between 0.0 and 1.0")
    passed += 1

    # 14. Trust Score History Progression
    status, history = make_request("/api/analytics/trust-history")
    assert status == 200, f"Trust history request failed: {status}, {history}"
    assert isinstance(history, list) and len(history) >= 2, f"Too few history points: {history}"
    first_hist = history[0]
    for key in ["case_id", "label", "trust_score", "coverage_score", "quality_score", "benchmark_target"]:
        assert key in first_hist, f"Missing key '{key}' in history point: {first_hist}"
    print(f"[PASS] Check 14: GET /api/analytics/trust-history returns {len(history)} historical audit points")
    passed += 1

    # 15. Benchmark Target & Trust Score Range Verification
    for pt in history:
        assert pt["benchmark_target"] == 85, f"Unexpected benchmark: {pt}"
        assert 0 <= pt["trust_score"] <= 100, f"Trust score out of bounds: {pt}"
        assert 0 <= pt["coverage_score"] <= 100
        assert 0 <= pt["quality_score"] <= 100
    print("[PASS] Check 15: Trust score progression adheres to 85-point benchmark and component bounds")
    passed += 1

    print("=" * 70)
    print(f"MODULE 3V VERIFICATION SUCCESSFUL: {passed}/{total} CHECKS PASSED")
    print("=" * 70)
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    if not success:
        sys.exit(1)
