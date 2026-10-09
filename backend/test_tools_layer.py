import hashlib
import json
import urllib.request
import urllib.error
import sys

BASE_URL = "http://127.0.0.1:8000"


def make_request(path, method="GET", data=None):
    url = f"{BASE_URL}{path}"
    headers = {"Accept": "application/json"}
    body = None
    if data is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            status_code = resp.status
            resp_body = resp.read().decode("utf-8")
            return status_code, json.loads(resp_body) if resp_body else {}
    except urllib.error.HTTPError as e:
        resp_body = e.read().decode("utf-8")
        try:
            parsed = json.loads(resp_body)
        except Exception:
            parsed = {"raw": resp_body}
        return e.code, parsed


def run_tests():
    print("==================================================")
    print("AGENTIC SOC — MODULE 3B SECURITY TOOL LAYER TESTS")
    print("==================================================")
    passed = 0
    total = 0

    def assert_test(cond, title, detail=""):
        nonlocal passed, total
        total += 1
        if cond:
            passed += 1
            print(f"[PASS] Check {total:02d}: {title}")
            if detail:
                print(f"        -> {detail}")
        else:
            print(f"[FAIL] Check {total:02d}: {title}")
            if detail:
                print(f"        -> {detail}")
            sys.exit(1)

    # 1. Verify GET /api/tools returns all 6 allow-listed tools
    code, tools = make_request("/api/tools")
    assert_test(code == 200 and isinstance(tools, list) and len(tools) == 6, "List Allow-listed Tools (Count = 6)")

    tool_names = [t.get("tool_name") for t in tools]
    expected_tools = ["edr_process_search", "hash_lookup", "sandbox_summary", "siem_search", "whois_lookup", "yara_scan"]
    assert_test(
        all(t in tool_names for t in expected_tools),
        "All 6 Expected Tools Present in Registry",
        f"Registered: {', '.join(tool_names)}",
    )

    generated_evidence_ids = []

    # 2. Test Execution: siem_search
    siem_req = {
        "investigation_id": "INV-012",
        "tool_name": "siem_search",
        "input": {"query": "host=PC-DB-TEST powershell"},
    }
    code, siem_res = make_request("/api/tools/execute", method="POST", data=siem_req)
    assert_test(
        code == 200 and siem_res.get("success") is True and siem_res.get("evidence_id") is not None,
        "Execute siem_search (HTTP 200 & Auto-Evidence)",
        f"Evidence ID: {siem_res.get('evidence_id')}, Matches: {siem_res.get('data', {}).get('total_matches')}",
    )
    generated_evidence_ids.append(siem_res.get("evidence_id"))

    # 3. Test Execution: edr_process_search
    edr_req = {
        "investigation_id": "INV-012",
        "tool_name": "edr_process_search",
        "input": {"host": "PC-DB-TEST"},
    }
    code, edr_res = make_request("/api/tools/execute", method="POST", data=edr_req)
    assert_test(
        code == 200 and edr_res.get("success") is True and "powershell.exe" in edr_res.get("data', {}).get('lineage_summary", str(edr_res.get("data"))),
        "Execute edr_process_search (Process Lineage Returned)",
        f"Evidence ID: {edr_res.get('evidence_id')}, Lineage: {edr_res.get('data', {}).get('lineage_summary')}",
    )
    generated_evidence_ids.append(edr_res.get("evidence_id"))

    # 4. Test Execution: hash_lookup
    hash_req = {
        "investigation_id": "INV-012",
        "tool_name": "hash_lookup",
        "input": {"hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    }
    code, hash_res = make_request("/api/tools/execute", method="POST", data=hash_req)
    assert_test(
        code == 200 and hash_res.get("success") is True and hash_res.get("data", {}).get("reputation") == "UNKNOWN",
        "Execute hash_lookup (Deterministic UNKNOWN reputation for uncatalogued hash)",
        f"Evidence ID: {hash_res.get('evidence_id')}, Reputation: {hash_res.get('data', {}).get('reputation')}",
    )
    generated_evidence_ids.append(hash_res.get("evidence_id"))

    # 5. Test Execution: sandbox_summary
    sandbox_req = {
        "investigation_id": "INV-012",
        "tool_name": "sandbox_summary",
        "input": {"sample_id": "sample-001"},
    }
    code, sand_res = make_request("/api/tools/execute", method="POST", data=sandbox_req)
    assert_test(
        code == 200 and sand_res.get("success") is True and sand_res.get("data", {}).get("verdict") == "SUSPICIOUS",
        "Execute sandbox_summary (Behavioral Detonation Summary)",
        f"Evidence ID: {sand_res.get('evidence_id')}, Verdict: {sand_res.get('data', {}).get('verdict')}",
    )
    generated_evidence_ids.append(sand_res.get("evidence_id"))

    # 6. Test Execution: whois_lookup
    whois_req = {
        "investigation_id": "INV-012",
        "tool_name": "whois_lookup",
        "input": {"domain": "example.test"},
    }
    code, whois_res = make_request("/api/tools/execute", method="POST", data=whois_req)
    assert_test(
        code == 200 and whois_res.get("success") is True and whois_res.get("data", {}).get("registrar") is not None,
        "Execute whois_lookup (Deterministic Mock WHOIS)",
        f"Evidence ID: {whois_res.get('evidence_id')}, Registrar: {whois_res.get('data', {}).get('registrar')}",
    )
    generated_evidence_ids.append(whois_res.get("evidence_id"))

    # 7. Test Execution: yara_scan
    yara_req = {
        "investigation_id": "INV-012",
        "tool_name": "yara_scan",
        "input": {"sample_id": "sample-001"},
    }
    code, yara_res = make_request("/api/tools/execute", method="POST", data=yara_req)
    assert_test(
        code == 200 and yara_res.get("success") is True and yara_res.get("data", {}).get("total_matches", 0) > 0,
        "Execute yara_scan (YARA Rule Signature Match)",
        f"Evidence ID: {yara_res.get('evidence_id')}, Matches: {len(yara_res.get('data', {}).get('matches', []))}",
    )
    generated_evidence_ids.append(yara_res.get("evidence_id"))

    # 8. Cryptographic Proof: Verify every generated evidence item exists in Evidence Engine with valid SHA-256
    print("\n--- Verifying Generated Evidence Integrity ---")
    for ev_id in generated_evidence_ids:
        c, v_check = make_request(f"/api/evidence/{ev_id}/verify")
        assert_test(
            c == 200 and v_check.get("valid") is True,
            f"Evidence Integrity Check for {ev_id}",
            f"Hash: {v_check.get('content_hash')[:16]}... Valid: {v_check.get('valid')}",
        )

    # 9. Verify Tool Executions Audit Log
    code, audit_logs = make_request("/api/investigations/INV-012/tool-executions")
    assert_test(
        code == 200 and len(audit_logs) >= 6,
        "Tool Execution Audit Trail for INV-012",
        f"Recorded {len(audit_logs)} auditable tool executions",
    )

    # 10. SECURITY BOUNDARY TEST 1: Reject unknown tool 'run_shell_command'
    code, rej1 = make_request("/api/tools/execute", method="POST", data={
        "tool_name": "run_shell_command",
        "input": {"command": "whoami"},
    })
    assert_test(
        rej1.get("success") is False and rej1.get("error") == "TOOL_NOT_ALLOWLISTED",
        "Security Boundary: Reject 'run_shell_command'",
        f"Response: {rej1}",
    )

    # 11. SECURITY BOUNDARY TEST 2: Reject unauthorized tool 'execute_python'
    code, rej2 = make_request("/api/tools/execute", method="POST", data={
        "tool_name": "execute_python",
        "input": {"code": "import os; os.system('whoami')"},
    })
    assert_test(
        rej2.get("success") is False and rej2.get("error") == "TOOL_NOT_ALLOWLISTED",
        "Security Boundary: Reject 'execute_python'",
        f"Response: {rej2}",
    )

    # 12. SECURITY BOUNDARY TEST 3: Reject unauthorized tool 'run_powershell'
    code, rej3 = make_request("/api/tools/execute", method="POST", data={
        "tool_name": "run_powershell",
        "input": {"command": "Get-Process"},
    })
    assert_test(
        rej3.get("success") is False and rej3.get("error") == "TOOL_NOT_ALLOWLISTED",
        "Security Boundary: Reject 'run_powershell'",
        f"Response: {rej3}",
    )

    # 13. SECURITY BOUNDARY TEST 4: Reject shell metacharacters in parameter
    code, rej4 = make_request("/api/tools/execute", method="POST", data={
        "tool_name": "sandbox_summary",
        "input": {"sample_id": "sample-001; rm -rf /"},
    })
    assert_test(
        rej4.get("success") is False and "unauthorized shell token" in rej4.get("error", "").lower(),
        "Security Boundary: Reject Metacharacter Injection in Parameters",
        f"Error: {rej4.get('error')}",
    )

    # 14. Determinism Test: Same tool + same input -> same output
    code1, det1 = make_request("/api/tools/execute", method="POST", data=whois_req)
    code2, det2 = make_request("/api/tools/execute", method="POST", data=whois_req)
    assert_test(
        det1.get("data") == det2.get("data"),
        "Determinism Guarantee: Identical Tool Outputs for Identical Inputs",
        f"Data 1 == Data 2: {det1.get('data') == det2.get('data')}",
    )

    print("\n==================================================")
    print(f"ALL {passed}/{total} SECURITY TOOL LAYER TESTS PASSED!")
    print("==================================================")


if __name__ == "__main__":
    run_tests()
