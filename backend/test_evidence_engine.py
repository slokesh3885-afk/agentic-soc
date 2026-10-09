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
    print("AGENTIC SOC — MODULE 3A EVIDENCE ENGINE VERIFICATION")
    print("==================================================")
    passed = 0
    total = 0

    def assert_test(cond, title, detail=""):
        nonlocal passed, total
        total += 1
        if cond:
            passed += 1
            print(f"[PASS] Test {total}: {title}")
            if detail:
                print(f"       -> {detail}")
        else:
            print(f"[FAIL] Test {total}: {title}")
            if detail:
                print(f"       -> {detail}")
            sys.exit(1)

    # 1. Health check
    code, res = make_request("/api/health")
    assert_test(code == 200 and res.get("status") == "ok", "Backend Health Check", f"Module: {res.get('module')}")

    # 2. Check INV-012 exists
    code, inv = make_request("/api/investigations/INV-012")
    assert_test(code == 200 and inv.get("id") == "INV-012", "Investigation INV-012 Exists", f"Target Host: {inv.get('target_host')}")

    # 3. List evidence for INV-012
    code, ev_list = make_request("/api/investigations/INV-012/evidence")
    assert_test(code == 200 and len(ev_list) >= 2, "List Evidence for INV-012", f"Found {len(ev_list)} evidence objects")

    # 4. Check E-001 content & SHA-256
    e001 = next((e for e in ev_list if e.get("id") == "E-001"), None)
    assert_test(e001 is not None, "E-001 Present in INV-012", f"Evidence Type: {e001.get('evidence_type') if e001 else 'N/A'}")
    
    expected_e001_raw = "powershell.exe executed from an unusual parent process."
    expected_e001_hash = hashlib.sha256(expected_e001_raw.encode("utf-8")).hexdigest()
    assert_test(
        e001.get("raw_output") == expected_e001_raw and e001.get("content_hash") == expected_e001_hash,
        "E-001 Deterministic SHA-256 Hash Match",
        f"Hash: {e001.get('content_hash')}",
    )

    # 5. Check E-002 content & SHA-256
    e002 = next((e for e in ev_list if e.get("id") == "E-002"), None)
    assert_test(e002 is not None, "E-002 Present in INV-012", f"Evidence Type: {e002.get('evidence_type') if e002 else 'N/A'}")
    
    expected_e002_raw = "powershell.exe spawned by unknown_process.exe."
    expected_e002_hash = hashlib.sha256(expected_e002_raw.encode("utf-8")).hexdigest()
    assert_test(
        e002.get("raw_output") == expected_e002_raw and e002.get("content_hash") == expected_e002_hash,
        "E-002 Deterministic SHA-256 Hash Match",
        f"Hash: {e002.get('content_hash')}",
    )

    # 6. Single evidence lookup
    code, single = make_request("/api/evidence/E-001")
    assert_test(code == 200 and single.get("id") == "E-001", "GET /api/evidence/E-001 Lookup", f"Source: {single.get('source')}")

    # 7. Cryptographic integrity verification endpoint
    code, v_res = make_request("/api/evidence/E-001/verify")
    assert_test(
        code == 200 and v_res.get("valid") is True and v_res.get("content_hash") == v_res.get("recalculated_hash"),
        "GET /api/evidence/E-001/verify Integrity Verified",
        f"Valid: {v_res.get('valid')}, Recalculated: {v_res.get('recalculated_hash')[:16]}...",
    )

    # 8. Rejection of evidence creation on nonexistent investigation
    code, err_res = make_request(
        "/api/investigations/INV-999/evidence",
        method="POST",
        data={
            "evidence_type": "DNS_EVENT",
            "source": "Mock DNS",
            "raw_output": "test rejection output",
        },
    )
    assert_test(code == 404, "Reject Evidence on Nonexistent Investigation INV-999 (HTTP 404)", f"Detail: {err_res.get('detail')}")

    # 9. Append new evidence to INV-012
    sample_raw = "NetFlow session: TCP 10.0.0.45:49182 -> 198.51.100.42:443 (8452 bytes transferred)"
    sample_hash = hashlib.sha256(sample_raw.encode("utf-8")).hexdigest()
    code, created_ev = make_request(
        "/api/investigations/INV-012/evidence",
        method="POST",
        data={
            "evidence_type": "DNS_EVENT",
            "source": "Zeek Network Monitor",
            "query": "conn.log | filter host=PC-DB-TEST",
            "raw_output": sample_raw,
        },
    )
    assert_test(
        code == 201 and created_ev.get("content_hash") == sample_hash,
        "POST /api/investigations/INV-012/evidence (Autonomous ID & SHA-256)",
        f"Created ID: {created_ev.get('id')}, Hash: {created_ev.get('content_hash')[:16]}...",
    )

    # 10. Verify integrity of newly created evidence item
    new_ev_id = created_ev.get("id")
    code, new_v = make_request(f"/api/evidence/{new_ev_id}/verify")
    assert_test(
        code == 200 and new_v.get("valid") is True,
        f"Verify Integrity of Newly Created {new_ev_id}",
        f"Hash Match: {new_v.get('recalculated_hash')[:16]}... Valid: {new_v.get('valid')}",
    )

    # 11. Verify parent investigation evidence_count incremented
    code, updated_inv = make_request("/api/investigations/INV-012")
    assert_test(
        code == 200 and updated_inv.get("evidence_count") >= 3,
        "Parent Investigation evidence_count Incremented",
        f"Updated Count: {updated_inv.get('evidence_count')}",
    )

    # 12. Strict Append-Only Verification (No UPDATE / No DELETE)
    code_put, _ = make_request(f"/api/evidence/{new_ev_id}", method="PUT", data={"raw_output": "tampered"})
    code_del, _ = make_request(f"/api/evidence/{new_ev_id}", method="DELETE")
    assert_test(
        code_put in [404, 405] and code_del in [404, 405],
        "Append-Only Integrity (PUT and DELETE Rejected)",
        f"PUT status: {code_put}, DELETE status: {code_del}",
    )

    print("==================================================")
    print(f"ALL {passed}/{total} VERIFICATION CHECKS PASSED PERFECTLY!")
    print("==================================================")


if __name__ == "__main__":
    run_tests()
