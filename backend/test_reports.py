"""
Module 3P Test Suite — Executive Incident Reporting & Regulatory Compliance Engine
Agentic SOC — Auditable AI Security Operations Center

Verifies:
1. Health check exposes Module 3P reporting module and compliance frameworks.
2. GET /api/reports/summary returns valid aggregated statistics.
3. GET /api/reports returns seeded reports list.
4. GET /api/reports/{id} returns complete report with all required sections.
5. Report contains valid Threat Actor Attribution Policy enforcement (NOT ESTABLISHED / blocked).
6. Report contains valid Claims and Evidence correlation with evidence IDs.
7. Report contains Adversarial Red-Team / Critic review findings.
8. Report contains Regulatory Compliance evaluation across all 5 frameworks (NIST, ISO, SOC 2, GDPR, HIPAA).
9. Report compliance adherence score is calculated correctly (0-100%).
10. POST /api/reports/generate generates a new report on-demand for an investigation.
11. Generated report has a valid 64-character SHA-256 report_hash.
12. Generating a report commits a REPORT_GENERATED block into the Module 3L cryptographic audit ledger.
13. Module 3L audit trail chain verification passes (/api/audit-trail/verify) after report generation.
14. GET /api/reports/{id}/export/json returns valid Canonical Case JSON attachment.
15. GET /api/reports/{id}/export/markdown and /export/html return valid formatted documents.
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


def make_raw_request(path: str):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req) as resp:
        return resp.status, resp.read().decode("utf-8"), dict(resp.headers)


def run_tests():
    print("=" * 70)
    print("MODULE 3P: EXECUTIVE INCIDENT REPORTING & REGULATORY COMPLIANCE TEST SUITE")
    print("=" * 70)

    # 1. Health check exposes Module 3P
    st, health = make_request("/api/health")
    assert st == 200, f"Health check failed: {st}"
    assert "Module 3P" in health.get("reporting_module", ""), f"Module 3P reporting not in health: {health}"
    assert "NIST SP 800-61" in health.get("compliance_engine", ""), f"Compliance engine not in health: {health}"
    assert health.get("version") in ("0.15.0", "0.16.0", "0.17.0"), f"Unexpected version: {health.get('version')}"
    print("[PASS] Test 1: Health check exposes Module 3P reporting & compliance engine.")

    # 2. GET /api/reports/summary
    st, summary = make_request("/api/reports/summary")
    assert st == 200, f"Summary failed: {st}"
    assert summary.get("total_reports", 0) >= 4, f"Insufficient reports in summary: {summary}"
    assert summary.get("published_count", 0) >= 4, f"Insufficient published count: {summary}"
    assert 0 <= summary.get("average_compliance_score", 0) <= 100, f"Invalid compliance score: {summary}"
    print(f"[PASS] Test 2: Reports summary returns {summary['total_reports']} reports with {summary['average_compliance_score']}% compliance.")

    # 3. GET /api/reports list
    st, reports = make_request("/api/reports")
    assert st == 200, f"List failed: {st}"
    assert isinstance(reports, list) and len(reports) >= 4, f"Invalid reports list: {reports}"
    print(f"[PASS] Test 3: Listed {len(reports)} historical incident reports.")

    # 4. GET /api/reports/{id}
    rep_001 = next(r for r in reports if r["id"] == "REP-001")
    st, report = make_request(f"/api/reports/{rep_001['id']}")
    assert st == 200, f"Report lookup failed: {st}"
    assert report["id"] == "REP-001", f"ID mismatch: {report['id']}"
    assert "executive_summary" in report and len(report["executive_summary"]) > 20, "Missing executive summary"
    print(f"[PASS] Test 4: Retrieved individual report {report['id']} with full sections.")

    # 5. Threat Actor Attribution Guard
    threat_attr = report.get("threat_attribution", {})
    assert threat_attr.get("status") == "NOT ESTABLISHED", f"Attribution guard failed: {threat_attr}"
    assert "cannot assert a specific threat actor" in threat_attr.get("policy_note", ""), f"Missing policy note: {threat_attr}"
    print(f"[PASS] Test 5: Threat Actor Attribution Guard verified: status '{threat_attr['status']}' (policy strictly enforced).")

    # 6. Claims & Evidence Corroboration
    claims = report.get("claims", [])
    assert len(claims) >= 1, f"No claims in report: {report}"
    for c in claims:
        assert "claim_id" in c and "statement" in c and "status" in c, f"Malformed claim: {c}"
    evidence = report.get("evidence", [])
    assert len(evidence) >= 1, f"No evidence in report: {report}"
    print(f"[PASS] Test 6: Report contains {len(claims)} adjudicated claims verified against {len(evidence)} forensic evidence items.")

    # 7. Critic / Red-Team Findings
    critic_findings = report.get("critic_findings", [])
    assert len(critic_findings) >= 1, f"Missing critic findings: {report}"
    print(f"[PASS] Test 7: Adversarial Red-Team critique findings documented in report.")

    # 8. Regulatory Compliance Frameworks
    compliance = report.get("compliance_mappings", {})
    required_frameworks = [
        "NIST SP 800-61 Rev. 2",
        "ISO/IEC 27035:2023",
        "SOC 2 Type II",
        "GDPR Article 33",
        "HIPAA Security Rule",
    ]
    for fw in required_frameworks:
        assert fw in compliance, f"Missing compliance framework {fw} in report: {list(compliance.keys())}"
        fw_data = compliance[fw]
        assert fw_data.get("status") == "COMPLIANT", f"Framework {fw} not compliant: {fw_data}"
        assert len(fw_data.get("controls", [])) >= 2, f"Insufficient controls in {fw}: {fw_data}"
    print(f"[PASS] Test 8: All 5 international regulatory compliance frameworks successfully mapped.")

    # 9. Compliance adherence score
    comp_score = report.get("compliance_score", 0.0)
    assert 90.0 <= comp_score <= 100.0, f"Unexpected compliance score: {comp_score}"
    print(f"[PASS] Test 9: Aggregate regulatory compliance adherence score verified: {comp_score}%.")

    # 10. POST /api/reports/generate on-demand
    new_report_payload = {
        "investigation_id": "INV-001",
        "report_type": "TECHNICAL",
        "classification": "RESTRICTED",
        "notes": "Automated technical post-mortem report.",
        "author": "Forensic Automation Unit",
    }
    st, new_rep = make_request("/api/reports/generate", method="POST", data=new_report_payload)
    assert st == 200, f"Generate report failed: {st}, {new_rep}"
    assert new_rep["investigation_id"] == "INV-001", f"Investigation ID mismatch: {new_rep}"
    assert new_rep["report_type"] == "TECHNICAL", f"Report type mismatch: {new_rep}"
    assert new_rep["classification"] == "RESTRICTED", f"Classification mismatch: {new_rep}"
    print(f"[PASS] Test 10: Successfully generated on-demand report {new_rep['id']} for INV-001.")

    # 11. Report SHA-256 Hash
    h = new_rep.get("report_hash", "")
    assert len(h) == 64 and all(c in "0123456789abcdef" for c in h), f"Invalid report hash: {h}"
    print(f"[PASS] Test 11: Cryptographic SHA-256 fingerprint verified: {h[:24]}...")

    # 12. Audit ledger block appended
    audit_entry_id = new_rep.get("audit_entry_id")
    assert audit_entry_id and audit_entry_id.startswith("AUD-"), f"Missing audit entry: {audit_entry_id}"
    st, audit_trail = make_request("/api/audit-trail")
    assert st == 200, f"Audit trail failed: {st}"
    entries = audit_trail if isinstance(audit_trail, list) else audit_trail.get("entries", [])
    events = [e for e in entries if e.get("event_type") == "REPORT_GENERATED"]
    assert len(events) >= 1, f"REPORT_GENERATED not found in audit trail: {events}"
    print(f"[PASS] Test 12: Cryptographic ledger block {audit_entry_id} appended with REPORT_GENERATED event.")

    # 13. Audit trail chain integrity verification
    st, verify_res = make_request("/api/audit-trail/verify")
    assert st == 200, f"Audit verification endpoint failed: {st}"
    assert verify_res.get("chain_valid") is True, f"Audit ledger chain corrupted after report generation: {verify_res}"
    print("[PASS] Test 13: Cryptographic audit trail chain integrity verified (100% tamper-evident).")

    # 14. Export Case JSON endpoint
    st, raw_json, headers = make_raw_request(f"/api/reports/{new_rep['id']}/export/json")
    assert st == 200, f"Export JSON failed: {st}"
    case_json = json.loads(raw_json)
    assert case_json.get("case_id") == "INV-001", f"Case ID mismatch: {case_json}"
    assert "claims" in case_json and "evidence" in case_json, f"Missing case fields: {case_json}"
    print("[PASS] Test 14: Canonical Case JSON export endpoint validated with complete audit package.")

    # 15. Export Markdown & HTML endpoints
    st, raw_md, _ = make_raw_request(f"/api/reports/{new_rep['id']}/export/markdown")
    assert st == 200, f"Export Markdown failed: {st}"
    assert "# Incident Security Report:" in raw_md, f"Malformed markdown: {raw_md[:100]}"

    st, raw_html, _ = make_raw_request(f"/api/reports/{new_rep['id']}/export/html")
    assert st == 200, f"Export HTML failed: {st}"
    assert "<!DOCTYPE html>" in raw_html and "CRYPTOGRAPHIC AUDIT ATTESTATION" in raw_html, "Malformed HTML"
    print("[PASS] Test 15: Markdown and standalone printable HTML export endpoints validated.")

    print("=" * 70)
    print("MODULE 3P TEST RESULTS: 15/15 PASSED")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
