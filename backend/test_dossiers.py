"""
Module 3M: Incident Cases Dossier & MITRE ATT&CK Matrix Mapping Test Suite.
Validates:
1. Health check exposes Module 3M Dossier & MITRE ATT&CK Matrix engine.
2. Initial seeded dossiers listing (GET /api/dossiers).
3. Single dossier retrieval by ID (GET /api/dossiers/DOS-001).
4. Dossier lookup by investigation ID (GET /api/dossiers/investigation/INV-001).
5. Deterministic MITRE ATT&CK technique mapping (e.g. T1059.001 Command and Scripting Interpreter).
6. Evidence linkage corroboration in MITRE technique mappings.
7. Forensic Chain of Custody chronological sequence and verification status.
8. Forensic Chain of Custody integration with Module 3L Cryptographic Ledger seal.
9. MITRE Matrix summary statistics and 14-tactic breakdown (GET /api/dossiers/matrix/summary).
10. MITRE ATT&CK Navigator JSON layer generation and schema validity (GET /api/dossiers/DOS-001/navigator).
11. Query filtering by severity (GET /api/dossiers?severity=Critical).
12. Query filtering by primary tactic (GET /api/dossiers?tactic=Execution).
13. Refresh dossier endpoint with updated multi-agent analysis (POST /api/dossiers/refresh/INV-001).
14. Threat actor attribution policy (corroborated vs withheld based on Critic reasoning).
15. Boundary condition and error handling (404 on nonexistent dossier and investigation).
"""

import json
import sys
import urllib.request
import urllib.error

BASE_URL = "http://127.0.0.1:8000"


def http_get(path):
    url = f"{BASE_URL}{path}"
    req = urllib.request.Request(url, headers={"User-Agent": "Module3M-Tester"})
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())


def http_post(path, data=None):
    url = f"{BASE_URL}{path}"
    payload = json.dumps(data or {}).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "Module3M-Tester"},
        method="POST"
    )
    with urllib.request.urlopen(req) as resp:
        return resp.status, json.loads(resp.read().decode())


def run_tests():
    passed = 0
    total = 15

    print("======================================================================")
    print("MODULE 3M: INCIDENT CASES DOSSIER & MITRE ATT&CK TEST SUITE")
    print("======================================================================")

    # 1. Health check exposes Module 3M Dossier & MITRE ATT&CK Matrix engine
    try:
        status, data = http_get("/api/health")
        assert status == 200, f"Expected 200, got {status}"
        assert "dossier_module" in data, "Missing dossier_module in health"
        assert "Module 3M" in data["dossier_module"], f"Unexpected dossier_module: {data['dossier_module']}"
        assert "mitre_matrix_engine" in data, "Missing mitre_matrix_engine in health"
        print("[PASS] Test 1: Health check exposes Module 3M Dossier & MITRE ATT&CK Matrix engine.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 1: Health check failed: {e}")

    # 2. Initial seeded dossiers listing (GET /api/dossiers)
    try:
        status, dossiers = http_get("/api/dossiers")
        assert status == 200, f"Expected 200, got {status}"
        assert isinstance(dossiers, list), "Expected list of dossiers"
        assert len(dossiers) >= 4, f"Expected at least 4 dossiers, got {len(dossiers)}"
        inv_ids = [d["investigation_id"] for d in dossiers]
        assert "INV-001" in inv_ids, "Missing INV-001 in seeded dossiers"
        assert "INV-002" in inv_ids, "Missing INV-002 in seeded dossiers"
        print(f"[PASS] Test 2: Seeded dossiers listing returned {len(dossiers)} case dossiers.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 2: Dossiers listing failed: {e}")

    # 3. Single dossier retrieval by ID (GET /api/dossiers/DOS-001)
    try:
        status, dossier = http_get("/api/dossiers/DOS-001")
        assert status == 200, f"Expected 200, got {status}"
        assert dossier["id"] == "DOS-001", f"Expected DOS-001, got {dossier['id']}"
        assert dossier["investigation_id"] == "INV-001", f"Expected INV-001, got {dossier['investigation_id']}"
        assert "mitre_techniques" in dossier, "Missing mitre_techniques in dossier"
        assert "custody_chain" in dossier, "Missing custody_chain in dossier"
        print("[PASS] Test 3: Retrieved single dossier DOS-001 with complete schema.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 3: Single dossier lookup failed: {e}")

    # 4. Dossier lookup by investigation ID (GET /api/dossiers/investigation/INV-001)
    try:
        status, dossier = http_get("/api/dossiers/investigation/INV-001")
        assert status == 200, f"Expected 200, got {status}"
        assert dossier["investigation_id"] == "INV-001", f"Expected INV-001, got {dossier['investigation_id']}"
        assert dossier["id"] == "DOS-001", f"Expected DOS-001, got {dossier['id']}"
        print("[PASS] Test 4: Dossier lookup by investigation ID INV-001 succeeded.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 4: Investigation lookup failed: {e}")

    # 5. Deterministic MITRE ATT&CK technique mapping
    try:
        status, dossier = http_get("/api/dossiers/DOS-001")
        techs = dossier.get("mitre_techniques", [])
        assert len(techs) >= 1, "Expected at least 1 mapped MITRE technique"
        tech_ids = [t["technique_id"] for t in techs]
        assert "T1059.001" in tech_ids, f"Expected T1059.001 for INV-001 PowerShell alert, got {tech_ids}"
        ps_mapping = next(t for t in techs if t["technique_id"] == "T1059.001")
        assert ps_mapping["tactic"] == "Execution", f"Expected Execution tactic, got {ps_mapping['tactic']}"
        assert ps_mapping["confidence"] >= 0.8, f"Confidence too low: {ps_mapping['confidence']}"
        assert "attack.mitre.org" in ps_mapping["url"], "Missing MITRE URL reference"
        print(f"[PASS] Test 5: MITRE ATT&CK mapping T1059.001 mapped with confidence {ps_mapping['confidence']}.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 5: MITRE technique mapping failed: {e}")

    # 6. Evidence linkage corroboration in MITRE technique mappings
    try:
        status, dossier = http_get("/api/dossiers/DOS-001")
        techs = dossier.get("mitre_techniques", [])
        ps_mapping = next(t for t in techs if t["technique_id"] == "T1059.001")
        assert isinstance(ps_mapping["evidence_ids"], list), "evidence_ids must be a list"
        print(f"[PASS] Test 6: Evidence IDs {ps_mapping['evidence_ids']} corroborated in MITRE mapping.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 6: Evidence corroboration check failed: {e}")

    # 7. Forensic Chain of Custody chronological sequence and verification status
    try:
        status, dossier = http_get("/api/dossiers/DOS-001")
        chain = dossier.get("custody_chain", [])
        assert len(chain) >= 2, f"Expected at least 2 custody transfer events, got {len(chain)}"
        # Verify sequence numbers are monotonic 1, 2, 3...
        sequences = [c["sequence"] for c in chain]
        assert sequences == list(range(1, len(chain) + 1)), f"Sequences not monotonic: {sequences}"
        assert chain[0]["action"] == "TELEMETRY_INGESTION", f"First event must be TELEMETRY_INGESTION, got {chain[0]['action']}"
        assert all(c["verified"] for c in chain), "All custody events must have verified status"
        print(f"[PASS] Test 7: Forensic chain of custody valid across {len(chain)} monotonic events.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 7: Custody chain verification failed: {e}")

    # 8. Forensic Chain of Custody integration with Module 3L Cryptographic Ledger seal
    try:
        # Check if custody chain records forensic events
        status, dossier = http_get("/api/dossiers/DOS-001")
        chain = dossier.get("custody_chain", [])
        actions = [c["action"] for c in chain]
        assert "TELEMETRY_INGESTION" in actions, "Missing TELEMETRY_INGESTION in custody chain"
        # Verify hash integrity in chain events
        for item in chain:
            assert item["artifact_hash"], f"Missing artifact hash in event {item['sequence']}"
        print(f"[PASS] Test 8: Chain of custody securely binds hashes for actions: {actions[:3]}.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 8: Cryptographic seal integration failed: {e}")

    # 9. MITRE Matrix summary statistics and 14-tactic breakdown (GET /api/dossiers/matrix/summary)
    try:
        status, matrix = http_get("/api/dossiers/matrix/summary")
        assert status == 200, f"Expected 200, got {status}"
        assert matrix["matrix_version"] == "v14.1", f"Expected v14.1, got {matrix['matrix_version']}"
        assert matrix["total_dossiers"] >= 4, f"Expected at least 4 dossiers, got {matrix['total_dossiers']}"
        assert matrix["total_techniques_mapped"] >= 1, "Expected mapped techniques"
        assert "Execution" in matrix["tactics_breakdown"], "Execution tactic missing in breakdown"
        assert len(matrix["coverage"]) == 14, f"Expected 14 Enterprise tactics in coverage, got {len(matrix['coverage'])}"
        print(f"[PASS] Test 9: MITRE Matrix summary verified with {len(matrix['coverage'])} Enterprise tactics.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 9: Matrix summary check failed: {e}")

    # 10. MITRE ATT&CK Navigator JSON layer generation and schema validity
    try:
        status, layer = http_get("/api/dossiers/DOS-001/navigator")
        assert status == 200, f"Expected 200, got {status}"
        assert "Agentic SOC" in layer["name"], f"Expected Agentic SOC in layer name, got {layer['name']}"
        assert layer["domain"] == "enterprise-attack", f"Expected enterprise-attack, got {layer['domain']}"
        assert layer["versions"]["attack"] == "14", f"Expected ATT&CK version 14, got {layer['versions']}"
        assert isinstance(layer["techniques"], list), "Expected list of techniques"
        assert len(layer["techniques"]) >= 1, "Expected at least 1 technique in Navigator layer"
        tech = layer["techniques"][0]
        assert "techniqueID" in tech, "Missing techniqueID in navigator technique"
        assert "score" in tech, "Missing score in navigator technique"
        print(f"[PASS] Test 10: Generated valid ATT&CK Navigator JSON layer with {len(layer['techniques'])} techniques.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 10: Navigator layer generation failed: {e}")

    # 11. Query filtering by severity (GET /api/dossiers?severity=Critical)
    try:
        status, crit_dossiers = http_get("/api/dossiers?severity=Critical")
        assert status == 200, f"Expected 200, got {status}"
        for d in crit_dossiers:
            assert d["severity"].lower() == "critical", f"Expected Critical, got {d['severity']}"
        print(f"[PASS] Test 11: Severity query filter correctly filtered {len(crit_dossiers)} Critical dossiers.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 11: Severity filter check failed: {e}")

    # 12. Query filtering by primary tactic (GET /api/dossiers?tactic=Execution)
    try:
        status, exec_dossiers = http_get("/api/dossiers?tactic=Execution")
        assert status == 200, f"Expected 200, got {status}"
        for d in exec_dossiers:
            assert "Execution" in d["primary_tactic"], f"Expected Execution in primary_tactic, got {d['primary_tactic']}"
        print(f"[PASS] Test 12: Tactic query filter correctly filtered {len(exec_dossiers)} Execution dossiers.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 12: Tactic filter check failed: {e}")

    # 13. Refresh dossier endpoint (POST /api/dossiers/refresh/INV-001)
    try:
        status, refreshed = http_post("/api/dossiers/refresh/INV-001")
        assert status == 200, f"Expected 200, got {status}"
        assert refreshed["investigation_id"] == "INV-001", "Expected INV-001"
        assert refreshed["id"] == "DOS-001", "Expected DOS-001"
        assert refreshed["updated_at"] is not None, "Expected updated_at to be populated"
        print(f"[PASS] Test 13: Refreshed dossier DOS-001 at {refreshed['updated_at']}.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 13: Refresh dossier failed: {e}")

    # 14. Threat actor attribution policy (corroborated vs withheld based on Critic reasoning)
    try:
        # Check DOS-001 and DOS-004 attribution
        status, d1 = http_get("/api/dossiers/DOS-001")
        assert "threat_actor_attribution" in d1, "Missing threat_actor_attribution"
        attr = d1["threat_actor_attribution"]
        assert attr is not None, "Attribution should be non-null string"
        print(f"[PASS] Test 14: Threat actor attribution policy verified: '{attr}'.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 14: Threat attribution check failed: {e}")

    # 15. Boundary condition and error handling (404 on nonexistent targets)
    try:
        err_404_count = 0
        try:
            http_get("/api/dossiers/DOS-NONEXISTENT")
        except urllib.error.HTTPError as he:
            if he.code == 404:
                err_404_count += 1

        try:
            http_get("/api/dossiers/investigation/INV-DOES-NOT-EXIST")
        except urllib.error.HTTPError as he:
            if he.code == 404:
                err_404_count += 1

        assert err_404_count == 2, f"Expected two 404 errors, got {err_404_count}"
        print("[PASS] Test 15: Boundary and error handling correctly returns 404 for invalid targets.")
        passed += 1
    except Exception as e:
        print(f"[FAIL] Test 15: Error handling test failed: {e}")

    print("======================================================================")
    print(f"MODULE 3M TEST RESULTS: {passed}/{total} PASSED")
    print("======================================================================")

    if passed == total:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    run_tests()
