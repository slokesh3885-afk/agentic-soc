import subprocess
import sys

files = [
    "test_evidence_engine.py",
    "test_tools_layer.py",
    "test_planner.py",
    "test_critic.py",
    "test_auditor.py",
    "test_case_schema.py",
    "test_trust_score.py",
    "test_scenario_true_positive.py",
    "test_scenario_trap.py",
    "test_human_approval.py",
    "test_websockets.py",
    "test_audit_trail.py",
    "test_dossiers.py",
    "test_containment.py",
    "test_replay.py",
    "test_reports.py",
    "test_agents.py",
    "test_evidence_control_plane.py",
    "test_critic_redteam.py",
    "test_case_audit_object.py",
    "test_system_control_plane.py",
    "test_overview_analytics.py",
    "test_control_plane_integration.py",
    "test_interactive_orchestrator.py",
    "test_reusable_components_trust_score.py",
    "test_module_3z_final_verification.py",
]

total_checks = 0
all_passed = True

print("======================================================================")
print("AGENTIC SOC: FULL REGRESSION TEST SUITE (MODULES 3A - 3Z)")
print("======================================================================")

for f in files:
    res = subprocess.run([sys.executable, f], capture_output=True, text=True)
    out_lines = [l for l in res.stdout.strip().splitlines() if "PASSED" in l or "RESULTS" in l]
    summary_line = out_lines[-1] if out_lines else "NO SUMMARY FOUND"
    print(f"[{'PASS' if res.returncode == 0 else 'FAIL'}] {f}: {summary_line}")
    if res.returncode != 0:
        print("  Error output:", res.stderr or res.stdout)
        all_passed = False
    # Extract passed count if in format X/Y PASSED
    import re
    m = re.search(r"(\d+)/\1\s+PASSED", summary_line)
    if m:
        total_checks += int(m.group(1))

print("======================================================================")
print(f"OVERALL SUMMARY: {total_checks} CHECKS VERIFIED. ALL SUITES PASSED: {all_passed}")
print("======================================================================")

if not all_passed:
    sys.exit(1)
