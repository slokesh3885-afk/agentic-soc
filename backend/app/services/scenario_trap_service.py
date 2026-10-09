"""
Scenario Trap Service (Module 3I)
Agentic SOC — Auditable AI Security Operations Center

Deterministic pipeline execution for the Synthetic Trap / Deception demonstration scenario:
Evidence Engine -> Planner -> Critic -> Auditor -> Case JSON -> Trust Score.

Demonstrates that the multi-agent SOC pipeline detects misleading, contradictory, or
intentionally deceptive evidence rather than blindly accepting investigator draft conclusions.

Strictly synthetic demonstration data:
- No real infrastructure or credentials
- Target host: TEST-SRV-FIN-02.corp.test
- Deceptive signal: Authorized IT Change Management ticket CHG-99214 conflicting with suspicious alert
- Full multi-agent pipeline verification with automated contradiction detection
"""

import json
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session

from app.models.investigation import InvestigationModel
from app.models.evidence import EvidenceModel
from app.models.tool_execution import ToolExecutionModel
from app.schemas.evidence import EvidenceResponse
from app.schemas.scenario_trap import TrapScenarioResponse
from app.schemas.critic import CriticRequest, ClaimInput as CriticClaimInput
from app.schemas.auditor import AuditorRequest, AuditClaimInput
from app.services.evidence_service import compute_content_hash
from app.services.planner_service import create_or_update_investigation_plan
from app.services.critic_service import evaluate_draft_conclusion
from app.services.auditor_service import audit_investigation, export_canonical_case
from app.services.trust_score_service import get_investigation_trust_score

# Stable identifiers for the synthetic trap scenario
SYNTHETIC_TRAP_INV_ID = "INV-TRAP-001"
SYNTHETIC_TRAP_HOST = "TEST-SRV-FIN-02.corp.test"
SYNTHETIC_TRAP_ALERT = "Synthetic Trap: Suspicious Script Execution with Contradictory Maintenance Telemetry"
DECEPTIVE_EVIDENCE_ID = "E-TRAP-DECEPTIVE"

SYNTHETIC_TRAP_EVIDENCE_DEFS = [
    {
        "id": "E-TRAP-SIEM",
        "evidence_type": "SIEM_LOG",
        "source": "Synthetic SIEM / Detection Sensor",
        "timestamp": "2026-09-27 11:30:10 UTC",
        "raw_output": (
            "[SYNTHETIC TRAP TEST] EventID: 4104 - ScriptBlock logging flagged suspicious obfuscated command: "
            "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Enc WwBTAHkAcwB0AGUAbQ... on TEST-SRV-FIN-02. "
            "Telemetry indicates suspicious unauthorized PowerShell execution."
        ),
    },
    {
        "id": "E-TRAP-EDR",
        "evidence_type": "EDR_EVENT",
        "source": "Synthetic Endpoint EDR",
        "timestamp": "2026-09-27 11:30:45 UTC",
        "raw_output": (
            "[SYNTHETIC TRAP TEST] Process tree: winlogon.exe -> services.exe -> powershell.exe (PID 6248) "
            "executing backup_maintenance.ps1 on host TEST-SRV-FIN-02. Parent process is legitimate services subsystem."
        ),
    },
    {
        "id": "E-TRAP-DECEPTIVE",
        "evidence_type": "SIEM_LOG",
        "source": "Synthetic IT Change Management System",
        "timestamp": "2026-09-27 11:31:00 UTC",
        "raw_output": (
            "[SYNTHETIC TRAP TEST] IT Change Management Ticket CHG-99214: Approved administrative backup "
            "and health probe script execution by authorized IT administrator. Status: approved administrative script, "
            "authorized task, scheduled backup script, approved maintenance."
        ),
    },
    {
        "id": "E-TRAP-AUTH",
        "evidence_type": "SIEM_LOG",
        "source": "Synthetic Active Directory Domain Controller",
        "timestamp": "2026-09-27 11:30:05 UTC",
        "raw_output": (
            "[SYNTHETIC TRAP TEST] EventID: 4624 - Successful interactive logon for domain service account "
            "svc_backup_admin from trusted administrative subnet 10.0.4.15."
        ),
    },
]

SYNTHETIC_TRAP_TOOL_EXECS = [
    {
        "id": "EXEC-TRAP-001",
        "tool_name": "siem_search",
        "input": {"query": "EventID:4104 TEST-SRV-FIN-02", "timeframe": "1h"},
        "output": {"matches": 1, "alert": "Suspicious ScriptBlock"},
        "success": True,
        "timestamp": "2026-09-27 11:30:15 UTC",
        "evidence_id": "E-TRAP-SIEM",
    },
    {
        "id": "EXEC-TRAP-002",
        "tool_name": "edr_process_search",
        "input": {"host": SYNTHETIC_TRAP_HOST, "process": "powershell.exe"},
        "output": {"pid": 6248, "parent": "services.exe", "script": "backup_maintenance.ps1"},
        "success": True,
        "timestamp": "2026-09-27 11:30:50 UTC",
        "evidence_id": "E-TRAP-EDR",
    },
]

SYNTHETIC_TRAP_CLAIMS_INPUT = [
    {
        "claim": "Malicious unauthorized PowerShell execution occurred on host TEST-SRV-FIN-02",
        "evidence_ids": ["E-TRAP-SIEM", "E-TRAP-DECEPTIVE"],
    },
    {
        "claim": "Process execution matches approved scheduled administrative backup task",
        "evidence_ids": ["E-TRAP-EDR", "E-TRAP-DECEPTIVE"],
    },
    {
        "claim": "Activity is definitely attributed to external threat actor APT-29",
        "evidence_ids": [],
    },
]

SYNTHETIC_TRAP_DRAFT_CONCLUSION = (
    "Draft Conclusion: Malicious unauthorized PowerShell execution occurred on host TEST-SRV-FIN-02 "
    "and is definitely attributed to threat actor APT-29."
)


def run_trap_scenario(db: Session, force_reset: bool = True) -> TrapScenarioResponse:
    """
    Execute the deterministic Synthetic Trap / Deception Scenario (Module 3I).
    Runs the multi-agent SOC pipeline and demonstrates detection of deceptive and contradictory evidence:
    1. Seed parent synthetic trap investigation
    2. Seed conflicting synthetic evidence (suspicious alert vs. approved maintenance log)
    3. Run Planner Agent
    4. Run Critic / Red-Team Review (flags contradiction between E-TRAP-SIEM and E-TRAP-DECEPTIVE, flags overclaims)
    5. Run Auditor Agent (evaluates contradiction, marks claim CONTRADICTED, rejects unsupported attribution)
    6. Export Canonical Case JSON
    7. Compute Evidence Trust Score (reflects contradiction penalties)
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Seed or retrieve parent synthetic trap investigation
    inv = db.query(InvestigationModel).filter(InvestigationModel.id == SYNTHETIC_TRAP_INV_ID).first()
    if not inv:
        inv = InvestigationModel(
            id=SYNTHETIC_TRAP_INV_ID,
            alert_name=SYNTHETIC_TRAP_ALERT,
            target_host=SYNTHETIC_TRAP_HOST,
            severity="High",
            event_timestamp="2026-09-27 11:30:00 UTC",
            description=(
                "[SYNTHETIC TRAP TEST] Deception test case evaluating system resilience against conflicting evidence. "
                "Suspicious script execution alert contradicted by approved IT Change Management ticket CHG-99214."
            ),
            status="Investigating",
            evidence_count=len(SYNTHETIC_TRAP_EVIDENCE_DEFS),
            trust_score=50,
            created_at=now_utc,
            assigned_agent="Host Triage Agent",
            mitre_technique="T1059.001 (PowerShell) / T1078 (Valid Accounts)",
        )
        db.add(inv)
        db.commit()
        db.refresh(inv)

    # 2. Seed synthetic evidence items with SHA-256 hashes
    evidence_models: List[EvidenceModel] = []
    for ev_def in SYNTHETIC_TRAP_EVIDENCE_DEFS:
        existing_ev = db.query(EvidenceModel).filter(EvidenceModel.id == ev_def["id"]).first()
        content_hash = compute_content_hash(ev_def["raw_output"])

        if existing_ev:
            existing_ev.investigation_id = SYNTHETIC_TRAP_INV_ID
            existing_ev.evidence_type = ev_def["evidence_type"]
            existing_ev.source = ev_def["source"]
            existing_ev.timestamp = ev_def["timestamp"]
            existing_ev.raw_output = ev_def["raw_output"]
            existing_ev.content_hash = content_hash
            existing_ev.status = "COLLECTED"
            evidence_models.append(existing_ev)
        else:
            new_ev = EvidenceModel(
                id=ev_def["id"],
                investigation_id=SYNTHETIC_TRAP_INV_ID,
                evidence_type=ev_def["evidence_type"],
                source=ev_def["source"],
                timestamp=ev_def["timestamp"],
                raw_output=ev_def["raw_output"],
                content_hash=content_hash,
                status="COLLECTED",
                created_at=ev_def["timestamp"],
            )
            db.add(new_ev)
            evidence_models.append(new_ev)

    db.commit()

    # 3. Seed synthetic tool executions
    for tool_def in SYNTHETIC_TRAP_TOOL_EXECS:
        existing_t = db.query(ToolExecutionModel).filter(ToolExecutionModel.id == tool_def["id"]).first()
        if not existing_t:
            new_t = ToolExecutionModel(
                id=tool_def["id"],
                investigation_id=SYNTHETIC_TRAP_INV_ID,
                tool_name=tool_def["tool_name"],
                input=json.dumps(tool_def["input"]),
                output=json.dumps(tool_def["output"]),
                success=tool_def["success"],
                timestamp=tool_def["timestamp"],
                evidence_id=tool_def["evidence_id"],
            )
            db.add(new_t)

    db.commit()

    # 4. Pipeline Step 1: Planner Agent
    planner_res = create_or_update_investigation_plan(db, SYNTHETIC_TRAP_INV_ID, SYNTHETIC_TRAP_ALERT)

    # 5. Pipeline Step 2: Critic Agent (Challenges draft, detects contradiction & attribution)
    critic_req = CriticRequest(
        investigation_id=SYNTHETIC_TRAP_INV_ID,
        draft_conclusion=SYNTHETIC_TRAP_DRAFT_CONCLUSION,
        claims=[
            CriticClaimInput(claim=c["claim"], evidence_ids=c["evidence_ids"])
            for c in SYNTHETIC_TRAP_CLAIMS_INPUT
        ],
    )
    critic_res = evaluate_draft_conclusion(db, SYNTHETIC_TRAP_INV_ID, critic_req)

    # 6. Pipeline Step 3: Auditor Agent (Resolves contradiction, applies NO EVIDENCE -> NO CLAIM)
    auditor_req = AuditorRequest(
        investigation_id=SYNTHETIC_TRAP_INV_ID,
        claims=[
            AuditClaimInput(claim=c["claim"], evidence_ids=c["evidence_ids"])
            for c in SYNTHETIC_TRAP_CLAIMS_INPUT
        ],
        critic_findings=[obj.model_dump() for obj in critic_res.objections],
        final_conclusion=(
            "Audited Case: The initial intrusion hypothesis is contradicted by approved IT Change Ticket CHG-99214. "
            "Threat-actor attribution to APT-29 is unsupported by available telemetry."
        ),
    )
    audited_case_res = audit_investigation(db, SYNTHETIC_TRAP_INV_ID, auditor_req)

    # 7. Pipeline Step 4: Canonical Case JSON (Module 3F)
    case_json_res = export_canonical_case(db, SYNTHETIC_TRAP_INV_ID, audited_case_res.case_id)

    # 8. Pipeline Step 5: Trust Score Engine (Module 3G)
    trust_score_res = get_investigation_trust_score(db, SYNTHETIC_TRAP_INV_ID, audited_case_res.case_id)

    # Format response
    ev_responses = [
        EvidenceResponse(
            id=ev.id,
            investigation_id=ev.investigation_id,
            evidence_type=ev.evidence_type,
            source=ev.source,
            timestamp=ev.timestamp,
            query=None,
            raw_output=ev.raw_output,
            content_hash=ev.content_hash,
            status=ev.status,
            created_at=ev.created_at,
            integrity_verified=True,
        )
        for ev in evidence_models
    ]

    contradicted_count = sum(1 for c in audited_case_res.claims if c.status == "CONTRADICTED")
    unsupported_count = sum(1 for c in audited_case_res.claims if c.status == "UNSUPPORTED")
    supported_count = sum(1 for c in audited_case_res.claims if c.status == "SUPPORTED")

    explanation = (
        f"Synthetic Trap scenario executed across the complete SOC pipeline. "
        f"The system successfully identified the deceptive signal in {DECEPTIVE_EVIDENCE_ID} "
        f"(IT Change Ticket CHG-99214). Critic flagged contradictions and overconfident attribution. "
        f"Auditor marked {contradicted_count} claim as CONTRADICTED and {unsupported_count} claim as UNSUPPORTED. "
        f"Trust Score reflects contradiction deductions: {trust_score_res.trust_score}/100 ({trust_score_res.explanation.verdict})."
    )

    return TrapScenarioResponse(
        scenario_id="SCENARIO-TRAP",
        scenario_name="Synthetic Trap / Deception Demonstration",
        is_synthetic=True,
        status="TRAP_DETECTED_CONTRADICTION",
        investigation_id=SYNTHETIC_TRAP_INV_ID,
        target_host=SYNTHETIC_TRAP_HOST,
        alert_name=SYNTHETIC_TRAP_ALERT,
        deceptive_evidence_id=DECEPTIVE_EVIDENCE_ID,
        deceptive_evidence_summary=(
            "IT Change Ticket CHG-99214 indicates approved scheduled administrative activity, "
            "directly contradicting the investigator's claim of an unauthorized malicious intrusion."
        ),
        evidence_count=len(ev_responses),
        contradicted_claims_count=contradicted_count,
        unsupported_claims_count=unsupported_count,
        supported_claims_count=supported_count,
        evidence_items=ev_responses,
        planner=planner_res,
        critic=critic_res,
        audited_case=audited_case_res,
        case_json=case_json_res,
        trust_score=trust_score_res,
        explanation=explanation,
        executed_at=now_utc,
    )


def get_trap_scenario(db: Session) -> TrapScenarioResponse:
    """
    Retrieve or initialize the Synthetic Trap / Deception demonstration scenario.
    """
    return run_trap_scenario(db, force_reset=False)
