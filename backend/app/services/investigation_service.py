import re
import json
from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from sqlalchemy import desc

from app.models.investigation import InvestigationModel
from app.schemas.investigation import InvestigationCreate


def generate_next_investigation_id(db: Session) -> str:
    """Generate sequential investigation ID (e.g. INV-001, INV-007) without relying on frontend."""
    records = db.query(InvestigationModel.id).all()
    max_num = 0
    pattern = re.compile(r"^INV-(\d+)$")

    for (rec_id,) in records:
        match = pattern.match(rec_id)
        if match:
            num = int(match.group(1))
            if num > max_num:
                max_num = num

    return f"INV-{max_num + 1:03d}"


def get_all_investigations(db: Session) -> List[InvestigationModel]:
    """Retrieve all investigations ordered by created_at / ID descending."""
    return db.query(InvestigationModel).order_by(desc(InvestigationModel.id)).all()


def get_investigation_by_id(db: Session, investigation_id: str) -> Optional[InvestigationModel]:
    """Retrieve a single investigation by ID."""
    return db.query(InvestigationModel).filter(InvestigationModel.id == investigation_id).first()


def create_investigation(db: Session, data: InvestigationCreate) -> InvestigationModel:
    """Create and persist a new investigation with backend-generated ID."""
    new_id = generate_next_investigation_id(db)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Initial corroboration seeds for a new investigation
    initial_corroboration = [
        {"source": "Initial SIEM Alert Trigger", "score": 95, "corroborated": True},
        {"source": "Host Process Lineage", "score": 89, "corroborated": True},
    ]

    model = InvestigationModel(
        id=new_id,
        alert_name=data.alert_name,
        target_host=data.target_host,
        severity=data.severity,
        event_timestamp=data.event_timestamp or now_utc,
        description=data.description or "",
        status=data.status or "Investigating",
        evidence_count=data.evidence_count if data.evidence_count is not None else 3,
        trust_score=data.trust_score if data.trust_score is not None else 91,
        created_at=now_utc,
        assigned_agent="Host Triage Agent",
        mitre_technique="T1059 (Execution: Command and Scripting Interpreter)",
        evidence_corroboration=json.dumps(initial_corroboration),
    )

    db.add(model)
    db.commit()
    db.refresh(model)

    # Module 3K: Broadcast ALERT_CREATED telemetry event to alerts channel
    try:
        from app.services.websocket_manager import ws_manager
        ws_manager.dispatch_sync(
            channel="alerts",
            event_type="ALERT_CREATED",
            data={
                "investigation_id": model.id,
                "alert_name": model.alert_name,
                "target_host": model.target_host,
                "severity": model.severity,
                "status": model.status,
                "created_at": model.created_at,
            },
            investigation_id=model.id,
        )
    except Exception:
        pass

    return model


def seed_initial_investigations(db: Session) -> None:
    """Seed database with realistic initial investigations if empty."""
    existing_count = db.query(InvestigationModel).count()
    if existing_count > 0:
        return

    seed_data = [
        {
            "id": "INV-001",
            "alert_name": "Suspicious PowerShell Execution",
            "target_host": "DC-PROD-01.corp.internal",
            "severity": "Critical",
            "status": "Investigating",
            "trust_score": 94,
            "evidence_count": 14,
            "event_timestamp": "2026-09-27 13:25:12 UTC",
            "created_at": "2026-09-27 13:28:44 UTC",
            "description": "Encoded base64 PowerShell invocation with memory injection flags detected originating from scheduled task SYSTEM_UPDATE_TASK.",
            "assigned_agent": "Host Triage Agent",
            "mitre_technique": "T1059.001 (Command and Scripting Interpreter: PowerShell)",
            "evidence_corroboration": json.dumps([
                {"source": "Windows Event Logs (Sysmon EID 1)", "score": 98, "corroborated": True},
                {"source": "Endpoint EDR Process Tree", "score": 95, "corroborated": True},
                {"source": "Network Outbound Socket", "score": 89, "corroborated": True},
            ]),
        },
        {
            "id": "INV-002",
            "alert_name": "Unusual DNS Traffic",
            "target_host": "GW-EDGE-02.dmz.internal",
            "severity": "High",
            "status": "Awaiting Review",
            "trust_score": 88,
            "evidence_count": 9,
            "event_timestamp": "2026-09-27 13:12:08 UTC",
            "created_at": "2026-09-27 13:14:22 UTC",
            "description": "High volume of high-entropy TXT records queried to dynamic external NS domain (ns1.cobalt-cdn-updater.xyz), indicating potential DNS tunneling.",
            "assigned_agent": "Network Forensics Agent",
            "mitre_technique": "T1071.004 (Application Layer Protocol: DNS)",
            "evidence_corroboration": json.dumps([
                {"source": "Zeek DNS Logs", "score": 96, "corroborated": True},
                {"source": "Firewall NetFlow Session Duration", "score": 91, "corroborated": True},
                {"source": "Threat Intel Domain Reputation", "score": 77, "corroborated": True},
            ]),
        },
        {
            "id": "INV-003",
            "alert_name": "Suspicious File Hash",
            "target_host": "WKS-FIN-88.internal",
            "severity": "High",
            "status": "Completed",
            "trust_score": 96,
            "evidence_count": 18,
            "event_timestamp": "2026-09-27 12:45:30 UTC",
            "created_at": "2026-09-27 12:48:10 UTC",
            "description": "SHA-256 match for known Mimikatz credential dumper binary placed in C:\\Users\\Public\\Downloads\\invoice_sep.exe.",
            "assigned_agent": "Malware Analysis Agent",
            "mitre_technique": "T1003.001 (OS Credential Dumping: LSASS Memory)",
            "evidence_corroboration": json.dumps([
                {"source": "EDR Static Hash Reputation (VT 63/72)", "score": 99, "corroborated": True},
                {"source": "Kernel Object Access to LSASS", "score": 97, "corroborated": True},
                {"source": "Isolated Quarantine Snapshot", "score": 92, "corroborated": True},
            ]),
        },
        {
            "id": "INV-004",
            "alert_name": "Lateral SMB Session Spacing",
            "target_host": "FS-ARCHIVE-04.corp.internal",
            "severity": "Medium",
            "status": "Inconclusive",
            "trust_score": 58,
            "evidence_count": 5,
            "event_timestamp": "2026-09-27 11:58:19 UTC",
            "created_at": "2026-09-27 12:02:05 UTC",
            "description": "Repeated anonymous pipe access over Port 445 without corresponding Active Directory Kerberos ticket generation.",
            "assigned_agent": "Identity & Auth Agent",
            "mitre_technique": "T1021.002 (Remote Services: SMB/Windows Admin Shares)",
            "evidence_corroboration": json.dumps([
                {"source": "SMB Server Event 3000", "score": 62, "corroborated": True},
                {"source": "Kerberos KDC Audit Trail", "score": 55, "corroborated": False},
                {"source": "Host Memory Volatility Analysis", "score": 57, "corroborated": False},
            ]),
        },
        {
            "id": "INV-005",
            "alert_name": "Suspicious Cloud IAM Privilege Escalation",
            "target_host": "AWS-IAM-ROLE/DevSecOps-Deployer",
            "severity": "Critical",
            "status": "Investigating",
            "trust_score": 92,
            "evidence_count": 11,
            "event_timestamp": "2026-09-27 13:20:44 UTC",
            "created_at": "2026-09-27 13:22:15 UTC",
            "description": "AttachRolePolicy API invoked with AdministratorAccess policy from an unmanaged residential IP block in Eastern Europe.",
            "assigned_agent": "Cloud Infrastructure Agent",
            "mitre_technique": "T1098 (Account Manipulation)",
            "evidence_corroboration": json.dumps([
                {"source": "CloudTrail Event Record", "score": 98, "corroborated": True},
                {"source": "GuardDuty Impossible Travel Finding", "score": 94, "corroborated": True},
                {"source": "VPC Gateway Transit Log", "score": 84, "corroborated": True},
            ]),
        },
        {
            "id": "INV-006",
            "alert_name": "Kernel Module Driver Injection",
            "target_host": "SRV-KUBE-NODE-03.dmz.internal",
            "severity": "High",
            "status": "Completed",
            "trust_score": 97,
            "evidence_count": 22,
            "event_timestamp": "2026-09-27 09:30:00 UTC",
            "created_at": "2026-09-27 09:35:12 UTC",
            "description": "Unknown eBPF tracepoint hook attached to sys_enter_execve with elevated ring 0 rootkit capability.",
            "assigned_agent": "Linux Runtime Defense Agent",
            "mitre_technique": "T1547.006 (Boot or Logon Autostart Execution: Kernel Modules and Extensions)",
            "evidence_corroboration": json.dumps([
                {"source": "BPFtool Kernel Map Verification", "score": 99, "corroborated": True},
                {"source": "Falco Daemon Detection Signature", "score": 98, "corroborated": True},
                {"source": "Memory Integrity Hash Verification", "score": 94, "corroborated": True},
            ]),
        },
    ]

    for item in seed_data:
        db.add(InvestigationModel(**item))

    db.commit()
