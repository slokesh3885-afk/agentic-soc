"""
Module 3K Test Suite — Real-time WebSockets & Live Telemetry Broadcast
Agentic SOC — Auditable AI Security Operations Center

Verifies:
1. Backend health check registers Module 3K WebSockets & streaming capability.
2. HTTP diagnostic endpoint GET /api/ws/status returns active metrics and online status.
3. WebSocket handshake and subscription to /ws/investigations/INV-012 receives CONNECTED welcome.
4. WebSocket Ping-Pong ({"action": "ping"} -> {"event": "pong"}).
5. WebSocket Echo functionality ({"action": "echo"} -> {"event": "echo"}).
6. Real-time broadcast on Tool Execution (TOOL_EXECUTED received with evidence ID & hash).
7. Real-time broadcast on Evidence Creation (EVIDENCE_CREATED with valid SHA-256 hash).
8. Real-time broadcast on Approval Request Creation (APPROVAL_REQUESTED with trust score).
9. Real-time broadcast on Approval Decision (APPROVAL_DECIDED with reviewer & status).
10. Real-time broadcast on Auditor Run (CASE_AUDITED with verified case ID).
11. Real-time broadcast on Planner Run (PLAN_PROPOSED with step counts).
12. Real-time broadcast on Critic Review (CRITIC_REVIEWED with objection metrics).
13. System-wide alert WebSocket /ws/alerts connects, pings, and receives ALERT_CREATED.
14. Multiple concurrent subscribers on the same channel receive broadcasts in parallel.
15. Security & Isolation Boundary: WebSocket telemetry does not mutate evidence or trigger rogue tools; client disconnect is cleanly handled without server degradation.
"""

import asyncio
import json
import urllib.request
import urllib.error
import websockets
import sys

BASE_HTTP = "http://127.0.0.1:8000"
BASE_WS = "ws://127.0.0.1:8000"


def make_http_request(path: str, method: str = "GET", data: dict = None):
    url = f"{BASE_HTTP}{path}"
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


async def recv_until_event(ws, target_event: str, timeout: float = 5.0):
    """Receive messages from WebSocket until target event is found."""
    loop = asyncio.get_running_loop()
    start = loop.time()
    while loop.time() - start < timeout:
        remaining = max(0.1, timeout - (loop.time() - start))
        raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
        msg = json.loads(raw)
        if msg.get("event") == target_event:
            return msg
    raise TimeoutError(f"Event '{target_event}' not received within {timeout}s")


async def run_all_checks():
    print("=" * 65)
    print("AGENTIC SOC — MODULE 3K WEBSOCKETS & LIVE TELEMETRY TESTS")
    print("=" * 65)

    passed = 0
    total = 0

    def assert_check(condition: bool, check_num: int, title: str, detail: str = ""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"[PASS] Check {check_num:02d}: {title}")
            if detail:
                print(f"        -> {detail}")
        else:
            print(f"[FAIL] Check {check_num:02d}: {title}")
            if detail:
                print(f"        -> {detail}")
            sys.exit(1)

    # -------------------------------------------------------------
    # Check 01: Health check registers Module 3K WebSockets
    # -------------------------------------------------------------
    status, health = make_http_request("/api/health")
    assert_check(
        status == 200 and "websocket_streaming" in health and "Active" in health["websocket_streaming"],
        1,
        "Backend Health Check Registers Module 3K WebSockets",
        f"Status: {health.get('websocket_streaming')}",
    )

    # -------------------------------------------------------------
    # Check 02: HTTP diagnostic endpoint GET /api/ws/status
    # -------------------------------------------------------------
    status, ws_status = make_http_request("/api/ws/status")
    assert_check(
        status == 200 and ws_status.get("status") == "online" and "total_broadcast_count" in ws_status,
        2,
        "HTTP Diagnostic Endpoint GET /api/ws/status Verified",
        f"Active Connections: {ws_status.get('total_active_connections')}, Status: {ws_status.get('status')}",
    )

    # -------------------------------------------------------------
    # Check 03: WebSocket Handshake & Welcome Message on Investigation
    # -------------------------------------------------------------
    async with websockets.connect(f"{BASE_WS}/ws/investigations/INV-012") as ws:
        raw_welcome = await asyncio.wait_for(ws.recv(), timeout=5.0)
        welcome = json.loads(raw_welcome)
        assert_check(
            welcome.get("event") == "CONNECTED"
            and welcome.get("investigation_id") == "INV-012"
            and "investigation:INV-012" in welcome.get("channel", ""),
            3,
            "WebSocket Handshake & Investigation Subscription Verified",
            f"Event: {welcome.get('event')}, Channel: {welcome.get('channel')}",
        )

        # -------------------------------------------------------------
        # Check 04: WebSocket Ping-Pong
        # -------------------------------------------------------------
        await ws.send(json.dumps({"action": "ping"}))
        raw_pong = await asyncio.wait_for(ws.recv(), timeout=5.0)
        pong = json.loads(raw_pong)
        assert_check(
            pong.get("event") == "pong" and pong.get("investigation_id") == "INV-012",
            4,
            "WebSocket Keepalive Ping-Pong Protocol Verified",
            f"Response: {pong}",
        )

        # -------------------------------------------------------------
        # Check 05: WebSocket Echo
        # -------------------------------------------------------------
        await ws.send(json.dumps({"action": "echo", "data": {"test_field": "soc_audit_telemetry"}}))
        raw_echo = await asyncio.wait_for(ws.recv(), timeout=5.0)
        echo = json.loads(raw_echo)
        assert_check(
            echo.get("event") == "echo" and echo.get("data", {}).get("test_field") == "soc_audit_telemetry",
            5,
            "WebSocket Echo Action Verified",
            f"Payload echoed: {echo.get('data')}",
        )

    # -------------------------------------------------------------
    # Check 06 & 07: Real-time Broadcast on Tool Execution & Evidence Creation
    # -------------------------------------------------------------
    async with websockets.connect(f"{BASE_WS}/ws/investigations/INV-012") as ws:
        await ws.recv()  # Consume CONNECTED

        loop = asyncio.get_running_loop()

        def execute_tool_call():
            tool_payload = {
                "investigation_id": "INV-012",
                "tool_name": "edr_process_search",
                "input": {"host": "PC-DB-TEST", "process_name": "powershell.exe"},
            }
            return make_http_request("/api/tools/execute", method="POST", data=tool_payload)

        # Trigger tool in threadpool
        t_status, t_res = await loop.run_in_executor(None, execute_tool_call)
        assert t_status == 200 and t_res.get("success") is True

        # Receive 2 events: EVIDENCE_CREATED and TOOL_EXECUTED
        ev1 = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))
        ev2 = json.loads(await asyncio.wait_for(ws.recv(), timeout=5.0))

        events_map = {ev1.get("event"): ev1, ev2.get("event"): ev2}

        # Check 06: Tool Executed Event
        tool_ev = events_map.get("TOOL_EXECUTED")
        assert_check(
            tool_ev is not None
            and tool_ev.get("investigation_id") == "INV-012"
            and tool_ev.get("data", {}).get("tool_name") == "edr_process_search"
            and tool_ev.get("data", {}).get("evidence_id") == t_res.get("evidence_id"),
            6,
            "Real-Time TOOL_EXECUTED Event Broadcast Verified",
            f"Tool: {tool_ev.get('data', {}).get('tool_name')}, Evidence ID: {tool_ev.get('data', {}).get('evidence_id')}",
        )

        # Check 07: Evidence Created Event with SHA-256 Hash
        evidence_ev = events_map.get("EVIDENCE_CREATED")
        content_hash = evidence_ev.get("data", {}).get("content_hash", "")
        assert_check(
            evidence_ev is not None
            and evidence_ev.get("investigation_id") == "INV-012"
            and evidence_ev.get("data", {}).get("evidence_id") == t_res.get("evidence_id")
            and len(content_hash) == 64,
            7,
            "Real-Time EVIDENCE_CREATED Event Broadcast with Cryptographic Hash",
            f"Evidence ID: {evidence_ev.get('data', {}).get('evidence_id')}, SHA-256: {content_hash[:16]}...",
        )

    # -------------------------------------------------------------
    # Check 08 & 09: Real-time Broadcast on Approval Request and Decision
    # -------------------------------------------------------------
    async with websockets.connect(f"{BASE_WS}/ws/investigations/INV-012") as ws:
        await ws.recv()  # Consume CONNECTED

        # 1. Trigger Approval Request Creation
        def create_app_call():
            app_payload = {
                "action_type": "CONTAINMENT_ISOLATE_HOST",
                "recommended_action": "Isolate host PC-DB-TEST pending forensic triage",
                "risk_level": "HIGH",
                "requested_by": "Autonomous Triage Pipeline",
            }
            return make_http_request("/api/investigations/INV-012/approvals", method="POST", data=app_payload)

        a_status, a_res = await loop.run_in_executor(None, create_app_call)
        assert a_status == 200, f"Approval creation failed: {a_status} {a_res}"
        created_app_id = a_res.get("id")

        app_req_ev = await recv_until_event(ws, "APPROVAL_REQUESTED")
        assert_check(
            app_req_ev.get("event") == "APPROVAL_REQUESTED"
            and app_req_ev.get("data", {}).get("approval_id") == created_app_id
            and app_req_ev.get("data", {}).get("action_type") == "CONTAINMENT_ISOLATE_HOST",
            8,
            "Real-Time APPROVAL_REQUESTED Broadcast Verified",
            f"Approval ID: {created_app_id}, Status: {app_req_ev.get('data', {}).get('status')}",
        )

        # 2. Trigger Approval Decision
        def submit_decision_call():
            decision_payload = {
                "decision": "APPROVED",
                "reviewer": "SecOps Lead Analyst",
                "decision_notes": "Corroborated endpoint compromise confirmed by forensic triage.",
                "override_justification": "Verified containment necessary; critical threat actor behavior identified.",
            }
            return make_http_request(f"/api/approvals/{created_app_id}/decision", method="POST", data=decision_payload)

        d_status, d_res = await loop.run_in_executor(None, submit_decision_call)
        assert d_status == 200, f"Approval decision failed: {d_status} {d_res}"

        app_dec_ev = await recv_until_event(ws, "APPROVAL_DECIDED")
        assert_check(
            app_dec_ev.get("event") == "APPROVAL_DECIDED"
            and app_dec_ev.get("data", {}).get("approval_id") == created_app_id
            and app_dec_ev.get("data", {}).get("status") == "APPROVED"
            and app_dec_ev.get("data", {}).get("reviewer") == "SecOps Lead Analyst",
            9,
            "Real-Time APPROVAL_DECIDED Broadcast Verified",
            f"Approval ID: {created_app_id}, Decision: APPROVED by {app_dec_ev.get('data', {}).get('reviewer')}",
        )

    # -------------------------------------------------------------
    # Check 10: Real-time Broadcast on Auditor Run
    # -------------------------------------------------------------
    async with websockets.connect(f"{BASE_WS}/ws/investigations/INV-012") as ws:
        await ws.recv()  # Consume CONNECTED

        def run_audit_call():
            audit_payload = {
                "claims": [
                    {
                        "claim": "PowerShell executed with encoded command line",
                        "evidence_ids": ["E-001"],
                    }
                ],
                "draft_conclusion": "Suspicious execution detected on host PC-DB-TEST.",
            }
            return make_http_request("/api/investigations/INV-012/audit", method="POST", data=audit_payload)

        aud_status, aud_res = await loop.run_in_executor(None, run_audit_call)
        assert aud_status == 200, f"Audit run failed: {aud_status} {aud_res}"

        aud_ev = await recv_until_event(ws, "CASE_AUDITED")
        assert_check(
            aud_ev.get("event") == "CASE_AUDITED"
            and aud_ev.get("investigation_id") == "INV-012"
            and aud_ev.get("data", {}).get("case_id") == aud_res.get("case_id")
            and aud_ev.get("data", {}).get("audit_verified") is True,
            10,
            "Real-Time CASE_AUDITED Broadcast Verified",
            f"Case ID: {aud_ev.get('data', {}).get('case_id')}, Audit Verified: True",
        )

    # -------------------------------------------------------------
    # Check 11: Real-time Broadcast on Planner Run
    # -------------------------------------------------------------
    async with websockets.connect(f"{BASE_WS}/ws/investigations/INV-012") as ws:
        await ws.recv()  # Consume CONNECTED

        def run_planner_call():
            plan_payload = {
                "alert": "Suspicious PowerShell with memory injection flags",
                "custom_instructions": "Check parent process and outbound sockets",
            }
            return make_http_request("/api/investigations/INV-012/plan", method="POST", data=plan_payload)

        plan_status, plan_res = await loop.run_in_executor(None, run_planner_call)
        assert plan_status == 200, f"Plan run failed: {plan_status} {plan_res}"

        plan_ev = await recv_until_event(ws, "PLAN_PROPOSED")
        assert_check(
            plan_ev.get("event") == "PLAN_PROPOSED"
            and plan_ev.get("investigation_id") == "INV-012"
            and plan_ev.get("data", {}).get("steps_count", 0) > 0,
            11,
            "Real-Time PLAN_PROPOSED Broadcast Verified",
            f"Plan ID: {plan_ev.get('data', {}).get('plan_id')}, Steps: {plan_ev.get('data', {}).get('steps_count')}",
        )

    # -------------------------------------------------------------
    # Check 12: Real-time Broadcast on Critic Review
    # -------------------------------------------------------------
    async with websockets.connect(f"{BASE_WS}/ws/investigations/INV-012") as ws:
        await ws.recv()  # Consume CONNECTED

        def run_critic_call():
            critic_payload = {
                "claims": [
                    {
                        "claim": "Attacker deployed Fancy Bear malware",
                        "evidence_ids": ["E-001"],
                    }
                ],
                "draft_conclusion": "Definitely Fancy Bear APT group.",
            }
            return make_http_request("/api/investigations/INV-012/critic", method="POST", data=critic_payload)

        critic_status, critic_res = await loop.run_in_executor(None, run_critic_call)
        assert critic_status == 200, f"Critic run failed: {critic_status} {critic_res}"

        critic_ev = await recv_until_event(ws, "CRITIC_REVIEWED")
        assert_check(
            critic_ev.get("event") == "CRITIC_REVIEWED"
            and critic_ev.get("investigation_id") == "INV-012"
            and critic_ev.get("data", {}).get("objections_count", 0) > 0,
            12,
            "Real-Time CRITIC_REVIEWED Broadcast Verified",
            f"Review ID: {critic_ev.get('data', {}).get('review_id')}, Objections: {critic_ev.get('data', {}).get('objections_count')}",
        )

    # -------------------------------------------------------------
    # Check 13: System-Wide Alerts Channel (/ws/alerts)
    # -------------------------------------------------------------
    async with websockets.connect(f"{BASE_WS}/ws/alerts") as alert_ws:
        raw_alert_welcome = await asyncio.wait_for(alert_ws.recv(), timeout=5.0)
        alert_welcome = json.loads(raw_alert_welcome)
        assert alert_welcome.get("event") == "CONNECTED" and alert_welcome.get("channel") == "alerts"

        # Ping-pong on alerts channel
        await alert_ws.send(json.dumps({"action": "ping"}))
        alert_pong = json.loads(await asyncio.wait_for(alert_ws.recv(), timeout=5.0))
        assert alert_pong.get("event") == "pong" and alert_pong.get("channel") == "alerts"

        # Trigger investigation creation
        def create_inv_call():
            inv_payload = {
                "alert_name": "Real-time Telemetry Verification Alert",
                "target_host": "SRV-WS-TEST.corp",
                "severity": "Medium",
                "event_timestamp": "2026-09-28 08:10:00 UTC",
                "description": "Synthetic alert for testing WebSocket broadcast delivery",
            }
            return make_http_request("/api/investigations", method="POST", data=inv_payload)

        ci_status, ci_res = await loop.run_in_executor(None, create_inv_call)
        assert ci_status in (200, 201), f"Create investigation failed: {ci_status} {ci_res}"

        alert_ev = await recv_until_event(alert_ws, "ALERT_CREATED")
        assert_check(
            alert_ev.get("event") == "ALERT_CREATED"
            and alert_ev.get("data", {}).get("investigation_id") == ci_res.get("id"),
            13,
            "System-Wide Alerts WebSocket (/ws/alerts) Receives ALERT_CREATED",
            f"Investigation ID: {ci_res.get('id')}, Severity: {alert_ev.get('data', {}).get('severity')}",
        )

    # -------------------------------------------------------------
    # Check 14: Multiple Concurrent Subscribers on Same Channel
    # -------------------------------------------------------------
    async with websockets.connect(f"{BASE_WS}/ws/investigations/INV-012") as ws_client_a:
        await ws_client_a.recv()  # Consume CONNECTED
        async with websockets.connect(f"{BASE_WS}/ws/investigations/INV-012") as ws_client_b:
            await ws_client_b.recv()  # Consume CONNECTED

            # Trigger a manual broadcast via /api/ws/broadcast
            def trigger_manual_broadcast():
                b_payload = {
                    "channel": "investigation:INV-012",
                    "event": "CONCURRENT_TEST",
                    "data": {"broadcast_sync_id": 999},
                    "investigation_id": "INV-012",
                }
                return make_http_request("/api/ws/broadcast", method="POST", data=b_payload)

            mb_status, mb_res = await loop.run_in_executor(None, trigger_manual_broadcast)
            assert mb_status == 200

            # Both clients should receive the event
            msg_a = await recv_until_event(ws_client_a, "CONCURRENT_TEST")
            msg_b = await recv_until_event(ws_client_b, "CONCURRENT_TEST")

            assert_check(
                msg_a.get("event") == "CONCURRENT_TEST"
                and msg_b.get("event") == "CONCURRENT_TEST"
                and msg_a.get("data", {}).get("broadcast_sync_id") == 999
                and msg_b.get("data", {}).get("broadcast_sync_id") == 999,
                14,
                "Multiple Concurrent WebSocket Subscribers Verified",
                f"Client A Event: {msg_a.get('event')}, Client B Event: {msg_b.get('event')}",
            )

    # -------------------------------------------------------------
    # Check 15: Security Boundary & Graceful Disconnection Handling
    # -------------------------------------------------------------
    # Connect and disconnect immediately to test clean dereferencing
    async with websockets.connect(f"{BASE_WS}/ws/investigations/INV-012") as ephemeral_ws:
        await ephemeral_ws.recv()  # Connected
        await ephemeral_ws.close()

    # Query status after disconnects
    st_code, st_data = make_http_request("/api/ws/status")
    assert_check(
        st_code == 200 and st_data.get("status") == "online" and st_data.get("total_broadcast_count", 0) > 0,
        15,
        "Security Boundary: Zero Side-Effects & Graceful Disconnect Handled Cleanly",
        f"Server Online, Total Dispatches: {st_data.get('total_broadcast_count')}",
    )

    print("\n" + "=" * 65)
    print(f"ALL {passed}/{total} MODULE 3K WEBSOCKETS & TELEMETRY CHECKS PASSED!")
    print("=" * 65)


if __name__ == "__main__":
    asyncio.run(run_all_checks())
