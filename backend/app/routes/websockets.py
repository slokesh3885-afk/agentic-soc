"""
Module 3K — WebSockets Routes
Agentic SOC — Auditable AI Security Operations Center

Exposes real-time streaming WebSocket endpoints for:
- /ws/investigations/{investigation_id} (Per-investigation telemetry & agent activity stream)
- /ws/alerts (System-wide alert stream)
- /ws/telemetry (Global unified telemetry stream)
- /api/ws/status (Diagnostic endpoint reporting active connections & broadcast count)
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, status
from pydantic import BaseModel

from app.services.websocket_manager import ws_manager

logger = logging.getLogger("agentic_soc.websockets")
router = APIRouter(tags=["websockets"])


class BroadcastTestPayload(BaseModel):
    channel: str
    event: str
    data: Dict[str, Any] = {}
    investigation_id: Optional[str] = None


@router.websocket("/ws/investigations/{investigation_id}")
async def websocket_investigation_endpoint(websocket: WebSocket, investigation_id: str):
    """
    Real-time streaming WebSocket for an individual investigation.
    Streams tool executions, cryptographic evidence hashes, planner updates,
    critic reviews, audit seals, trust scores, and human approval events.
    """
    channel = f"investigation:{investigation_id}"
    await ws_manager.connect(websocket, channel)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Send initial welcome confirmation
    try:
        await websocket.send_text(
            json.dumps({
                "event": "CONNECTED",
                "channel": channel,
                "investigation_id": investigation_id,
                "timestamp": now_utc,
                "message": f"Subscribed to real-time telemetry for investigation {investigation_id}.",
            })
        )

        while True:
            raw_text = await websocket.receive_text()
            try:
                msg = json.loads(raw_text)
            except Exception:
                msg = {"action": raw_text}

            action = msg.get("action", "").lower() if isinstance(msg, dict) else str(raw_text).lower()

            if action == "ping":
                pong_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                await websocket.send_text(
                    json.dumps({
                        "event": "pong",
                        "channel": channel,
                        "investigation_id": investigation_id,
                        "timestamp": pong_utc,
                    })
                )
            elif action == "echo":
                await websocket.send_text(
                    json.dumps({
                        "event": "echo",
                        "data": msg.get("data", {}),
                    })
                )
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, channel)
    except Exception as e:
        logger.warning(f"WebSocket error in {channel}: {e}")
        ws_manager.disconnect(websocket, channel)


@router.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """
    Real-time streaming WebSocket for system-wide security alert broadcasts.
    """
    channel = "alerts"
    await ws_manager.connect(websocket, channel)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        await websocket.send_text(
            json.dumps({
                "event": "CONNECTED",
                "channel": channel,
                "timestamp": now_utc,
                "message": "Subscribed to system-wide security alerts stream.",
            })
        )

        while True:
            raw_text = await websocket.receive_text()
            try:
                msg = json.loads(raw_text)
            except Exception:
                msg = {"action": raw_text}

            action = msg.get("action", "").lower() if isinstance(msg, dict) else str(raw_text).lower()
            if action == "ping":
                pong_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                await websocket.send_text(
                    json.dumps({
                        "event": "pong",
                        "channel": channel,
                        "timestamp": pong_utc,
                    })
                )
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, channel)
    except Exception as e:
        logger.warning(f"WebSocket error in {channel}: {e}")
        ws_manager.disconnect(websocket, channel)


@router.websocket("/ws/telemetry")
async def websocket_global_telemetry_endpoint(websocket: WebSocket):
    """
    Global unified real-time telemetry stream across all investigations and pipeline events.
    """
    channel = "telemetry"
    await ws_manager.connect(websocket, channel)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    try:
        await websocket.send_text(
            json.dumps({
                "event": "CONNECTED",
                "channel": channel,
                "timestamp": now_utc,
                "message": "Subscribed to global unified telemetry pipeline.",
            })
        )

        while True:
            raw_text = await websocket.receive_text()
            try:
                msg = json.loads(raw_text)
            except Exception:
                msg = {"action": raw_text}

            action = msg.get("action", "").lower() if isinstance(msg, dict) else str(raw_text).lower()
            if action == "ping":
                pong_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                await websocket.send_text(
                    json.dumps({
                        "event": "pong",
                        "channel": channel,
                        "timestamp": pong_utc,
                    })
                )
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket, channel)
    except Exception as e:
        logger.warning(f"WebSocket error in telemetry: {e}")
        ws_manager.disconnect(websocket, channel)


@router.get("/ws/status", summary="Get WebSocket manager diagnostic metrics")
@router.get("/api/ws/status", summary="Get WebSocket manager diagnostic metrics (API alias)")
def get_websocket_status():
    """
    Diagnostic endpoint returning active connection counts, monitored channels,
    and total broadcast event counts.
    """
    return ws_manager.get_status()


@router.post("/api/ws/broadcast", summary="Manually trigger test broadcast event")
async def trigger_test_broadcast(payload: BroadcastTestPayload):
    """
    Trigger a broadcast event to a specific channel (used for pipeline testing).
    """
    await ws_manager.broadcast_to_channel(
        channel=payload.channel,
        event_type=payload.event,
        data=payload.data,
        investigation_id=payload.investigation_id,
    )
    return {
        "status": "dispatched",
        "channel": payload.channel,
        "event": payload.event,
        "total_dispatched": ws_manager.total_broadcast_count,
    }
