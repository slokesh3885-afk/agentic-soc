"""
Module 3K — Centralized WebSocket Connection & Broadcast Manager
Agentic SOC — Auditable AI Security Operations Center

Manages WebSocket client connections, rooms/channels, broadcast event distribution,
and thread-safe background event dispatching for real-time SOC pipeline telemetry.
"""

import asyncio
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Set, Any, Optional
from fastapi import WebSocket

logger = logging.getLogger("agentic_soc.websockets")


class ConnectionManager:
    """
    Manages active WebSocket connections subscribed to investigation-specific channels,
    system-wide alert channels, or unified telemetry streams.
    """

    def __init__(self):
        # Mapping: channel_id -> set of active WebSockets
        # Special channels: "global", "alerts", or "investigation:<id>"
        self.active_channels: Dict[str, Set[WebSocket]] = {}
        # Global counter of total broadcast events dispatched
        self.total_broadcast_count: int = 0
        # Reference to the main asyncio loop for sync -> async dispatch
        self.main_loop: Optional[asyncio.AbstractEventLoop] = None

    def set_loop(self, loop: asyncio.AbstractEventLoop):
        """Set reference to the active event loop."""
        self.main_loop = loop

    async def connect(self, websocket: WebSocket, channel: str):
        """Accept WebSocket and subscribe it to a specific channel."""
        try:
            self.main_loop = asyncio.get_running_loop()
        except RuntimeError:
            pass
        await websocket.accept()
        if channel not in self.active_channels:
            self.active_channels[channel] = set()
        self.active_channels[channel].add(websocket)
        logger.info(f"WebSocket client connected to channel '{channel}'. Active in channel: {len(self.active_channels[channel])}")

    def disconnect(self, websocket: WebSocket, channel: str):
        """Remove WebSocket connection from a channel."""
        if channel in self.active_channels:
            self.active_channels[channel].discard(websocket)
            if not self.active_channels[channel]:
                del self.active_channels[channel]
        logger.info(f"WebSocket client disconnected from channel '{channel}'.")

    async def broadcast_to_channel(self, channel: str, event_type: str, data: Dict[str, Any], investigation_id: Optional[str] = None):
        """Broadcast a structured JSON payload to all active clients on a channel."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        message = {
            "event": event_type,
            "investigation_id": investigation_id,
            "channel": channel,
            "timestamp": now_utc,
            "data": data,
        }
        self.total_broadcast_count += 1
        serialized = json.dumps(message)

        # Broadcast to channel subscribers
        targets = list(self.active_channels.get(channel, set()))
        # Also broadcast to global telemetry channel if distinct
        if channel != "telemetry" and "telemetry" in self.active_channels:
            targets.extend(list(self.active_channels.get("telemetry", set())))

        dead_connections = []
        for ws in targets:
            try:
                await ws.send_text(serialized)
            except Exception as e:
                logger.warning(f"Failed to send to client in channel '{channel}': {e}")
                dead_connections.append(ws)

        # Cleanup any broken connections
        for dead_ws in dead_connections:
            self.disconnect(dead_ws, channel)
            if "telemetry" in self.active_channels:
                self.disconnect(dead_ws, "telemetry")

    async def broadcast_investigation_event(
        self,
        investigation_id: str,
        event_type: str,
        data: Dict[str, Any],
    ):
        """Convenience method to broadcast to investigation channel."""
        channel = f"investigation:{investigation_id}"
        await self.broadcast_to_channel(channel, event_type, data, investigation_id=investigation_id)

    async def broadcast_alert_event(self, event_type: str, data: Dict[str, Any]):
        """Broadcast an alert event to the alerts channel."""
        await self.broadcast_to_channel("alerts", event_type, data)

    def dispatch_sync(
        self,
        channel: str,
        event_type: str,
        data: Dict[str, Any],
        investigation_id: Optional[str] = None,
    ):
        """
        Thread-safe synchronous dispatch method.
        Can be called from standard synchronous FastAPI routes/services.
        Schedules the async coroutine on the running event loop without blocking.
        """
        try:
            loop = self.main_loop
            if loop is None or not loop.is_running():
                try:
                    loop = asyncio.get_running_loop()
                    self.main_loop = loop
                except RuntimeError:
                    return

            if loop and loop.is_running():
                try:
                    current_loop = asyncio.get_running_loop()
                except RuntimeError:
                    current_loop = None

                if current_loop == loop:
                    asyncio.create_task(
                        self.broadcast_to_channel(channel, event_type, data, investigation_id=investigation_id)
                    )
                else:
                    asyncio.run_coroutine_threadsafe(
                        self.broadcast_to_channel(channel, event_type, data, investigation_id=investigation_id),
                        loop,
                    )
        except Exception as e:
            logger.warning(f"Broadcast dispatch exception: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Return diagnostic metrics about active connections and broadcast history."""
        channels_info = {ch: len(conns) for ch, conns in self.active_channels.items()}
        total_connections = sum(channels_info.values())
        return {
            "total_active_connections": total_connections,
            "channels": channels_info,
            "total_broadcast_count": self.total_broadcast_count,
            "has_loop": self.main_loop is not None,
            "loop_running": self.main_loop.is_running() if self.main_loop else False,
            "status": "online",
        }


# Global singleton instance
ws_manager = ConnectionManager()
