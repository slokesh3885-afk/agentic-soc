import { useState, useEffect, useRef, useCallback } from 'react';
import { WebSocketConnectionStatus, WebSocketEventMessage, WebSocketStatusResponse } from '../types/soc';

export function useAlertsSocket(onAlert?: (event: WebSocketEventMessage) => void) {
  const [status, setStatus] = useState<WebSocketConnectionStatus>('disconnected');
  const [alerts, setAlerts] = useState<WebSocketEventMessage[]>([]);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const pingIntervalRef = useRef<number | null>(null);

  const connect = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.hostname || '127.0.0.1';
    const wsUrl = `${protocol}//${host}:8000/ws/alerts`;

    setStatus('connecting');

    try {
      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        setStatus('connected');
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ action: 'ping' }));
          }
        }, 25000);
      };

      ws.onmessage = (event) => {
        try {
          const parsed: WebSocketEventMessage = JSON.parse(event.data);
          if (parsed.event === 'pong') return;

          setAlerts((prev) => [parsed, ...prev].slice(0, 50));
          if (onAlert) {
            onAlert(parsed);
          }
        } catch {
          // Ignore parse errors
        }
      };

      ws.onerror = () => {
        setStatus('error');
      };

      ws.onclose = () => {
        setStatus('disconnected');
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        reconnectTimeoutRef.current = window.setTimeout(() => {
          connect();
        }, 4000);
      };
    } catch {
      setStatus('error');
    }
  }, [onAlert]);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) clearTimeout(reconnectTimeoutRef.current);
      if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
      if (socketRef.current) {
        socketRef.current.close();
      }
    };
  }, [connect]);

  return {
    status,
    alerts,
    isConnected: status === 'connected',
  };
}

export async function fetchWebSocketDiagnosticStatus(): Promise<WebSocketStatusResponse> {
  const host = window.location.hostname || '127.0.0.1';
  const res = await fetch(`http://${host}:8000/api/ws/status`);
  if (!res.ok) {
    throw new Error(`Failed to fetch WS diagnostics: ${res.status}`);
  }
  return res.json();
}
