import { useState, useEffect, useRef, useCallback } from 'react';
import { WebSocketConnectionStatus, WebSocketEventMessage } from '../types/soc';

export interface UseInvestigationSocketOptions {
  investigationId: string | null;
  onEvent?: (event: WebSocketEventMessage) => void;
  autoReconnect?: boolean;
}

export function useInvestigationSocket({
  investigationId,
  onEvent,
  autoReconnect = true,
}: UseInvestigationSocketOptions) {
  const [status, setStatus] = useState<WebSocketConnectionStatus>('disconnected');
  const [events, setEvents] = useState<WebSocketEventMessage[]>([]);
  const [lastEvent, setLastEvent] = useState<WebSocketEventMessage | null>(null);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);
  const pingIntervalRef = useRef<number | null>(null);

  const connect = useCallback(() => {
    if (!investigationId) return;

    // Build WebSocket URL
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // If backend is on 8000 in dev
    const host = window.location.hostname || '127.0.0.1';
    const wsUrl = `${protocol}//${host}:8000/ws/investigations/${investigationId}`;

    setStatus('connecting');

    try {
      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        setStatus('connected');
        // Start keepalive ping every 25 seconds
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
          if (parsed.event === 'pong') return; // Keepalive reply

          setLastEvent(parsed);
          setEvents((prev) => [parsed, ...prev].slice(0, 50)); // Keep latest 50 events
          if (onEvent) {
            onEvent(parsed);
          }
        } catch {
          // Ignore parse errors on raw messages
        }
      };

      ws.onerror = () => {
        setStatus('error');
      };

      ws.onclose = () => {
        setStatus('disconnected');
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        if (autoReconnect) {
          reconnectTimeoutRef.current = window.setTimeout(() => {
            connect();
          }, 3000);
        }
      };
    } catch {
      setStatus('error');
    }
  }, [investigationId, onEvent, autoReconnect]);

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

  const clearEvents = useCallback(() => {
    setEvents([]);
    setLastEvent(null);
  }, []);

  return {
    status,
    events,
    lastEvent,
    clearEvents,
    isConnected: status === 'connected',
  };
}
