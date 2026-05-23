"""FastAPI-based dashboard server for real-time IDS monitoring."""

from __future__ import annotations

import asyncio
import json
import os
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional

try:
    from fastapi import FastAPI, WebSocket, WebSocketDisconnect
    from fastapi.responses import HTMLResponse, JSONResponse
    from fastapi.staticfiles import StaticFiles
    import uvicorn
except ImportError:
    FastAPI = None  # type: ignore

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")


class DashboardState:
    """Thread-safe shared state between the IDS engine and the dashboard."""

    def __init__(self, max_alerts: int = 500) -> None:
        self._lock = threading.Lock()
        self._total_packets = 0
        self._total_alerts = 0
        self._alerts: deque = deque(maxlen=max_alerts)
        self._blocked_ips: List[str] = []
        self._start_time = time.time()
        self._packets_window: deque = deque(maxlen=120)  # 2-min sliding window
        self._ws_clients: List[Any] = []

    def record_packet(self) -> None:
        with self._lock:
            self._total_packets += 1
            self._packets_window.append(time.time())

    def record_alert(self, alert_data: dict) -> None:
        with self._lock:
            self._total_alerts += 1
            self._alerts.appendleft(alert_data)
        # Notify websocket clients (fire-and-forget)
        self._broadcast(alert_data)

    def record_block(self, ip: str) -> None:
        with self._lock:
            if ip not in self._blocked_ips:
                self._blocked_ips.append(ip)

    def get_stats(self) -> dict:
        with self._lock:
            now = time.time()
            # Packets per second (over last 10s window)
            cutoff = now - 10.0
            recent = sum(1 for t in self._packets_window if t > cutoff)
            pps = recent / 10.0

            return {
                "total_packets": self._total_packets,
                "total_alerts": self._total_alerts,
                "blocked_ips_count": len(self._blocked_ips),
                "packets_per_sec": round(pps, 2),
                "uptime_seconds": round(now - self._start_time, 1),
            }

    def get_recent_alerts(self, limit: int = 100) -> list:
        with self._lock:
            return list(self._alerts)[:limit]

    def get_blocked_ips(self) -> list:
        with self._lock:
            return list(self._blocked_ips)

    def register_ws(self, ws: Any) -> None:
        self._ws_clients.append(ws)

    def unregister_ws(self, ws: Any) -> None:
        try:
            self._ws_clients.remove(ws)
        except ValueError:
            pass

    def _broadcast(self, data: dict) -> None:
        """Best-effort broadcast to all connected WebSocket clients."""
        msg = json.dumps(data, default=str)
        stale = []
        for ws in list(self._ws_clients):
            try:
                asyncio.run_coroutine_threadsafe(ws.send_text(msg), ws._loop)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self.unregister_ws(ws)


def _create_app(state: DashboardState) -> "FastAPI":
    if FastAPI is None:
        raise RuntimeError("Install fastapi and uvicorn: pip install fastapi uvicorn")

    app = FastAPI(title="IDS Dashboard", docs_url=None, redoc_url=None)

    # --- API endpoints --------------------------------------------------------

    @app.get("/api/stats")
    async def api_stats():
        return JSONResponse(state.get_stats())

    @app.get("/api/alerts")
    async def api_alerts(limit: int = 100):
        return JSONResponse(state.get_recent_alerts(limit))

    @app.get("/api/blocked")
    async def api_blocked():
        return JSONResponse(state.get_blocked_ips())

    @app.websocket("/ws/live")
    async def websocket_live(ws: WebSocket):
        await ws.accept()
        ws._loop = asyncio.get_event_loop()  # type: ignore[attr-defined]
        state.register_ws(ws)
        try:
            while True:
                await ws.receive_text()  # keep-alive
        except WebSocketDisconnect:
            pass
        finally:
            state.unregister_ws(ws)

    # --- Static / SPA ---------------------------------------------------------

    @app.get("/")
    async def index():
        index_path = os.path.join(STATIC_DIR, "index.html")
        if os.path.exists(index_path):
            with open(index_path, "r", encoding="utf-8") as f:
                return HTMLResponse(f.read())
        return HTMLResponse("<h1>Dashboard</h1><p>Static files not found.</p>")

    if os.path.isdir(STATIC_DIR):
        app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

    return app


def start_dashboard(state: DashboardState, port: int = 8080) -> threading.Thread:
    """Launch the dashboard on a daemon thread and return the thread."""
    app = _create_app(state)

    def _run() -> None:
        config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="warning")
        server = uvicorn.Server(config)
        server.run()

    thread = threading.Thread(target=_run, daemon=True, name="ids-dashboard")
    thread.start()
    return thread
