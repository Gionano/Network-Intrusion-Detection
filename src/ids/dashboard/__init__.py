"""Real-time IDS monitoring dashboard.

Exposes ``DashboardState`` (thread-safe shared state) and ``start_dashboard``
(launches a FastAPI server on a background thread).
"""

from .server import DashboardState, start_dashboard

__all__ = ["DashboardState", "start_dashboard"]
