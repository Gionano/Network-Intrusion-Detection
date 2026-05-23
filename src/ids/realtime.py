from __future__ import annotations

import logging
import os
import threading
import time
from queue import Queue, Empty
from typing import Any, Optional

from .actions import block_ip, extract_src_ip, should_block
from .config import AppConfig
from .capture import start_capture
from .flow_tracker import FlowTracker
from .inference import detect
from .model import IDSModel, ATTACK_CLASSES


def _configure_logging(path: str, level: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(message)s",
        handlers=[logging.FileHandler(path), logging.StreamHandler()],
    )


def run_realtime(config: AppConfig) -> None:
    _configure_logging(config.logging.path, config.logging.level)
    logger = logging.getLogger("ids")

    model = IDSModel.load(config.model.path)
    blocked_ips: set[str] = set()
    flow_tracker = FlowTracker()

    queue: Queue[Any] = Queue(maxsize=2048)
    stop_event = threading.Event()

    # --- optional dashboard ---------------------------------------------------
    dashboard_state: Optional[Any] = None
    if config.dashboard.enabled:
        try:
            from .dashboard import DashboardState, start_dashboard

            dashboard_state = DashboardState()
            start_dashboard(dashboard_state, port=config.dashboard.port)
            logger.info("Dashboard started at http://localhost:%d", config.dashboard.port)
        except Exception as exc:
            logger.warning("Failed to start dashboard: %s", exc)

    # --- worker ---------------------------------------------------------------

    def worker() -> None:
        while not stop_event.is_set():
            try:
                packet = queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                flow_stats = flow_tracker.update(packet)
                result = detect(packet, model, config.model.threshold, flow_stats)

                if dashboard_state is not None:
                    dashboard_state.record_packet()

                if result.is_malicious:
                    src_ip = extract_src_ip(packet)
                    dst_ip = _extract_dst_ip(packet)
                    logger.warning(
                        "ALERT class=%s confidence=%.4f src_ip=%s",
                        result.attack_class,
                        result.confidence,
                        src_ip,
                    )

                    # Dashboard alert
                    if dashboard_state is not None:
                        dashboard_state.record_alert(
                            {
                                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
                                "src_ip": src_ip or "",
                                "dst_ip": dst_ip or "",
                                "attack_class": result.attack_class,
                                "confidence": result.confidence,
                                "class_probabilities": result.class_probabilities,
                            }
                        )

                    if should_block(src_ip, config.actions) and src_ip not in blocked_ips:
                        block_ip(src_ip, config.actions)
                        blocked_ips.add(src_ip)
                        logger.warning("BLOCKED src_ip=%s", src_ip)
                        if dashboard_state is not None:
                            dashboard_state.record_block(src_ip)
            except Exception as exc:
                logger.exception("Error processing packet: %s", exc)
            finally:
                queue.task_done()

    def handler(packet: Any) -> None:
        try:
            queue.put_nowait(packet)
        except Exception:
            logger.debug("Packet queue full; dropping")

    worker_thread = threading.Thread(target=worker, daemon=True)
    worker_thread.start()

    logger.info(
        "Starting capture on interface=%s filter=%s",
        config.capture.interface,
        config.capture.bpf_filter,
    )
    start_capture(
        packet_handler=handler,
        interface=config.capture.interface,
        bpf_filter=config.capture.bpf_filter,
        promiscuous=config.capture.promiscuous,
        packet_limit=config.capture.packet_limit,
    )

    stop_event.set()
    worker_thread.join(timeout=2.0)


def _extract_dst_ip(packet: Any) -> Optional[str]:
    try:
        from scapy.layers.inet import IP
    except Exception:
        return None
    if packet is not None and packet.haslayer(IP):
        return str(packet[IP].dst)
    return None
