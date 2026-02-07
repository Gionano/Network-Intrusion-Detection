from __future__ import annotations

import logging
import os
import threading
from queue import Queue, Empty
from typing import Any

from .actions import block_ip, extract_src_ip, should_block
from .config import AppConfig
from .capture import start_capture
from .inference import detect
from .model import IDSModel


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

    queue: Queue[Any] = Queue(maxsize=2048)
    stop_event = threading.Event()

    def worker() -> None:
        while not stop_event.is_set():
            try:
                packet = queue.get(timeout=0.5)
            except Empty:
                continue
            try:
                result = detect(packet, model, config.model.threshold)
                if result.is_malicious:
                    src_ip = extract_src_ip(packet)
                    logger.warning(
                        "ALERT probability=%.4f src_ip=%s", result.probability, src_ip
                    )
                    if should_block(src_ip, config.actions) and src_ip not in blocked_ips:
                        block_ip(src_ip, config.actions)
                        blocked_ips.add(src_ip)
                        logger.warning("BLOCKED src_ip=%s", src_ip)
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

    logger.info("Starting capture on interface=%s filter=%s", config.capture.interface, config.capture.bpf_filter)
    start_capture(
        packet_handler=handler,
        interface=config.capture.interface,
        bpf_filter=config.capture.bpf_filter,
        promiscuous=config.capture.promiscuous,
        packet_limit=config.capture.packet_limit,
    )

    stop_event.set()
    worker_thread.join(timeout=2.0)
