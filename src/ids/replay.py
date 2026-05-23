"""PCAP file replay for offline analysis.

Reads packets from ``.pcap`` / ``.pcapng`` files and runs each through the
same detection pipeline used for live capture.
"""

from __future__ import annotations

import csv
import logging
import os
from typing import Any, List, Optional

from .config import AppConfig
from .feature_extraction import FEATURE_NAMES
from .inference import detect
from .model import IDSModel

logger = logging.getLogger("ids.replay")

ATTACK_CLASSES = {0: "Normal", 1: "Port Scan", 2: "DDoS", 3: "Brute Force", 4: "Exfiltration"}


def replay_pcap(
    pcap_path: str,
    model: IDSModel,
    config: AppConfig,
    output_csv: str = "",
) -> List[dict]:
    """Replay a PCAP file through the IDS detection pipeline.

    Parameters
    ----------
    pcap_path:
        Path to a ``.pcap`` or ``.pcapng`` file.
    model:
        Loaded IDSModel instance.
    config:
        Application configuration (uses model.threshold).
    output_csv:
        If non-empty, write per-packet results to this CSV path.

    Returns
    -------
    List of result dicts for every detected malicious packet.
    """
    try:
        from scapy.utils import PcapReader
    except Exception as exc:
        raise RuntimeError("Scapy is required for PCAP replay") from exc

    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    alerts: List[dict] = []
    all_results: List[dict] = []
    total = 0

    logger.info("Replaying PCAP: %s", pcap_path)

    reader = PcapReader(pcap_path)
    try:
        for packet in reader:
            total += 1
            try:
                result = detect(packet, model, config.model.threshold)
                row = _result_to_dict(packet, result, total)
                all_results.append(row)

                if result.is_malicious:
                    alerts.append(row)
                    logger.warning(
                        "ALERT packet=%d class=%s confidence=%.4f src=%s",
                        total,
                        row.get("attack_class", "Unknown"),
                        result.confidence,
                        row.get("src_ip", "?"),
                    )
            except Exception as exc:
                logger.debug("Skipping packet %d: %s", total, exc)
    finally:
        reader.close()

    logger.info(
        "Replay complete: %d packets processed, %d alerts", total, len(alerts)
    )

    if output_csv:
        _write_csv(output_csv, all_results)
        logger.info("Results written to %s", output_csv)

    return alerts


def _result_to_dict(packet: Any, result: Any, index: int) -> dict:
    src_ip = ""
    dst_ip = ""
    try:
        from scapy.layers.inet import IP

        if packet.haslayer(IP):
            src_ip = str(packet[IP].src)
            dst_ip = str(packet[IP].dst)
    except Exception:
        pass

    row: dict = {
        "packet_index": index,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "attack_class": result.attack_class,
        "confidence": round(result.confidence, 6),
        "is_malicious": result.is_malicious,
    }
    return row


def _write_csv(path: str, rows: List[dict]) -> None:
    if not rows:
        return
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    fieldnames = list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
