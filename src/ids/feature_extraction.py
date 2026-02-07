from __future__ import annotations

from typing import Any, Dict, List

import numpy as np

MAX_PACKET_LEN = 1514.0
MAX_PORT = 65535.0

FEATURE_NAMES: List[str] = [
    "packet_len_norm",
    "src_port_norm",
    "dst_port_norm",
    "payload_len_norm",
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "tcp_syn",
    "tcp_ack",
    "tcp_fin",
    "tcp_rst",
]


def _normalize(value: float, max_value: float) -> float:
    if max_value <= 0:
        return 0.0
    if value < 0:
        return 0.0
    return min(value, max_value) / max_value


def _get_tcp_flag_set(flags: Any) -> set[str]:
    if flags is None:
        return set()
    if isinstance(flags, str):
        return set(flags)
    try:
        return set(str(flags))
    except Exception:
        return set()


def extract_features(packet: Any) -> np.ndarray:
    """Extract a fixed-length feature vector from a scapy packet."""
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except Exception as exc:
        raise RuntimeError("Scapy is required for packet feature extraction") from exc

    packet_len = float(len(packet)) if packet is not None else 0.0
    payload_len = 0.0
    try:
        payload_len = float(len(bytes(packet.payload)))
    except Exception:
        payload_len = 0.0

    src_port = 0.0
    dst_port = 0.0
    proto_tcp = 0.0
    proto_udp = 0.0
    proto_icmp = 0.0
    tcp_syn = 0.0
    tcp_ack = 0.0
    tcp_fin = 0.0
    tcp_rst = 0.0

    if packet.haslayer(IP):
        if packet.haslayer(TCP):
            proto_tcp = 1.0
            layer = packet[TCP]
            src_port = float(getattr(layer, "sport", 0) or 0)
            dst_port = float(getattr(layer, "dport", 0) or 0)
            flags = _get_tcp_flag_set(getattr(layer, "flags", ""))
            tcp_syn = 1.0 if "S" in flags else 0.0
            tcp_ack = 1.0 if "A" in flags else 0.0
            tcp_fin = 1.0 if "F" in flags else 0.0
            tcp_rst = 1.0 if "R" in flags else 0.0
        elif packet.haslayer(UDP):
            proto_udp = 1.0
            layer = packet[UDP]
            src_port = float(getattr(layer, "sport", 0) or 0)
            dst_port = float(getattr(layer, "dport", 0) or 0)
        elif packet.haslayer(ICMP):
            proto_icmp = 1.0

    features = np.array(
        [
            _normalize(packet_len, MAX_PACKET_LEN),
            _normalize(src_port, MAX_PORT),
            _normalize(dst_port, MAX_PORT),
            _normalize(payload_len, MAX_PACKET_LEN),
            proto_tcp,
            proto_udp,
            proto_icmp,
            tcp_syn,
            tcp_ack,
            tcp_fin,
            tcp_rst,
        ],
        dtype=np.float32,
    )
    return features


def feature_dict(packet: Any) -> Dict[str, float]:
    vec = extract_features(packet)
    return {name: float(value) for name, value in zip(FEATURE_NAMES, vec)}
