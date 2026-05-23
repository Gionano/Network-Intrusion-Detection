from __future__ import annotations

from typing import Any, Dict, List
import math

import numpy as np

MAX_PACKET_LEN = 1514.0
MAX_PORT = 65535.0
MAX_TTL = 255.0
MAX_WINDOW = 65535.0

FEATURE_NAMES: List[str] = [
    # --- original per-packet features ---
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
    # --- new per-packet features ---
    "tcp_psh",
    "tcp_urg",
    "tcp_window_size_norm",
    "ip_ttl_norm",
    "ip_header_len_norm",
    "payload_entropy",
    "payload_mean_byte",
    "is_dns",
    "is_http",
    # --- flow-level features (populated externally) ---
    "flow_duration",
    "flow_byte_rate",
    "flow_packet_rate",
    "fwd_packet_count",
    "bwd_packet_count",
    "fwd_bwd_ratio",
    "iat_mean",
    "iat_std",
    "iat_min",
    "iat_max",
]

NUM_FEATURES = len(FEATURE_NAMES)


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


def _entropy(data: bytes) -> float:
    """Compute Shannon entropy of a byte sequence (0.0 – 8.0)."""
    if not data:
        return 0.0
    length = len(data)
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            ent -= p * math.log2(p)
    return ent


def _mean_byte(data: bytes) -> float:
    """Return the mean byte value normalised to [0, 1]."""
    if not data:
        return 0.0
    return (sum(data) / len(data)) / 255.0


def extract_features(packet: Any, flow_stats: Any = None) -> np.ndarray:
    """Extract a fixed-length feature vector from a scapy packet.

    Parameters
    ----------
    packet:
        A scapy packet object.
    flow_stats:
        Optional ``FlowStats`` instance from :class:`~ids.flow_tracker.FlowTracker`.
        When provided, the flow-level features are filled in from it.
    """
    try:
        from scapy.layers.inet import IP, TCP, UDP, ICMP
    except Exception as exc:
        raise RuntimeError("Scapy is required for packet feature extraction") from exc

    packet_len = float(len(packet)) if packet is not None else 0.0

    # Payload bytes
    payload_bytes = b""
    payload_len = 0.0
    try:
        payload_bytes = bytes(packet.payload)
        payload_len = float(len(payload_bytes))
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
    tcp_psh = 0.0
    tcp_urg = 0.0
    tcp_window_size = 0.0
    ip_ttl = 0.0
    ip_header_len = 0.0
    is_dns = 0.0
    is_http = 0.0

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        ip_ttl = float(getattr(ip_layer, "ttl", 0) or 0)
        ip_header_len = float(getattr(ip_layer, "ihl", 5) or 5) * 4.0  # bytes

        if packet.haslayer(TCP):
            proto_tcp = 1.0
            layer = packet[TCP]
            src_port = float(getattr(layer, "sport", 0) or 0)
            dst_port = float(getattr(layer, "dport", 0) or 0)
            tcp_window_size = float(getattr(layer, "window", 0) or 0)
            flags = _get_tcp_flag_set(getattr(layer, "flags", ""))
            tcp_syn = 1.0 if "S" in flags else 0.0
            tcp_ack = 1.0 if "A" in flags else 0.0
            tcp_fin = 1.0 if "F" in flags else 0.0
            tcp_rst = 1.0 if "R" in flags else 0.0
            tcp_psh = 1.0 if "P" in flags else 0.0
            tcp_urg = 1.0 if "U" in flags else 0.0
            # DNS / HTTP heuristic
            if dst_port == 53 or src_port == 53:
                is_dns = 1.0
            if dst_port in (80, 443, 8080) or src_port in (80, 443, 8080):
                is_http = 1.0
        elif packet.haslayer(UDP):
            proto_udp = 1.0
            layer = packet[UDP]
            src_port = float(getattr(layer, "sport", 0) or 0)
            dst_port = float(getattr(layer, "dport", 0) or 0)
            if dst_port == 53 or src_port == 53:
                is_dns = 1.0
        elif packet.haslayer(ICMP):
            proto_icmp = 1.0

    # Flow-level features (defaults to zero if no tracker provided)
    fl_duration = 0.0
    fl_byte_rate = 0.0
    fl_packet_rate = 0.0
    fl_fwd_count = 0.0
    fl_bwd_count = 0.0
    fl_fwd_bwd_ratio = 0.0
    fl_iat_mean = 0.0
    fl_iat_std = 0.0
    fl_iat_min = 0.0
    fl_iat_max = 0.0

    if flow_stats is not None:
        fl_duration = min(flow_stats.duration, 600.0) / 600.0  # cap at 10 min
        fl_byte_rate = min(flow_stats.byte_rate, 1e8) / 1e8
        fl_packet_rate = min(flow_stats.packet_rate, 1e5) / 1e5
        fl_fwd_count = min(flow_stats.fwd_packet_count, 10000) / 10000.0
        fl_bwd_count = min(flow_stats.bwd_packet_count, 10000) / 10000.0
        fl_fwd_bwd_ratio = min(flow_stats.fwd_bwd_ratio, 100.0) / 100.0
        fl_iat_mean = min(flow_stats.iat_mean, 10.0) / 10.0
        fl_iat_std = min(flow_stats.iat_std, 10.0) / 10.0
        fl_iat_min = min(flow_stats.iat_min, 10.0) / 10.0
        fl_iat_max = min(flow_stats.iat_max, 10.0) / 10.0

    features = np.array(
        [
            # original
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
            # new per-packet
            tcp_psh,
            tcp_urg,
            _normalize(tcp_window_size, MAX_WINDOW),
            _normalize(ip_ttl, MAX_TTL),
            _normalize(ip_header_len, 60.0),  # max IP header is 60 bytes
            _entropy(payload_bytes) / 8.0,  # normalise to [0,1]
            _mean_byte(payload_bytes),
            is_dns,
            is_http,
            # flow-level
            fl_duration,
            fl_byte_rate,
            fl_packet_rate,
            fl_fwd_count,
            fl_bwd_count,
            fl_fwd_bwd_ratio,
            fl_iat_mean,
            fl_iat_std,
            fl_iat_min,
            fl_iat_max,
        ],
        dtype=np.float32,
    )
    return features


def feature_dict(packet: Any, flow_stats: Any = None) -> Dict[str, float]:
    vec = extract_features(packet, flow_stats)
    return {name: float(value) for name, value in zip(FEATURE_NAMES, vec)}
