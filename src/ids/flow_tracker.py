"""Flow-level traffic tracking for richer feature extraction.

Maintains per-flow state keyed by the 5-tuple (src_ip, dst_ip, src_port,
dst_port, protocol).  Each flow accumulates packet counts, byte counts,
timestamps, and inter-arrival-time statistics.  Flows expire automatically
after a configurable idle timeout.
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class FlowKey:
    """Immutable 5-tuple identifying a bidirectional flow."""

    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # "tcp", "udp", "icmp", "other"

    @classmethod
    def from_packet(cls, packet: Any) -> Optional["FlowKey"]:
        """Build a FlowKey from a scapy packet, or return None."""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
        except Exception:
            return None

        if packet is None or not packet.haslayer(IP):
            return None

        ip = packet[IP]
        src_ip = str(ip.src)
        dst_ip = str(ip.dst)

        if packet.haslayer(TCP):
            layer = packet[TCP]
            return cls(src_ip, dst_ip, int(layer.sport), int(layer.dport), "tcp")
        if packet.haslayer(UDP):
            layer = packet[UDP]
            return cls(src_ip, dst_ip, int(layer.sport), int(layer.dport), "udp")
        if packet.haslayer(ICMP):
            return cls(src_ip, dst_ip, 0, 0, "icmp")

        return cls(src_ip, dst_ip, 0, 0, "other")


@dataclass
class FlowStats:
    """Accumulated statistics for a single flow."""

    fwd_packet_count: int = 0
    bwd_packet_count: int = 0
    total_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    iat_values: list = field(default_factory=list)

    # --- derived properties ---------------------------------------------------

    @property
    def duration(self) -> float:
        return max(self.last_seen - self.first_seen, 0.0)

    @property
    def total_packets(self) -> int:
        return self.fwd_packet_count + self.bwd_packet_count

    @property
    def byte_rate(self) -> float:
        d = self.duration
        return self.total_bytes / d if d > 0 else 0.0

    @property
    def packet_rate(self) -> float:
        d = self.duration
        return self.total_packets / d if d > 0 else 0.0

    @property
    def fwd_bwd_ratio(self) -> float:
        if self.bwd_packet_count == 0:
            return float(self.fwd_packet_count)
        return self.fwd_packet_count / self.bwd_packet_count

    @property
    def iat_mean(self) -> float:
        if not self.iat_values:
            return 0.0
        return sum(self.iat_values) / len(self.iat_values)

    @property
    def iat_std(self) -> float:
        if len(self.iat_values) < 2:
            return 0.0
        mean = self.iat_mean
        var = sum((v - mean) ** 2 for v in self.iat_values) / len(self.iat_values)
        return math.sqrt(var)

    @property
    def iat_min(self) -> float:
        return min(self.iat_values) if self.iat_values else 0.0

    @property
    def iat_max(self) -> float:
        return max(self.iat_values) if self.iat_values else 0.0

    def as_dict(self) -> Dict[str, float]:
        return {
            "flow_duration": self.duration,
            "flow_byte_rate": self.byte_rate,
            "flow_packet_rate": self.packet_rate,
            "fwd_packet_count": float(self.fwd_packet_count),
            "bwd_packet_count": float(self.bwd_packet_count),
            "fwd_bwd_ratio": self.fwd_bwd_ratio,
            "iat_mean": self.iat_mean,
            "iat_std": self.iat_std,
            "iat_min": self.iat_min,
            "iat_max": self.iat_max,
        }


class FlowTracker:
    """Maintains a table of active flows and returns stats per-packet.

    Parameters
    ----------
    idle_timeout:
        Seconds of inactivity after which a flow is expired and removed.
    """

    def __init__(self, idle_timeout: float = 120.0) -> None:
        self._flows: Dict[Tuple[str, ...], FlowStats] = {}
        self._idle_timeout = idle_timeout

    # ------------------------------------------------------------------

    def update(self, packet: Any) -> Optional[FlowStats]:
        """Update flow state for *packet* and return the current FlowStats.

        Returns ``None`` if a FlowKey cannot be derived (non-IP packet).
        """
        key = FlowKey.from_packet(packet)
        if key is None:
            return None

        now = time.time()
        self._expire(now)

        canonical = self._canonical_key(key)
        is_forward = self._is_forward(key, canonical)
        pkt_len = len(packet) if packet is not None else 0

        if canonical not in self._flows:
            stats = FlowStats(first_seen=now, last_seen=now)
            self._flows[canonical] = stats
        else:
            stats = self._flows[canonical]
            iat = now - stats.last_seen
            stats.iat_values.append(iat)
            stats.last_seen = now

        if is_forward:
            stats.fwd_packet_count += 1
        else:
            stats.bwd_packet_count += 1
        stats.total_bytes += pkt_len

        return stats

    def active_flow_count(self) -> int:
        return len(self._flows)

    def reset(self) -> None:
        self._flows.clear()

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _canonical_key(key: FlowKey) -> Tuple[str, ...]:
        """Return a direction-agnostic canonical form of the 5-tuple."""
        fwd = (key.src_ip, key.dst_ip, str(key.src_port), str(key.dst_port), key.protocol)
        bwd = (key.dst_ip, key.src_ip, str(key.dst_port), str(key.src_port), key.protocol)
        return min(fwd, bwd)

    @staticmethod
    def _is_forward(key: FlowKey, canonical: Tuple[str, ...]) -> bool:
        fwd = (key.src_ip, key.dst_ip, str(key.src_port), str(key.dst_port), key.protocol)
        return fwd == canonical

    def _expire(self, now: float) -> None:
        expired = [
            k for k, v in self._flows.items()
            if (now - v.last_seen) > self._idle_timeout
        ]
        for k in expired:
            del self._flows[k]
