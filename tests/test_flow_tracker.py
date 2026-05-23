"""Tests for ids.flow_tracker module."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

from ids.flow_tracker import FlowKey, FlowStats, FlowTracker


class TestFlowKey:
    def test_from_packet_none(self):
        assert FlowKey.from_packet(None) is None

    def test_immutable(self):
        key = FlowKey("1.1.1.1", "2.2.2.2", 80, 443, "tcp")
        with pytest.raises(AttributeError):
            key.src_ip = "3.3.3.3"

    def test_equality(self):
        a = FlowKey("1.1.1.1", "2.2.2.2", 80, 443, "tcp")
        b = FlowKey("1.1.1.1", "2.2.2.2", 80, 443, "tcp")
        assert a == b

    def test_hashable(self):
        key = FlowKey("1.1.1.1", "2.2.2.2", 80, 443, "tcp")
        d = {key: "test"}
        assert d[key] == "test"


class TestFlowStats:
    def test_defaults(self):
        fs = FlowStats()
        assert fs.total_packets == 0
        assert fs.duration == 0.0
        assert fs.byte_rate == 0.0
        assert fs.iat_mean == 0.0
        assert fs.iat_std == 0.0
        assert fs.fwd_bwd_ratio == 0.0

    def test_duration(self):
        fs = FlowStats(first_seen=100.0, last_seen=110.0)
        assert fs.duration == pytest.approx(10.0)

    def test_rates(self):
        fs = FlowStats(
            fwd_packet_count=5,
            bwd_packet_count=5,
            total_bytes=1000,
            first_seen=0.0,
            last_seen=10.0,
        )
        assert fs.byte_rate == pytest.approx(100.0)
        assert fs.packet_rate == pytest.approx(1.0)

    def test_fwd_bwd_ratio_no_bwd(self):
        fs = FlowStats(fwd_packet_count=10, bwd_packet_count=0)
        assert fs.fwd_bwd_ratio == 10.0

    def test_iat_stats(self):
        fs = FlowStats(iat_values=[1.0, 2.0, 3.0])
        assert fs.iat_mean == pytest.approx(2.0)
        assert fs.iat_min == pytest.approx(1.0)
        assert fs.iat_max == pytest.approx(3.0)
        assert fs.iat_std > 0.0

    def test_iat_std_single(self):
        fs = FlowStats(iat_values=[5.0])
        assert fs.iat_std == 0.0

    def test_as_dict(self):
        fs = FlowStats(first_seen=0.0, last_seen=1.0, fwd_packet_count=2)
        d = fs.as_dict()
        assert "flow_duration" in d
        assert "iat_mean" in d
        assert len(d) == 10


class TestFlowTracker:
    def test_update_creates_flow(self, tcp_packet):
        tracker = FlowTracker()
        stats = tracker.update(tcp_packet)
        assert stats is not None
        assert stats.total_packets == 1
        assert tracker.active_flow_count() == 1

    def test_update_increments(self, tcp_packet):
        tracker = FlowTracker()
        tracker.update(tcp_packet)
        stats = tracker.update(tcp_packet)
        assert stats.total_packets == 2

    def test_none_packet(self):
        tracker = FlowTracker()
        assert tracker.update(None) is None

    def test_non_ip_packet(self):
        pkt = MagicMock()
        pkt.haslayer = lambda layer: False
        tracker = FlowTracker()
        assert tracker.update(pkt) is None

    def test_flow_expiry(self, tcp_packet):
        tracker = FlowTracker(idle_timeout=0.0)
        tracker.update(tcp_packet)
        time.sleep(0.01)
        # Next update triggers expiry
        tracker.update(tcp_packet)
        # The old flow was expired and a new one created
        assert tracker.active_flow_count() == 1

    def test_reset(self, tcp_packet):
        tracker = FlowTracker()
        tracker.update(tcp_packet)
        tracker.reset()
        assert tracker.active_flow_count() == 0

    def test_iat_populated_on_second_packet(self, tcp_packet):
        tracker = FlowTracker()
        tracker.update(tcp_packet)
        time.sleep(0.01)
        stats = tracker.update(tcp_packet)
        assert len(stats.iat_values) >= 1
