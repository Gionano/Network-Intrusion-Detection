"""Tests for ids.feature_extraction module."""

from __future__ import annotations

import numpy as np
import pytest

from ids.feature_extraction import (
    FEATURE_NAMES,
    NUM_FEATURES,
    _entropy,
    _mean_byte,
    _normalize,
    extract_features,
    feature_dict,
)


class TestNormalize:
    def test_basic(self):
        assert _normalize(50.0, 100.0) == pytest.approx(0.5)

    def test_clamp_above(self):
        assert _normalize(200.0, 100.0) == pytest.approx(1.0)

    def test_negative(self):
        assert _normalize(-5.0, 100.0) == 0.0

    def test_zero_max(self):
        assert _normalize(50.0, 0.0) == 0.0

    def test_zero_value(self):
        assert _normalize(0.0, 100.0) == 0.0


class TestEntropy:
    def test_empty(self):
        assert _entropy(b"") == 0.0

    def test_uniform(self):
        # All same byte → entropy 0
        assert _entropy(b"\xff" * 100) == 0.0

    def test_two_symbols(self):
        # Equal mix of two symbols → entropy 1.0
        data = b"\x00" * 50 + b"\x01" * 50
        assert _entropy(data) == pytest.approx(1.0, abs=0.01)

    def test_max_entropy(self):
        # 256 distinct bytes → entropy 8.0
        data = bytes(range(256))
        assert _entropy(data) == pytest.approx(8.0, abs=0.01)


class TestMeanByte:
    def test_empty(self):
        assert _mean_byte(b"") == 0.0

    def test_zeros(self):
        assert _mean_byte(b"\x00\x00") == 0.0

    def test_max(self):
        assert _mean_byte(b"\xff") == pytest.approx(1.0)


class TestExtractFeatures:
    def test_output_length(self, tcp_packet):
        feats = extract_features(tcp_packet)
        assert len(feats) == NUM_FEATURES
        assert feats.dtype == np.float32

    def test_feature_names_match_length(self):
        assert len(FEATURE_NAMES) == NUM_FEATURES

    def test_tcp_proto_flag(self, tcp_packet):
        feats = extract_features(tcp_packet)
        idx_tcp = FEATURE_NAMES.index("proto_tcp")
        idx_udp = FEATURE_NAMES.index("proto_udp")
        idx_icmp = FEATURE_NAMES.index("proto_icmp")
        assert feats[idx_tcp] == 1.0
        assert feats[idx_udp] == 0.0
        assert feats[idx_icmp] == 0.0

    def test_udp_proto_flag(self, udp_packet):
        feats = extract_features(udp_packet)
        assert feats[FEATURE_NAMES.index("proto_udp")] == 1.0
        assert feats[FEATURE_NAMES.index("proto_tcp")] == 0.0

    def test_icmp_proto_flag(self, icmp_packet):
        feats = extract_features(icmp_packet)
        assert feats[FEATURE_NAMES.index("proto_icmp")] == 1.0

    def test_dns_flag_udp(self, udp_packet):
        feats = extract_features(udp_packet)
        # UDP packet with dport=53 should set is_dns
        assert feats[FEATURE_NAMES.index("is_dns")] == 1.0

    def test_all_values_in_range(self, tcp_packet):
        feats = extract_features(tcp_packet)
        assert np.all(feats >= 0.0)
        assert np.all(feats <= 1.0)

    def test_with_flow_stats(self, tcp_packet):
        from unittest.mock import MagicMock

        stats = MagicMock()
        stats.duration = 10.0
        stats.byte_rate = 5000.0
        stats.packet_rate = 50.0
        stats.fwd_packet_count = 20
        stats.bwd_packet_count = 10
        stats.fwd_bwd_ratio = 2.0
        stats.iat_mean = 0.5
        stats.iat_std = 0.1
        stats.iat_min = 0.01
        stats.iat_max = 1.0

        feats = extract_features(tcp_packet, flow_stats=stats)
        assert feats[FEATURE_NAMES.index("flow_duration")] > 0.0


class TestFeatureDict:
    def test_keys_match(self, tcp_packet):
        d = feature_dict(tcp_packet)
        assert set(d.keys()) == set(FEATURE_NAMES)
