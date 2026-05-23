"""Tests for ids.inference module."""

from __future__ import annotations

from unittest.mock import MagicMock

import numpy as np
import pytest

from ids.feature_extraction import NUM_FEATURES
from ids.inference import DetectionResult, detect
from ids.model import ATTACK_CLASSES, NUM_CLASSES, IDSModel, build_model


class TestDetect:
    @pytest.fixture
    def model(self):
        keras_model = build_model(input_dim=NUM_FEATURES, num_classes=NUM_CLASSES)
        return IDSModel(model=keras_model, input_dim=NUM_FEATURES)

    def test_returns_detection_result(self, model, tcp_packet):
        result = detect(tcp_packet, model, threshold=0.5)
        assert isinstance(result, DetectionResult)

    def test_result_fields(self, model, tcp_packet):
        result = detect(tcp_packet, model, threshold=0.5)
        assert isinstance(result.predicted_class, int)
        assert isinstance(result.attack_class, str)
        assert 0.0 <= result.confidence <= 1.0
        assert isinstance(result.class_probabilities, dict)
        assert isinstance(result.features, np.ndarray)
        assert len(result.features) == NUM_FEATURES

    def test_normal_not_malicious(self, model, tcp_packet):
        # If predicted class is 0 (Normal), should not be malicious regardless of threshold
        result = detect(tcp_packet, model, threshold=0.0)
        if result.predicted_class == 0:
            assert result.is_malicious is False

    def test_high_threshold_not_malicious(self, model, tcp_packet):
        # With impossibly high threshold, nothing should be flagged
        result = detect(tcp_packet, model, threshold=1.1)
        assert result.is_malicious is False

    def test_attack_class_in_dict(self, model, tcp_packet):
        result = detect(tcp_packet, model, threshold=0.5)
        assert result.attack_class in ATTACK_CLASSES.values()

    def test_probabilities_sum(self, model, tcp_packet):
        result = detect(tcp_packet, model, threshold=0.5)
        total = sum(result.class_probabilities.values())
        assert total == pytest.approx(1.0, abs=0.02)

    def test_with_flow_stats(self, model, tcp_packet):
        stats = MagicMock()
        stats.duration = 1.0
        stats.byte_rate = 100.0
        stats.packet_rate = 10.0
        stats.fwd_packet_count = 5
        stats.bwd_packet_count = 3
        stats.fwd_bwd_ratio = 1.67
        stats.iat_mean = 0.1
        stats.iat_std = 0.05
        stats.iat_min = 0.01
        stats.iat_max = 0.2

        result = detect(tcp_packet, model, threshold=0.5, flow_stats=stats)
        assert isinstance(result, DetectionResult)
