"""Tests for ids.config module."""

from __future__ import annotations

import os
import tempfile

import pytest

from ids.config import (
    ActionConfig,
    AppConfig,
    CaptureConfig,
    DashboardConfig,
    LoggingConfig,
    ModelConfig,
    ReplayConfig,
    load_config,
)


class TestCaptureConfig:
    def test_defaults(self):
        cfg = CaptureConfig.from_dict(None)
        assert cfg.interface == ""
        assert cfg.bpf_filter == "ip"
        assert cfg.promiscuous is True
        assert cfg.packet_limit == 0

    def test_custom(self):
        cfg = CaptureConfig.from_dict({"interface": "eth0", "packet_limit": 100})
        assert cfg.interface == "eth0"
        assert cfg.packet_limit == 100


class TestModelConfig:
    def test_defaults(self):
        cfg = ModelConfig.from_dict(None)
        assert cfg.path == "models/ids_model"
        assert cfg.threshold == 0.6
        assert cfg.num_classes == 5

    def test_custom(self):
        cfg = ModelConfig.from_dict({"threshold": 0.8, "num_classes": 3})
        assert cfg.threshold == 0.8
        assert cfg.num_classes == 3


class TestActionConfig:
    def test_defaults(self):
        cfg = ActionConfig.from_dict(None)
        assert cfg.enable_blocking is False
        assert "{ip}" in cfg.block_command_template

    def test_enabled(self):
        cfg = ActionConfig.from_dict({"enable_blocking": True})
        assert cfg.enable_blocking is True


class TestLoggingConfig:
    def test_defaults(self):
        cfg = LoggingConfig.from_dict(None)
        assert cfg.path == "logs/ids.log"
        assert cfg.level == "INFO"


class TestDashboardConfig:
    def test_defaults(self):
        cfg = DashboardConfig.from_dict(None)
        assert cfg.enabled is True
        assert cfg.port == 8080

    def test_disabled(self):
        cfg = DashboardConfig.from_dict({"enabled": False, "port": 9090})
        assert cfg.enabled is False
        assert cfg.port == 9090


class TestReplayConfig:
    def test_defaults(self):
        cfg = ReplayConfig.from_dict(None)
        assert cfg.output_csv == ""


class TestAppConfig:
    def test_from_empty(self):
        cfg = AppConfig.from_dict({})
        assert cfg.capture.bpf_filter == "ip"
        assert cfg.dashboard.enabled is True

    def test_from_none(self):
        cfg = AppConfig.from_dict(None)
        assert cfg.model.threshold == 0.6


class TestLoadConfig:
    def test_missing_file(self):
        cfg = load_config("/nonexistent/path.yaml")
        assert cfg.capture.bpf_filter == "ip"

    def test_none_path(self):
        cfg = load_config(None)
        assert cfg.model.path == "models/ids_model"

    def test_valid_yaml(self, tmp_path):
        path = tmp_path / "test.yaml"
        path.write_text("model:\n  threshold: 0.9\ndashboard:\n  port: 3000\n")
        cfg = load_config(str(path))
        assert cfg.model.threshold == 0.9
        assert cfg.dashboard.port == 3000
        # Other sections should use defaults
        assert cfg.capture.bpf_filter == "ip"

    def test_empty_yaml(self, tmp_path):
        path = tmp_path / "empty.yaml"
        path.write_text("")
        cfg = load_config(str(path))
        assert cfg.model.threshold == 0.6
