"""Tests for ids.actions module."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from ids.actions import build_block_command, extract_src_ip, should_block
from ids.config import ActionConfig


class TestExtractSrcIp:
    def test_with_ip_packet(self, tcp_packet):
        ip = extract_src_ip(tcp_packet)
        assert ip == "192.168.1.100"

    def test_with_none(self):
        assert extract_src_ip(None) is None

    def test_without_ip_layer(self):
        pkt = MagicMock()
        pkt.haslayer = lambda layer: False
        assert extract_src_ip(pkt) is None


class TestBuildBlockCommand:
    def test_template(self):
        template = 'netsh advfirewall firewall add rule name="Block {ip}" remoteip={ip}'
        result = build_block_command(template, "1.2.3.4")
        assert "1.2.3.4" in result
        assert result.count("1.2.3.4") == 2

    def test_simple_template(self):
        assert build_block_command("block {ip}", "10.0.0.1") == "block 10.0.0.1"


class TestShouldBlock:
    def test_blocking_enabled(self):
        cfg = ActionConfig(enable_blocking=True)
        assert should_block("1.2.3.4", cfg) is True

    def test_blocking_disabled(self):
        cfg = ActionConfig(enable_blocking=False)
        assert should_block("1.2.3.4", cfg) is False

    def test_no_ip(self):
        cfg = ActionConfig(enable_blocking=True)
        assert should_block(None, cfg) is False
        assert should_block("", cfg) is False
