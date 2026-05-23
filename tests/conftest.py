"""Shared pytest fixtures for the IDS test suite."""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, PropertyMock

import numpy as np
import pytest

# Ensure src/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ─── Mock Scapy Packets ─────────────────────────────────────────────

def _make_mock_ip():
    ip = MagicMock()
    ip.src = "192.168.1.100"
    ip.dst = "10.0.0.1"
    ip.ttl = 64
    ip.ihl = 5
    return ip


@pytest.fixture
def tcp_packet():
    """Mock TCP packet with SYN+ACK flags."""
    pkt = MagicMock()
    pkt.__len__ = lambda self: 200

    ip = _make_mock_ip()
    tcp = MagicMock()
    tcp.sport = 54321
    tcp.dport = 80
    tcp.flags = "SA"
    tcp.window = 65535

    # haslayer routing
    def haslayer(layer):
        name = getattr(layer, "__name__", str(layer))
        return name in ("IP", "TCP")

    pkt.haslayer = haslayer

    def getitem(layer):
        name = getattr(layer, "__name__", str(layer))
        if name == "IP":
            return ip
        if name == "TCP":
            return tcp
        raise KeyError(name)

    pkt.__getitem__ = getitem
    pkt.payload = MagicMock()
    pkt.payload.__bytes__ = lambda self: b"\x00" * 50
    type(pkt.payload).__len__ = lambda self: 50

    return pkt


@pytest.fixture
def udp_packet():
    """Mock UDP packet."""
    pkt = MagicMock()
    pkt.__len__ = lambda self: 150

    ip = _make_mock_ip()
    udp = MagicMock()
    udp.sport = 12345
    udp.dport = 53

    def haslayer(layer):
        name = getattr(layer, "__name__", str(layer))
        return name in ("IP", "UDP")

    pkt.haslayer = haslayer

    def getitem(layer):
        name = getattr(layer, "__name__", str(layer))
        if name == "IP":
            return ip
        if name == "UDP":
            return udp
        raise KeyError(name)

    pkt.__getitem__ = getitem
    pkt.payload = MagicMock()
    pkt.payload.__bytes__ = lambda self: b"\xAB" * 30
    type(pkt.payload).__len__ = lambda self: 30

    return pkt


@pytest.fixture
def icmp_packet():
    """Mock ICMP packet."""
    pkt = MagicMock()
    pkt.__len__ = lambda self: 64

    ip = _make_mock_ip()

    def haslayer(layer):
        name = getattr(layer, "__name__", str(layer))
        return name in ("IP", "ICMP")

    pkt.haslayer = haslayer

    def getitem(layer):
        name = getattr(layer, "__name__", str(layer))
        if name == "IP":
            return ip
        raise KeyError(name)

    pkt.__getitem__ = getitem
    pkt.payload = MagicMock()
    pkt.payload.__bytes__ = lambda self: b""
    type(pkt.payload).__len__ = lambda self: 0

    return pkt


@pytest.fixture
def sample_config():
    """Return a default AppConfig."""
    from ids.config import AppConfig

    return AppConfig.from_dict({})


@pytest.fixture
def sample_features():
    """A sample feature vector of the correct length."""
    from ids.feature_extraction import NUM_FEATURES

    rng = np.random.default_rng(0)
    return rng.random(NUM_FEATURES).astype(np.float32)
