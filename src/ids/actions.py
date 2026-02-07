from __future__ import annotations

from typing import Any, Optional
import subprocess

from .config import ActionConfig


def extract_src_ip(packet: Any) -> Optional[str]:
    try:
        from scapy.layers.inet import IP
    except Exception:
        return None
    if packet is None:
        return None
    if packet.haslayer(IP):
        return str(packet[IP].src)
    return None


def build_block_command(template: str, ip: str) -> str:
    return template.format(ip=ip)


def block_ip(ip: str, config: ActionConfig) -> None:
    cmd = build_block_command(config.block_command_template, ip)
    subprocess.run(cmd, shell=True, check=False)


def should_block(ip: Optional[str], config: ActionConfig) -> bool:
    return bool(ip) and config.enable_blocking
