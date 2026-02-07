from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict
import os

import yaml


@dataclass
class CaptureConfig:
    interface: str = ""
    bpf_filter: str = "ip"
    promiscuous: bool = True
    packet_limit: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "CaptureConfig":
        data = data or {}
        return cls(
            interface=str(data.get("interface", "")),
            bpf_filter=str(data.get("bpf_filter", "ip")),
            promiscuous=bool(data.get("promiscuous", True)),
            packet_limit=int(data.get("packet_limit", 0)),
        )


@dataclass
class ModelConfig:
    path: str = "models/ids_model"
    threshold: float = 0.6

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "ModelConfig":
        data = data or {}
        return cls(
            path=str(data.get("path", "models/ids_model")),
            threshold=float(data.get("threshold", 0.6)),
        )


@dataclass
class ActionConfig:
    enable_blocking: bool = False
    block_command_template: str = (
        'netsh advfirewall firewall add rule name="IDS Block {ip}" '
        "dir=in action=block remoteip={ip}"
    )

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "ActionConfig":
        data = data or {}
        return cls(
            enable_blocking=bool(data.get("enable_blocking", False)),
            block_command_template=str(
                data.get(
                    "block_command_template",
                    (
                        'netsh advfirewall firewall add rule name="IDS Block {ip}" '
                        "dir=in action=block remoteip={ip}"
                    ),
                )
            ),
        )


@dataclass
class LoggingConfig:
    path: str = "logs/ids.log"
    level: str = "INFO"

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "LoggingConfig":
        data = data or {}
        return cls(
            path=str(data.get("path", "logs/ids.log")),
            level=str(data.get("level", "INFO")),
        )


@dataclass
class AppConfig:
    capture: CaptureConfig
    model: ModelConfig
    actions: ActionConfig
    logging: LoggingConfig

    @classmethod
    def from_dict(cls, data: Dict[str, Any] | None) -> "AppConfig":
        data = data or {}
        return cls(
            capture=CaptureConfig.from_dict(data.get("capture")),
            model=ModelConfig.from_dict(data.get("model")),
            actions=ActionConfig.from_dict(data.get("actions")),
            logging=LoggingConfig.from_dict(data.get("logging")),
        )


def load_config(path: str | None) -> AppConfig:
    if not path:
        return AppConfig.from_dict({})
    if not os.path.exists(path):
        return AppConfig.from_dict({})
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    return AppConfig.from_dict(data)
