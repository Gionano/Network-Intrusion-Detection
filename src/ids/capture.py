from __future__ import annotations

from typing import Any, Callable


def start_capture(
    packet_handler: Callable[[Any], None],
    interface: str = "",
    bpf_filter: str = "",
    promiscuous: bool = True,
    packet_limit: int = 0,
) -> None:
    try:
        from scapy.all import sniff
    except Exception as exc:
        raise RuntimeError("Scapy is required for packet capture") from exc

    sniff(
        iface=interface or None,
        filter=bpf_filter or None,
        prn=packet_handler,
        store=False,
        count=packet_limit if packet_limit and packet_limit > 0 else 0,
        promisc=promiscuous,
    )
