from __future__ import annotations

import argparse
import os
import sys

from ids.config import load_config
from ids.realtime import run_realtime


def main() -> int:
    parser = argparse.ArgumentParser(description="Run realtime IDS/IPS")
    parser.add_argument(
        "--config",
        default="configs/default.yaml",
        help="Path to configuration YAML",
    )
    parser.add_argument(
        "--pcap",
        default="",
        help="Path to a PCAP file for offline replay (skips live capture)",
    )
    parser.add_argument(
        "--output-csv",
        default="",
        help="Write per-packet results to this CSV (only with --pcap)",
    )
    args = parser.parse_args()

    config = load_config(args.config)
    if not os.path.exists(config.model.path):
        print(
            f"Model not found at {config.model.path}. Train first with: python src\\train.py",
            file=sys.stderr,
        )
        return 1

    if args.pcap:
        # Offline PCAP replay mode
        from ids.model import IDSModel
        from ids.replay import replay_pcap

        model = IDSModel.load(config.model.path)
        output_csv = args.output_csv or config.replay.output_csv
        alerts = replay_pcap(args.pcap, model, config, output_csv=output_csv)
        print(f"\nReplay finished: {len(alerts)} alert(s) detected.")
        return 0

    # Live capture mode
    run_realtime(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
