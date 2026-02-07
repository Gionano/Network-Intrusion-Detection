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
    args = parser.parse_args()

    config = load_config(args.config)
    if not os.path.exists(config.model.path):
        print(
            f"Model not found at {config.model.path}. Train first with: python src\\train.py",
            file=sys.stderr,
        )
        return 1

    run_realtime(config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
