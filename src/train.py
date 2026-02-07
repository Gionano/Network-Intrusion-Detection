from __future__ import annotations

import argparse
import os
from typing import Tuple

import numpy as np
import pandas as pd

from ids.feature_extraction import FEATURE_NAMES
from ids.model import IDSModel, build_model, require_tensorflow


def load_csv(path: str) -> Tuple[np.ndarray, np.ndarray]:
    try:
        df = pd.read_csv(path)
    except pd.errors.EmptyDataError as exc:
        raise ValueError(
            f"CSV file is empty: {path}. Generate one with --export-csv or add data."
        ) from exc
    if df.empty:
        raise ValueError(f"CSV has no rows: {path}. Add data or regenerate the file.")
    missing = [name for name in FEATURE_NAMES if name not in df.columns]
    if missing:
        raise ValueError(f"CSV missing required feature columns: {missing}")
    if "label" not in df.columns:
        raise ValueError("CSV missing required label column: label")
    x = df[FEATURE_NAMES].astype("float32").to_numpy()
    y = df["label"].astype("float32").to_numpy()
    return x, y


def export_csv(path: str, samples: int, seed: int) -> None:
    x, y = generate_synthetic(samples, seed)
    df = pd.DataFrame(x, columns=FEATURE_NAMES)
    df["label"] = y
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    df.to_csv(path, index=False)


def generate_synthetic(samples: int, seed: int) -> Tuple[np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    x = np.zeros((samples, len(FEATURE_NAMES)), dtype=np.float32)
    y = np.zeros(samples, dtype=np.float32)

    suspicious_ports = np.array([23, 445, 3389, 5900], dtype=np.float32) / 65535.0

    for i in range(samples):
        proto_choice = rng.choice(["tcp", "udp", "icmp"], p=[0.6, 0.3, 0.1])
        packet_len = rng.uniform(0.05, 1.0)
        src_port = rng.uniform(0.0, 1.0)
        dst_port = rng.uniform(0.0, 1.0)
        payload_len = rng.uniform(0.0, 1.0)

        proto_tcp = 1.0 if proto_choice == "tcp" else 0.0
        proto_udp = 1.0 if proto_choice == "udp" else 0.0
        proto_icmp = 1.0 if proto_choice == "icmp" else 0.0

        tcp_syn = 0.0
        tcp_ack = 0.0
        tcp_fin = 0.0
        tcp_rst = 0.0

        if proto_choice == "tcp":
            if rng.random() < 0.1:
                dst_port = float(rng.choice(suspicious_ports))
            tcp_syn = 1.0 if rng.random() < 0.3 else 0.0
            tcp_ack = 1.0 if rng.random() < 0.7 else 0.0
            tcp_fin = 1.0 if rng.random() < 0.05 else 0.0
            tcp_rst = 1.0 if rng.random() < 0.02 else 0.0

        x[i] = np.array(
            [
                packet_len,
                src_port,
                dst_port,
                payload_len,
                proto_tcp,
                proto_udp,
                proto_icmp,
                tcp_syn,
                tcp_ack,
                tcp_fin,
                tcp_rst,
            ],
            dtype=np.float32,
        )

        is_suspicious_port = np.any(np.isclose(dst_port, suspicious_ports, atol=0.0005))
        is_syn_scan = proto_tcp == 1.0 and tcp_syn == 1.0 and tcp_ack == 0.0
        is_large_payload = packet_len > 0.9 and payload_len > 0.8

        label = 1.0 if (is_suspicious_port and is_syn_scan) or is_large_payload else 0.0
        if rng.random() < 0.02:
            label = 1.0 - label
        y[i] = label

    return x, y


def train_model(
    x: np.ndarray,
    y: np.ndarray,
    epochs: int,
    batch_size: int,
    test_split: float,
) -> IDSModel:
    require_tensorflow()
    rng = np.random.default_rng(42)
    idx = rng.permutation(len(x))
    x = x[idx]
    y = y[idx]

    split = int(len(x) * (1.0 - test_split))
    x_train, x_test = x[:split], x[split:]
    y_train, y_test = y[:split], y[split:]

    model = build_model(input_dim=x.shape[1])
    model.fit(x_train, y_train, validation_data=(x_test, y_test), epochs=epochs, batch_size=batch_size)
    return IDSModel(model=model, input_dim=x.shape[1])


def main() -> int:
    parser = argparse.ArgumentParser(description="Train IDS model")
    parser.add_argument("--csv", default="", help="Path to CSV training data")
    parser.add_argument("--model-out", default="models/ids_model", help="Output model path")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--test-split", type=float, default=0.2)
    parser.add_argument("--synthetic-samples", type=int, default=5000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument(
        "--export-csv",
        default="",
        help="Write a synthetic dataset CSV to this path before training",
    )
    args = parser.parse_args()

    if args.export_csv:
        export_csv(args.export_csv, args.synthetic_samples, args.seed)
        print(f"Wrote synthetic dataset to {args.export_csv}")

    if args.csv:
        x, y = load_csv(args.csv)
    else:
        x, y = generate_synthetic(args.synthetic_samples, args.seed)

    model = train_model(x, y, args.epochs, args.batch_size, args.test_split)
    os.makedirs(os.path.dirname(args.model_out) or ".", exist_ok=True)
    model.save(args.model_out)
    print(f"Saved model to {args.model_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
