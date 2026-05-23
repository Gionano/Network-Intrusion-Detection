from __future__ import annotations

import argparse
import os
from typing import Tuple

import numpy as np
import pandas as pd

from ids.feature_extraction import FEATURE_NAMES, NUM_FEATURES
from ids.model import (
    IDSModel,
    ATTACK_CLASSES,
    NUM_CLASSES,
    build_model,
    get_callbacks,
    require_tensorflow,
)


# ---------------------------------------------------------------------------
# CSV I/O
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Synthetic data generation (multi-class, 30 features)
# ---------------------------------------------------------------------------

def generate_synthetic(samples: int, seed: int) -> Tuple[np.ndarray, np.ndarray]:
    """Generate synthetic IDS training data with 5 attack classes.

    Classes:
        0 = Normal
        1 = Port Scan  (SYN packets to suspicious ports, many destinations)
        2 = DDoS       (high packet rate, large payloads, floods)
        3 = Brute Force (repeated connections to auth ports)
        4 = Exfiltration(large outbound payloads, high entropy)
    """
    rng = np.random.default_rng(seed)
    x = np.zeros((samples, NUM_FEATURES), dtype=np.float32)
    y = np.zeros(samples, dtype=np.float32)

    suspicious_ports = np.array([23, 445, 3389, 5900], dtype=np.float32) / 65535.0
    auth_ports = np.array([22, 23, 3389, 21, 110, 143], dtype=np.float32) / 65535.0

    for i in range(samples):
        # Decide class first (weighted: 60% normal, 10% each attack)
        attack_type = rng.choice(5, p=[0.60, 0.10, 0.10, 0.10, 0.10])

        if attack_type == 0:
            vec = _gen_normal(rng)
        elif attack_type == 1:
            vec = _gen_port_scan(rng, suspicious_ports)
        elif attack_type == 2:
            vec = _gen_ddos(rng)
        elif attack_type == 3:
            vec = _gen_brute_force(rng, auth_ports)
        else:
            vec = _gen_exfiltration(rng)

        x[i] = vec
        y[i] = float(attack_type)

        # 2% label noise
        if rng.random() < 0.02:
            y[i] = float(rng.choice(NUM_CLASSES))

    return x, y


def _gen_normal(rng) -> np.ndarray:
    proto = rng.choice(["tcp", "udp", "icmp"], p=[0.6, 0.3, 0.1])
    pkt_len = rng.uniform(0.05, 0.7)
    src_port = rng.uniform(0.3, 1.0)  # ephemeral
    dst_port = rng.uniform(0.0, 1.0)
    payload_len = rng.uniform(0.0, 0.5)
    return _build_vector(rng, proto, pkt_len, src_port, dst_port, payload_len,
                         entropy=rng.uniform(0.1, 0.5),
                         flow_dur=rng.uniform(0.01, 0.3),
                         flow_rate=rng.uniform(0.0, 0.05),
                         fwd_count=rng.uniform(0.0, 0.05),
                         bwd_count=rng.uniform(0.0, 0.05))


def _gen_port_scan(rng, suspicious_ports) -> np.ndarray:
    pkt_len = rng.uniform(0.02, 0.15)  # small SYN packets
    src_port = rng.uniform(0.5, 1.0)
    dst_port = float(rng.choice(suspicious_ports)) if rng.random() < 0.6 else rng.uniform(0.0, 1.0)
    return _build_vector(rng, "tcp", pkt_len, src_port, dst_port, rng.uniform(0.0, 0.1),
                         syn=1.0, ack=0.0,
                         entropy=rng.uniform(0.0, 0.2),
                         flow_dur=rng.uniform(0.0, 0.05),
                         flow_rate=rng.uniform(0.3, 0.8),
                         fwd_count=rng.uniform(0.1, 0.5),
                         bwd_count=rng.uniform(0.0, 0.02))


def _gen_ddos(rng) -> np.ndarray:
    proto = rng.choice(["tcp", "udp", "icmp"], p=[0.4, 0.4, 0.2])
    pkt_len = rng.uniform(0.5, 1.0)  # large packets
    payload_len = rng.uniform(0.6, 1.0)
    return _build_vector(rng, proto, pkt_len, rng.uniform(0.0, 1.0), rng.uniform(0.0, 0.3), payload_len,
                         syn=1.0 if proto == "tcp" and rng.random() < 0.7 else 0.0,
                         entropy=rng.uniform(0.3, 0.7),
                         flow_dur=rng.uniform(0.01, 0.1),
                         flow_rate=rng.uniform(0.6, 1.0),
                         fwd_count=rng.uniform(0.3, 0.8),
                         bwd_count=rng.uniform(0.0, 0.1))


def _gen_brute_force(rng, auth_ports) -> np.ndarray:
    pkt_len = rng.uniform(0.1, 0.4)
    dst_port = float(rng.choice(auth_ports))
    return _build_vector(rng, "tcp", pkt_len, rng.uniform(0.5, 1.0), dst_port, rng.uniform(0.1, 0.4),
                         syn=1.0 if rng.random() < 0.5 else 0.0,
                         ack=1.0 if rng.random() < 0.6 else 0.0,
                         psh=1.0 if rng.random() < 0.4 else 0.0,
                         entropy=rng.uniform(0.2, 0.5),
                         flow_dur=rng.uniform(0.05, 0.3),
                         flow_rate=rng.uniform(0.2, 0.6),
                         fwd_count=rng.uniform(0.1, 0.4),
                         bwd_count=rng.uniform(0.1, 0.4))


def _gen_exfiltration(rng) -> np.ndarray:
    pkt_len = rng.uniform(0.7, 1.0)  # large outbound
    payload_len = rng.uniform(0.7, 1.0)
    return _build_vector(rng, "tcp", pkt_len, rng.uniform(0.5, 1.0), rng.uniform(0.0, 0.2), payload_len,
                         ack=1.0, psh=1.0,
                         entropy=rng.uniform(0.7, 1.0),  # high entropy = encrypted/compressed
                         flow_dur=rng.uniform(0.1, 0.5),
                         flow_rate=rng.uniform(0.1, 0.5),
                         fwd_count=rng.uniform(0.2, 0.6),
                         bwd_count=rng.uniform(0.01, 0.1))


def _build_vector(
    rng,
    proto: str,
    pkt_len: float,
    src_port: float,
    dst_port: float,
    payload_len: float,
    *,
    syn: float = -1, ack: float = -1, fin: float = -1, rst: float = -1,
    psh: float = -1, urg: float = -1,
    entropy: float = 0.3,
    flow_dur: float = 0.1,
    flow_rate: float = 0.05,
    fwd_count: float = 0.02,
    bwd_count: float = 0.02,
) -> np.ndarray:
    proto_tcp = 1.0 if proto == "tcp" else 0.0
    proto_udp = 1.0 if proto == "udp" else 0.0
    proto_icmp = 1.0 if proto == "icmp" else 0.0

    # TCP flags: if -1 → randomise based on proto
    if proto == "tcp":
        tcp_syn = syn if syn >= 0 else (1.0 if rng.random() < 0.3 else 0.0)
        tcp_ack = ack if ack >= 0 else (1.0 if rng.random() < 0.7 else 0.0)
        tcp_fin = fin if fin >= 0 else (1.0 if rng.random() < 0.05 else 0.0)
        tcp_rst = rst if rst >= 0 else (1.0 if rng.random() < 0.02 else 0.0)
        tcp_psh = psh if psh >= 0 else (1.0 if rng.random() < 0.2 else 0.0)
        tcp_urg = urg if urg >= 0 else (1.0 if rng.random() < 0.01 else 0.0)
        tcp_window = rng.uniform(0.1, 1.0)
    else:
        tcp_syn = tcp_ack = tcp_fin = tcp_rst = tcp_psh = tcp_urg = 0.0
        tcp_window = 0.0

    ip_ttl = rng.uniform(0.2, 1.0)
    ip_hdr_len = rng.uniform(0.3, 0.5)  # typically 20/60 = 0.33
    mean_byte = rng.uniform(0.2, 0.8)

    # DNS / HTTP heuristic
    is_dns = 1.0 if abs(dst_port - 53 / 65535.0) < 0.001 else 0.0
    is_http = 1.0 if abs(dst_port - 80 / 65535.0) < 0.002 or abs(dst_port - 443 / 65535.0) < 0.002 else 0.0

    # Flow-level features
    fwd_bwd_ratio = fwd_count / max(bwd_count, 0.001)
    iat_mean = rng.uniform(0.0, 0.2)
    iat_std = rng.uniform(0.0, 0.1)
    iat_min = rng.uniform(0.0, iat_mean)
    iat_max = rng.uniform(iat_mean, min(iat_mean + 0.3, 1.0))

    return np.array([
        pkt_len, src_port, dst_port, payload_len,
        proto_tcp, proto_udp, proto_icmp,
        tcp_syn, tcp_ack, tcp_fin, tcp_rst,
        tcp_psh, tcp_urg, tcp_window,
        ip_ttl, ip_hdr_len,
        entropy, mean_byte,
        is_dns, is_http,
        flow_dur, flow_rate * 0.1,  # scale to match normalised range
        flow_rate,
        fwd_count, bwd_count, min(fwd_bwd_ratio, 1.0),
        iat_mean, iat_std, iat_min, iat_max,
    ], dtype=np.float32)


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def compute_class_weights(y: np.ndarray) -> dict:
    """Compute class weights inversely proportional to frequency."""
    classes, counts = np.unique(y.astype(int), return_counts=True)
    total = len(y)
    weights = {}
    for cls, cnt in zip(classes, counts):
        weights[int(cls)] = total / (len(classes) * cnt)
    return weights


def train_model(
    x: np.ndarray,
    y: np.ndarray,
    epochs: int,
    batch_size: int,
    test_split: float,
    learning_rate: float = 1e-3,
    patience: int = 5,
) -> Tuple[IDSModel, np.ndarray, np.ndarray, np.ndarray, np.ndarray]:
    """Train the IDS model and return (model, x_train, y_train, x_test, y_test)."""
    require_tensorflow()
    rng = np.random.default_rng(42)
    idx = rng.permutation(len(x))
    x = x[idx]
    y = y[idx]

    split = int(len(x) * (1.0 - test_split))
    x_train, x_test = x[:split], x[split:]
    y_train, y_test = y[:split], y[split:]

    class_weights = compute_class_weights(y_train)
    print(f"Class weights: {class_weights}")

    model = build_model(input_dim=x.shape[1], learning_rate=learning_rate)
    callbacks = get_callbacks(patience=patience)

    model.fit(
        x_train,
        y_train,
        validation_data=(x_test, y_test),
        epochs=epochs,
        batch_size=batch_size,
        class_weight=class_weights,
        callbacks=callbacks,
    )

    return IDSModel(model=model, input_dim=x.shape[1]), x_train, y_train, x_test, y_test


def evaluate_split(
    model: IDSModel, x_test: np.ndarray, y_test: np.ndarray
) -> None:
    """Print a classification report for the held-out test set."""
    try:
        from sklearn.metrics import classification_report
    except ImportError:
        print("Install scikit-learn for detailed evaluation: pip install scikit-learn")
        return

    require_tensorflow()
    preds = model.model.predict(x_test, verbose=0)
    y_pred = np.argmax(preds, axis=1)
    target_names = [ATTACK_CLASSES.get(i, f"class_{i}") for i in range(NUM_CLASSES)]
    print("\n=== Classification Report ===")
    print(classification_report(y_test.astype(int), y_pred, target_names=target_names, zero_division=0))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Train IDS model")
    parser.add_argument("--csv", default="", help="Path to CSV training data")
    parser.add_argument("--model-out", default="models/ids_model", help="Output model path")
    parser.add_argument("--epochs", type=int, default=30)
    parser.add_argument("--batch-size", type=int, default=64)
    parser.add_argument("--test-split", type=float, default=0.2)
    parser.add_argument("--synthetic-samples", type=int, default=10000)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--lr", type=float, default=1e-3, help="Learning rate")
    parser.add_argument("--patience", type=int, default=5, help="Early stopping patience")
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

    print(f"Training on {len(x)} samples with {NUM_FEATURES} features, {NUM_CLASSES} classes")
    model, x_train, y_train, x_test, y_test = train_model(
        x, y, args.epochs, args.batch_size, args.test_split,
        learning_rate=args.lr, patience=args.patience,
    )

    # Auto-evaluate on held-out split
    evaluate_split(model, x_test, y_test)

    os.makedirs(os.path.dirname(args.model_out) or ".", exist_ok=True)
    model.save(args.model_out)
    print(f"Saved model to {args.model_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
