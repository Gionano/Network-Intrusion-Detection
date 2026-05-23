"""Standalone model evaluation script.

Usage:
    python src/evaluate.py --model models/ids_model --csv data/sample_ids.csv

Produces:
    - Per-class precision / recall / F1 (console)
    - Confusion matrix PNG  (logs/confusion_matrix.png)
    - JSON evaluation report (logs/evaluation_report.json)
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Dict

import numpy as np

from ids.feature_extraction import FEATURE_NAMES
from ids.model import IDSModel, ATTACK_CLASSES, NUM_CLASSES, require_tensorflow


def load_test_data(csv_path: str):
    import pandas as pd

    df = pd.read_csv(csv_path)
    missing = [n for n in FEATURE_NAMES if n not in df.columns]
    if missing:
        raise ValueError(f"CSV missing columns: {missing}")
    if "label" not in df.columns:
        raise ValueError("CSV missing 'label' column")
    x = df[FEATURE_NAMES].astype("float32").to_numpy()
    y = df["label"].astype("int32").to_numpy()
    return x, y


def evaluate(
    model: IDSModel,
    x: np.ndarray,
    y_true: np.ndarray,
    output_dir: str = "logs",
) -> Dict:
    """Run full evaluation and return a results dict."""
    from sklearn.metrics import (
        classification_report,
        confusion_matrix,
        roc_auc_score,
    )

    require_tensorflow()

    preds = model.model.predict(x, verbose=0)
    y_pred = np.argmax(preds, axis=1)
    target_names = [ATTACK_CLASSES.get(i, f"class_{i}") for i in range(NUM_CLASSES)]

    # --- classification report ------------------------------------------------
    report_str = classification_report(
        y_true, y_pred, target_names=target_names, zero_division=0
    )
    report_dict = classification_report(
        y_true, y_pred, target_names=target_names, output_dict=True, zero_division=0
    )
    print("\n=== Classification Report ===")
    print(report_str)

    # --- confusion matrix -----------------------------------------------------
    cm = confusion_matrix(y_true, y_pred, labels=list(range(NUM_CLASSES)))
    print("=== Confusion Matrix ===")
    print(cm)

    os.makedirs(output_dir, exist_ok=True)
    _plot_confusion_matrix(cm, target_names, output_dir)

    # --- ROC-AUC (one-vs-rest) ------------------------------------------------
    auc_scores: Dict[str, float] = {}
    try:
        for i, name in enumerate(target_names):
            y_bin = (y_true == i).astype(int)
            if y_bin.sum() == 0 or y_bin.sum() == len(y_bin):
                auc_scores[name] = float("nan")
            else:
                auc_scores[name] = float(roc_auc_score(y_bin, preds[:, i]))
        avg_auc = float(np.nanmean(list(auc_scores.values())))
    except Exception:
        avg_auc = float("nan")

    print(f"\n=== ROC-AUC (one-vs-rest) ===")
    for name, score in auc_scores.items():
        print(f"  {name}: {score:.4f}")
    print(f"  Average: {avg_auc:.4f}")

    # --- JSON report ----------------------------------------------------------
    results = {
        "classification_report": report_dict,
        "confusion_matrix": cm.tolist(),
        "roc_auc": auc_scores,
        "roc_auc_average": avg_auc,
        "num_samples": len(y_true),
        "num_classes": NUM_CLASSES,
    }

    report_path = os.path.join(output_dir, "evaluation_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\nReport saved to {report_path}")

    return results


def _plot_confusion_matrix(cm, labels, output_dir):
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("Install matplotlib for confusion matrix plot: pip install matplotlib")
        return

    fig, ax = plt.subplots(figsize=(8, 6))
    im = ax.imshow(cm, interpolation="nearest", cmap="Blues")
    ax.figure.colorbar(im, ax=ax)
    ax.set(
        xticks=range(len(labels)),
        yticks=range(len(labels)),
        xticklabels=labels,
        yticklabels=labels,
        ylabel="True label",
        xlabel="Predicted label",
        title="Confusion Matrix",
    )
    plt.setp(ax.get_xticklabels(), rotation=45, ha="right")

    # Text annotations
    thresh = cm.max() / 2.0
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(
                j, i, format(cm[i, j], "d"),
                ha="center", va="center",
                color="white" if cm[i, j] > thresh else "black",
            )

    fig.tight_layout()
    path = os.path.join(output_dir, "confusion_matrix.png")
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Confusion matrix saved to {path}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate IDS model")
    parser.add_argument("--model", required=True, help="Path to saved model directory")
    parser.add_argument("--csv", required=True, help="Path to test CSV")
    parser.add_argument("--output-dir", default="logs", help="Directory for outputs")
    args = parser.parse_args()

    model = IDSModel.load(args.model)
    x, y = load_test_data(args.csv)
    print(f"Evaluating on {len(x)} samples")
    evaluate(model, x, y, args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
