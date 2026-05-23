from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict

import numpy as np

from .feature_extraction import extract_features
from .model import IDSModel, ATTACK_CLASSES


@dataclass
class DetectionResult:
    """Result of running a packet through the IDS model."""

    predicted_class: int
    attack_class: str
    confidence: float
    class_probabilities: Dict[str, float]
    is_malicious: bool
    features: np.ndarray


def detect(
    packet: Any,
    model: IDSModel,
    threshold: float,
    flow_stats: Any = None,
) -> DetectionResult:
    """Run the detection pipeline on a single packet.

    Parameters
    ----------
    packet:
        Scapy packet.
    model:
        Loaded IDSModel.
    threshold:
        Confidence threshold above which a non-Normal class is flagged.
    flow_stats:
        Optional FlowStats from the flow tracker.

    Returns
    -------
    DetectionResult
    """
    features = extract_features(packet, flow_stats)
    predicted_class, prob_dict = model.predict(features)
    attack_class = ATTACK_CLASSES.get(predicted_class, f"class_{predicted_class}")
    confidence = prob_dict.get(attack_class, 0.0)

    # Malicious = any non-Normal prediction above threshold
    is_malicious = predicted_class != 0 and confidence >= threshold

    return DetectionResult(
        predicted_class=predicted_class,
        attack_class=attack_class,
        confidence=confidence,
        class_probabilities=prob_dict,
        is_malicious=is_malicious,
        features=features,
    )
