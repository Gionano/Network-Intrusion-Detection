from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import numpy as np

from .feature_extraction import extract_features
from .model import IDSModel


@dataclass
class DetectionResult:
    probability: float
    is_malicious: bool
    features: np.ndarray


def detect(packet: Any, model: IDSModel, threshold: float) -> DetectionResult:
    features = extract_features(packet)
    probability = model.predict_proba(features)
    is_malicious = probability >= threshold
    return DetectionResult(probability=probability, is_malicious=is_malicious, features=features)
