from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import numpy as np

try:
    import tensorflow as tf
except Exception:  # pragma: no cover - handled at runtime
    tf = None


MODEL_INPUT_DIM = 11


def require_tensorflow() -> None:
    if tf is None:
        raise RuntimeError(
            "TensorFlow is required. Install dependencies with: pip install -r requirements.txt"
        )


def build_model(input_dim: int = MODEL_INPUT_DIM) -> "tf.keras.Model":
    require_tensorflow()
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Input(shape=(input_dim,)),
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dense(16, activation="relu"),
            tf.keras.layers.Dense(1, activation="sigmoid"),
        ]
    )
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model


@dataclass
class IDSModel:
    model: "tf.keras.Model"
    input_dim: int = MODEL_INPUT_DIM

    @classmethod
    def load(cls, path: str) -> "IDSModel":
        require_tensorflow()
        model = tf.keras.models.load_model(path)
        return cls(model=model, input_dim=model.input_shape[-1])

    def save(self, path: str) -> None:
        require_tensorflow()
        self.model.save(path)

    def predict_proba(self, features: np.ndarray) -> float:
        require_tensorflow()
        if features.ndim == 1:
            features = features.reshape(1, -1)
        preds = self.model.predict(features, verbose=0)
        return float(preds[0][0])
