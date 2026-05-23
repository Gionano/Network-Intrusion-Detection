from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional

import numpy as np

try:
    import tensorflow as tf
except Exception:  # pragma: no cover - handled at runtime
    tf = None

from .feature_extraction import NUM_FEATURES

MODEL_INPUT_DIM = NUM_FEATURES  # dynamically matches feature vector length

NUM_CLASSES = 5
ATTACK_CLASSES: Dict[int, str] = {
    0: "Normal",
    1: "Port Scan",
    2: "DDoS",
    3: "Brute Force",
    4: "Exfiltration",
}


def require_tensorflow() -> None:
    if tf is None:
        raise RuntimeError(
            "TensorFlow is required. Install dependencies with: pip install -r requirements.txt"
        )


def build_model(
    input_dim: int = MODEL_INPUT_DIM,
    num_classes: int = NUM_CLASSES,
    learning_rate: float = 1e-3,
) -> "tf.keras.Model":
    """Build an improved multi-class IDS classifier.

    Architecture:
        Input → Dense(128) → BatchNorm → Dropout(0.3)
              → Dense(64)  → BatchNorm → Dropout(0.3)
              → Dense(32)  → Dense(num_classes, softmax)
    """
    require_tensorflow()

    model = tf.keras.Sequential(
        [
            tf.keras.layers.Input(shape=(input_dim,)),
            tf.keras.layers.Dense(128, activation="relu"),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation="relu"),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dense(num_classes, activation="softmax"),
        ]
    )

    model.compile(
        optimizer=tf.keras.optimizers.Adam(learning_rate=learning_rate),
        loss="sparse_categorical_crossentropy",
        metrics=["accuracy"],
    )
    return model


def get_callbacks(patience: int = 5) -> List:
    """Return standard training callbacks (early stopping + LR reduction)."""
    require_tensorflow()
    return [
        tf.keras.callbacks.EarlyStopping(
            monitor="val_loss",
            patience=patience,
            restore_best_weights=True,
            verbose=1,
        ),
        tf.keras.callbacks.ReduceLROnPlateau(
            monitor="val_loss",
            factor=0.5,
            patience=max(2, patience // 2),
            min_lr=1e-6,
            verbose=1,
        ),
    ]


@dataclass
class IDSModel:
    model: "tf.keras.Model"
    input_dim: int = MODEL_INPUT_DIM
    num_classes: int = NUM_CLASSES

    @classmethod
    def load(cls, path: str) -> "IDSModel":
        require_tensorflow()
        model = tf.keras.models.load_model(path)
        input_dim = model.input_shape[-1]
        num_classes = model.output_shape[-1]
        return cls(model=model, input_dim=input_dim, num_classes=num_classes)

    def save(self, path: str) -> None:
        require_tensorflow()
        self.model.save(path)

    def predict(self, features: np.ndarray) -> tuple:
        """Return (predicted_class_index, class_probabilities_dict).

        Parameters
        ----------
        features:
            1-D or 2-D float32 feature array.

        Returns
        -------
        (int, dict)
            ``predicted_class`` and a dict mapping class names to probabilities.
        """
        require_tensorflow()
        if features.ndim == 1:
            features = features.reshape(1, -1)
        probs = self.model.predict(features, verbose=0)[0]
        predicted_class = int(np.argmax(probs))
        prob_dict = {
            ATTACK_CLASSES.get(i, f"class_{i}"): float(p) for i, p in enumerate(probs)
        }
        return predicted_class, prob_dict

    # Backward-compatible convenience method
    def predict_proba(self, features: np.ndarray) -> float:
        """Return the probability of the *most likely* class (legacy helper)."""
        _, prob_dict = self.predict(features)
        return max(prob_dict.values())
