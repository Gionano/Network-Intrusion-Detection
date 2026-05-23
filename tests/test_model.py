"""Tests for ids.model module."""

from __future__ import annotations

import os
import numpy as np
import pytest

from ids.model import (
    ATTACK_CLASSES,
    NUM_CLASSES,
    IDSModel,
    build_model,
    get_callbacks,
    require_tensorflow,
)
from ids.feature_extraction import NUM_FEATURES


class TestBuildModel:
    def test_output_shape(self):
        model = build_model(input_dim=NUM_FEATURES, num_classes=NUM_CLASSES)
        assert model.output_shape == (None, NUM_CLASSES)

    def test_input_shape(self):
        model = build_model(input_dim=NUM_FEATURES)
        assert model.input_shape == (None, NUM_FEATURES)

    def test_custom_dims(self):
        model = build_model(input_dim=10, num_classes=3)
        assert model.input_shape == (None, 10)
        assert model.output_shape == (None, 3)


class TestIDSModel:
    @pytest.fixture
    def trained_model(self):
        model = build_model(input_dim=NUM_FEATURES)
        return IDSModel(model=model, input_dim=NUM_FEATURES)

    def test_predict_returns_tuple(self, trained_model, sample_features):
        cls, probs = trained_model.predict(sample_features)
        assert isinstance(cls, int)
        assert isinstance(probs, dict)
        assert 0 <= cls < NUM_CLASSES

    def test_predict_probs_sum_to_one(self, trained_model, sample_features):
        _, probs = trained_model.predict(sample_features)
        total = sum(probs.values())
        assert total == pytest.approx(1.0, abs=0.01)

    def test_predict_proba_compat(self, trained_model, sample_features):
        p = trained_model.predict_proba(sample_features)
        assert 0.0 <= p <= 1.0

    def test_save_load_roundtrip(self, trained_model, sample_features, tmp_path):
        path = str(tmp_path / "test_model")
        trained_model.save(path)
        assert os.path.exists(path)

        loaded = IDSModel.load(path)
        cls1, _ = trained_model.predict(sample_features)
        cls2, _ = loaded.predict(sample_features)
        assert cls1 == cls2

    def test_predict_batch(self, trained_model):
        batch = np.random.rand(5, NUM_FEATURES).astype(np.float32)
        # predict handles 1D only, so test each
        for row in batch:
            cls, probs = trained_model.predict(row)
            assert 0 <= cls < NUM_CLASSES


class TestCallbacks:
    def test_returns_list(self):
        cbs = get_callbacks(patience=3)
        assert isinstance(cbs, list)
        assert len(cbs) == 2  # EarlyStopping + ReduceLROnPlateau


class TestAttackClasses:
    def test_all_classes_present(self):
        assert len(ATTACK_CLASSES) == NUM_CLASSES
        for i in range(NUM_CLASSES):
            assert i in ATTACK_CLASSES
