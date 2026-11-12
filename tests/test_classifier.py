"""Logistic regression: refusal, determinism, and JSON round-trip."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from promptwarden.classifier import FORMAT, MIN_EXAMPLES, Model, train


def _rows() -> list[tuple[list[float], int]]:
    rows: list[tuple[list[float], int]] = []
    for index in range(24):
        features = [0.0, 0.0, 0.0, 0.0]
        features[index % 4] = 1.0
        rows.append((features, 1 if index % 2 == 0 else 0))
    return rows


def test_train_refuses_too_few_rows() -> None:
    rows = [([1.0], index % 2) for index in range(MIN_EXAMPLES - 1)]
    assert len(rows) == MIN_EXAMPLES - 1
    with pytest.raises(ValueError, match="at least 20"):
        train(rows)


def test_train_refuses_a_single_class() -> None:
    with pytest.raises(ValueError, match="two classes"):
        train([([1.0], 1)] * MIN_EXAMPLES)
    with pytest.raises(ValueError, match="two classes"):
        train([([0.0], 0)] * MIN_EXAMPLES)


def test_same_rows_produce_the_same_weights() -> None:
    first = train(_rows())
    second = train(_rows())
    assert first.weights == second.weights
    assert first.bias == second.bias
    assert first.predict_proba(_rows()[0][0]) == second.predict_proba(_rows()[0][0])


def test_separable_rows_rank_the_positive_class_higher() -> None:
    rows: list[tuple[list[float], int]] = [([1.0], 1)] * 20 + [([0.0], 0)] * 20
    model = train(rows, epochs=80)
    assert model.predict_proba([1.0]) > model.predict_proba([0.0])
    assert 0.0 <= model.predict_proba([1.0]) <= 1.0
    assert 0.0 <= model.predict_proba([0.0]) <= 1.0


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    destination = tmp_path / "model.json"
    model = train(_rows())
    model.save(destination)
    loaded = Model.load(destination)
    assert loaded.weights == model.weights
    assert loaded.bias == model.bias
    assert loaded.learning_rate == model.learning_rate
    assert loaded.epochs == model.epochs
    assert loaded.l2 == model.l2
    features = _rows()[0][0]
    assert loaded.predict_proba(features) == model.predict_proba(features)
    payload = json.loads(destination.read_text(encoding="utf-8"))
    assert payload["format"] == FORMAT


def test_train_rejects_bad_rows() -> None:
    with pytest.raises(ValueError, match="0 or 1"):
        train([([1.0], 2)] * MIN_EXAMPLES)
    with pytest.raises(ValueError, match="0 or 1"):
        train([([1.0], True)] * 10 + [([0.0], False)] * 10)  # type: ignore[list-item]
    with pytest.raises(ValueError, match="same length"):
        train([([1.0, 0.0], 1)] * 10 + [([0.0], 0)] * 10)
    model = train(_rows(), epochs=5)
    with pytest.raises(ValueError, match="features"):
        model.predict_proba([0.0])


def test_load_rejects_a_bad_file(tmp_path: Path) -> None:
    source = tmp_path / "model.json"
    source.write_text("{", encoding="utf-8")
    with pytest.raises(ValueError, match="not valid JSON"):
        Model.load(source)
    source.write_text(json.dumps({"format": "other"}), encoding="utf-8")
    with pytest.raises(ValueError, match="unsupported model format"):
        Model.load(source)
    source.write_text(
        json.dumps(
            {
                "format": FORMAT,
                "weights": [],
                "bias": 0,
                "learning_rate": 1,
                "epochs": 1,
                "l2": 0,
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(ValueError):
        Model.load(source)
