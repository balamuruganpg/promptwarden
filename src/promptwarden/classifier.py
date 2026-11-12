"""Full-batch L2 logistic regression with no randomness.

Weights and the intercept start at 0. Each epoch uses every example, in the
order given, with no shuffle. The objective is the mean Bernoulli log loss
plus ``(l2 / 2) * ||w||^2``. The intercept is not penalised. The gradient step
is the usual full-batch update:

    w <- w - lr * (mean((p - y) x) + l2 * w)
    b <- b - lr * mean(p - y)

There is no RNG and no data-dependent early stop, so the same examples and the
same hyperparameters always produce the same weights.

:func:`train` raises ``ValueError`` when there are fewer than
:data:`MIN_EXAMPLES` rows or when every label is the same class.
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from promptwarden.features import FEATURE_DIM, NGRAM_DIM
from promptwarden.rules import SIGNAL_NAMES

MIN_EXAMPLES = 20
DEFAULT_LEARNING_RATE = 1.0
DEFAULT_EPOCHS = 400
DEFAULT_L2 = 0.01
FORMAT = "promptwarden-model-v1"
_LOGIT_CLIP = 30.0


@dataclass(frozen=True)
class Model:
    """A fitted binary logistic regression. ``predict_proba`` is P(label = 1)."""

    weights: tuple[float, ...]
    bias: float
    learning_rate: float
    epochs: int
    l2: float

    @property
    def dim(self) -> int:
        return len(self.weights)

    def predict_proba(self, features: Sequence[float]) -> float:
        """Probability that the row is the positive class."""

        if len(features) != self.dim:
            raise ValueError(f"expected {self.dim} features, got {len(features)}")
        logit = self.bias
        for weight, value in zip(self.weights, features, strict=True):
            number = _finite_feature(value)
            if number:
                logit += weight * number
        if not math.isfinite(logit):
            raise ValueError("logit is not finite")
        return _sigmoid(logit)

    def save(self, path: str | Path) -> None:
        """Write this model as JSON. Parent directories must already exist."""

        destination = Path(path)
        payload: dict[str, object] = {
            "bias": _format_float(self.bias),
            "epochs": self.epochs,
            "format": FORMAT,
            "l2": _format_float(self.l2),
            "learning_rate": _format_float(self.learning_rate),
            "weights": [_format_float(weight) for weight in self.weights],
        }
        # Full-width guardrail models record the feature schema so a later
        # code change cannot silently score a vector against the wrong layout.
        if self.dim == FEATURE_DIM:
            payload["ngram_dim"] = NGRAM_DIM
            payload["signals"] = list(SIGNAL_NAMES)
        destination.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def load(cls, path: str | Path) -> Model:
        """Load a model written by :meth:`save`."""

        source = Path(path)
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"model file {source} is not valid JSON") from exc
        if not isinstance(raw, dict):
            raise ValueError("model file must be a JSON object")
        if raw.get("format") != FORMAT:
            raise ValueError(f"unsupported model format {raw.get('format')!r}")
        weights = tuple(_load_float(item) for item in _require_list(raw, "weights"))
        if not weights:
            raise ValueError("model weights must be non-empty")
        model = cls(
            weights=weights,
            bias=_load_float(raw.get("bias")),
            learning_rate=_load_float(raw.get("learning_rate")),
            epochs=_require_epochs(raw.get("epochs")),
            l2=_load_float(raw.get("l2")),
        )
        _check_schema(raw, model.dim)
        return model


def train(
    examples: Sequence[tuple[Sequence[float], int]],
    *,
    learning_rate: float = DEFAULT_LEARNING_RATE,
    epochs: int = DEFAULT_EPOCHS,
    l2: float = DEFAULT_L2,
) -> Model:
    """Fit a model on ``(features, label)`` rows. Labels are ``0`` or ``1``."""

    if isinstance(examples, (str, bytes)):
        raise ValueError("examples must be a sequence of (features, label) rows")
    step = _positive("learning_rate", learning_rate)
    n_epochs = _require_epochs(epochs)
    penalty = _non_negative("l2", l2)
    rows = [_copy_row(features, label) for features, label in examples]
    if len(rows) < MIN_EXAMPLES:
        raise ValueError(f"need at least {MIN_EXAMPLES} examples to train; got {len(rows)}")
    labels = {label for _, label in rows}
    if len(labels) < 2:
        only = next(iter(labels))
        raise ValueError(f"need at least two classes to train; every example has label {only}")
    width = len(rows[0][0])
    for features, _label in rows:
        if len(features) != width:
            raise ValueError("feature rows must have the same length")
    weights = [0.0] * width
    bias = 0.0
    count = float(len(rows))
    for _ in range(n_epochs):
        grad_w = [0.0] * width
        grad_b = 0.0
        for features, label in rows:
            probability = _sigmoid(_dot(weights, features, bias))
            error = probability - float(label)
            for index, value in enumerate(features):
                if value:
                    grad_w[index] += error * value
            grad_b += error
        for index in range(width):
            weights[index] -= step * (grad_w[index] / count + penalty * weights[index])
        bias -= step * (grad_b / count)
    if not math.isfinite(bias):
        raise ValueError("logistic regression produced a non-finite intercept")
    for weight in weights:
        if not math.isfinite(weight):
            raise ValueError("logistic regression produced a non-finite coefficient")
    return Model(
        weights=tuple(weights),
        bias=bias,
        learning_rate=step,
        epochs=n_epochs,
        l2=penalty,
    )


def _dot(weights: Sequence[float], features: Sequence[float], bias: float) -> float:
    total = bias
    for weight, value in zip(weights, features, strict=True):
        if value:
            total += weight * value
    return total


def _sigmoid(value: float) -> float:
    if value >= _LOGIT_CLIP:
        return 1.0
    if value <= -_LOGIT_CLIP:
        return 0.0
    if value >= 0.0:
        z = math.exp(-value)
        return 1.0 / (1.0 + z)
    z = math.exp(value)
    return z / (1.0 + z)


def _copy_row(features: Sequence[float], label: object) -> tuple[tuple[float, ...], int]:
    if isinstance(features, (str, bytes)):
        raise ValueError("feature row must be a sequence of numbers")
    if isinstance(label, bool) or not isinstance(label, int) or label not in (0, 1):
        raise ValueError("label must be 0 or 1")
    copied = tuple(_finite_feature(value) for value in features)
    if not copied:
        raise ValueError("feature row must be non-empty")
    return copied, label


def _finite_feature(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("features must be finite numbers")
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("features must be finite numbers")
    return number


def _positive(name: str, value: object) -> float:
    number = _load_float(value)
    if number <= 0.0:
        raise ValueError(f"{name} must be > 0")
    return number


def _non_negative(name: str, value: object) -> float:
    number = _load_float(value)
    if number < 0.0:
        raise ValueError(f"{name} must be >= 0")
    return number


def _require_epochs(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("epochs must be a positive integer")
    if value < 1:
        raise ValueError("epochs must be a positive integer")
    return value


def _require_list(raw: Mapping[str, object], key: str) -> list[object]:
    value = raw.get(key)
    if not isinstance(value, list) or not value:
        raise ValueError(f"{key} must be a non-empty list")
    return value


def _load_float(value: object) -> float:
    if isinstance(value, str):
        try:
            number = float(value)
        except ValueError as exc:
            raise ValueError("expected a finite number") from exc
    elif isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("expected a finite number")
    else:
        number = float(value)
    if not math.isfinite(number):
        raise ValueError("expected a finite number")
    return number


def _format_float(value: float) -> str:
    return format(value, ".17g")


def _check_schema(raw: Mapping[str, object], dim: int) -> None:
    has_ngram = "ngram_dim" in raw
    has_signals = "signals" in raw
    if dim == FEATURE_DIM and (not has_ngram or not has_signals):
        raise ValueError("full-width model is missing the feature schema")
    if not has_ngram and not has_signals:
        return
    if dim != FEATURE_DIM:
        raise ValueError("model schema does not match the weight vector length")
    if raw.get("ngram_dim") != NGRAM_DIM:
        raise ValueError(f"model ngram_dim {raw.get('ngram_dim')!r} does not match {NGRAM_DIM}")
    if _signal_names(raw.get("signals")) != SIGNAL_NAMES:
        raise ValueError("model signal list does not match SIGNAL_NAMES")


def _signal_names(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list):
        return None
    names: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return None
        names.append(item)
    return tuple(names)
