"""Facade that combines rule scores with the logistic regression probability.

The published score is

    rule_score = min(1, sum of fired signal weights)
    score = rule_score                         when no model is loaded
    score = max(rule_score, P(malicious))      when a model is loaded

``max`` is deliberate. A Luhn hit, a private-key header, or an instruction
override is already on the 0–1 scale and must not be diluted by a low model
probability. The classifier can still raise the score when the rules are
silent. It cannot veto a rule. See SPEC.md.

``categories`` lists the families of the rule signals that fired, in the order
``("injection", "pii")``, and only when ``flagged`` is true. A classifier-only
flag has empty categories: the model is binary and does not name a family.
``categories`` is always empty when ``flagged`` is false.

``signals`` lists the rule signals that fired, in detector order. ``classifier``
is appended when a model is loaded and ``P(malicious) >= threshold``.
``rules_only`` is appended when the model file is missing. The two markers
never appear together.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from promptwarden.classifier import Model
from promptwarden.features import FEATURE_DIM, extract
from promptwarden.rules import detect, rule_score

_CATEGORIES = ("injection", "pii")


def bundled_model_path() -> Path:
    """Path of the model shipped inside the package."""

    return Path(__file__).resolve().with_name("default_model.json")


@dataclass(frozen=True)
class ScanResult:
    """Outcome of one scan.

    ``score`` is in ``[0, 1]``. ``flagged`` is true when ``score >= threshold``.
    ``categories`` is a subset of ``{"injection", "pii"}`` and is empty when the
    text is not flagged. ``signals`` names the rule signals that fired, plus
    ``classifier`` or ``rules_only`` as described on :class:`Warden`.
    """

    score: float
    flagged: bool
    categories: tuple[str, ...]
    signals: tuple[str, ...]

    def __post_init__(self) -> None:
        if isinstance(self.score, bool) or not isinstance(self.score, (int, float)):
            raise TypeError("score must be a float")
        score = float(self.score)
        if not math.isfinite(score) or not 0.0 <= score <= 1.0:
            raise ValueError("score must be between 0 and 1")
        object.__setattr__(self, "score", score)
        if type(self.flagged) is not bool:
            raise TypeError("flagged must be a bool")
        if self.categories not in ((), ("injection",), ("pii",), ("injection", "pii")):
            raise ValueError("categories must be a subsequence of ('injection', 'pii')")
        if self.categories and not self.flagged:
            raise ValueError("categories must be empty when flagged is false")
        if not isinstance(self.signals, tuple):
            raise TypeError("signals must be a tuple of strings")
        for name in self.signals:
            if not isinstance(name, str) or name == "":
                raise TypeError("signals must be a tuple of strings")
        if len(set(self.signals)) != len(self.signals):
            raise ValueError("signals must be unique")


class Warden:
    """Scan text for prompt injection and sensitive-data leakage.

    ``threshold`` is inclusive: a score equal to the threshold is flagged.
    Pass ``model`` to score with a fitted :class:`Model`. Pass ``model_path``
    to load one. When neither is set, the bundled model is loaded if its file
    exists. A missing file selects rules-only mode. A present file that is
    corrupt, or whose dimension does not match the feature layout, raises
    ``ValueError`` instead of failing open.
    """

    def __init__(
        self,
        threshold: float = 0.5,
        *,
        model_path: str | Path | None = None,
        model: Model | None = None,
    ) -> None:
        self.threshold = _threshold(threshold)
        if model is not None and model_path is not None:
            raise ValueError("pass model or model_path, not both")
        if model is not None:
            _require_width(model)
            self._model: Model | None = model
        elif model_path is not None:
            self._model = _load_if_present(Path(model_path))
        else:
            self._model = _load_if_present(bundled_model_path())

    @property
    def rules_only(self) -> bool:
        """True when no model is loaded and scores come from rules alone."""

        return self._model is None

    def scan(self, text: str) -> ScanResult:
        """Score ``text``. The result is deterministic for a given model."""

        if not isinstance(text, str):
            raise TypeError("text must be a string")
        fired = detect(text)
        rules = rule_score(fired)
        names = [signal.name for signal in fired]
        if self._model is None:
            names.append("rules_only")
            score = rules
        else:
            probability = self._model.predict_proba(extract(text, names))
            score = max(rules, probability)
            if probability >= self.threshold:
                names.append("classifier")
        if score < 0.0:
            score = 0.0
        elif score > 1.0:
            score = 1.0
        flagged = score >= self.threshold
        if flagged:
            families = {signal.family for signal in fired}
            categories = tuple(name for name in _CATEGORIES if name in families)
        else:
            categories = ()
        return ScanResult(
            score=score,
            flagged=flagged,
            categories=categories,
            signals=tuple(names),
        )


def _threshold(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("threshold must be a float")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ValueError("threshold must be between 0 and 1 inclusive")
    return number


def _load_if_present(path: Path) -> Model | None:
    if not path.is_file():
        return None
    model = Model.load(path)
    _require_width(model)
    return model


def _require_width(model: Model) -> None:
    if model.dim != FEATURE_DIM:
        raise ValueError(f"model has dim {model.dim}, expected {FEATURE_DIM}")
