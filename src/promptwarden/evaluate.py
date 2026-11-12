"""Corpus loading and the honest eval protocol.

Corpus rows are JSON objects, one per line:

    {"text": str, "label": "malicious" | "benign", "category": "injection" | "pii" | "benign"}

An optional ``split`` field of ``"train"`` or ``"test"`` may be set on every
row. If any row has it, every row must have it.

``promptwarden eval`` scores the positive class ``malicious``:

* when the corpus has ``split``, a model is trained on the train rows and the
  metrics are computed on the test rows only;
* otherwise the rows are split into 5 deterministic folds, ``index % 5``.
  Each fold trains on the other rows, in file order, and scores the held-out
  rows. Metrics are pooled: each row is scored once.

Predictions are :meth:`promptwarden.warden.Warden.scan` flags at the requested
threshold, so the numbers include the rules, not the classifier alone.
``promptwarden train`` is separate: it fits every row in the file and does not
look at ``split``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from promptwarden.classifier import MIN_EXAMPLES, Model, train
from promptwarden.features import extract
from promptwarden.rules import detect
from promptwarden.warden import Warden

_LABELS = frozenset({"malicious", "benign"})
_CATEGORIES = frozenset({"injection", "pii", "benign"})
_SPLITS = frozenset({"train", "test"})
FOLDS = 5


@dataclass(frozen=True)
class Example:
    """One labeled corpus row."""

    text: str
    label: str
    category: str
    split: str | None = None

    @property
    def y(self) -> int:
        """1 for malicious, 0 for benign."""

        return 1 if self.label == "malicious" else 0


@dataclass(frozen=True)
class EvalReport:
    """Pooled classification metrics. Rates are 0 when the denominator is 0."""

    precision: float
    recall: float
    f1: float
    fpr: float
    tp: int
    fp: int
    tn: int
    fn: int
    n: int
    method: str

    def as_text(self) -> str:
        """Stable multi-line report used by the CLI."""

        return (
            f"method: {self.method}\n"
            f"n: {self.n}\n"
            f"tp: {self.tp}\n"
            f"fp: {self.fp}\n"
            f"tn: {self.tn}\n"
            f"fn: {self.fn}\n"
            f"precision: {self.precision:.6f}\n"
            f"recall: {self.recall:.6f}\n"
            f"f1: {self.f1:.6f}\n"
            f"fpr: {self.fpr:.6f}\n"
        )


def load_corpus(path: str | Path) -> list[Example]:
    """Load a JSONL corpus. Blank lines are ignored. Errors name the line."""

    source = Path(path)
    examples: list[Example] = []
    text = source.read_text(encoding="utf-8")
    for number, line in enumerate(text.splitlines(), start=1):
        if line.strip() == "":
            continue
        examples.append(_parse_row(line, number))
    if not examples:
        raise ValueError(f"corpus {source} has no rows")
    splits = [example.split for example in examples]
    if any(split is not None for split in splits) and any(split is None for split in splits):
        raise ValueError("every corpus row must include split, or none of them")
    return examples


def fit_examples(examples: Sequence[Example]) -> Model:
    """Train on ``examples`` in order, using the public feature layout."""

    rows: list[tuple[list[float], int]] = []
    for example in examples:
        fired = detect(example.text)
        rows.append((extract(example.text, [signal.name for signal in fired]), example.y))
    return train(rows)


def evaluate_corpus(path: str | Path, *, threshold: float = 0.5) -> EvalReport:
    """Evaluate a corpus file. See the module docstring for the protocol."""

    return evaluate_examples(load_corpus(path), threshold=threshold)


def evaluate_examples(examples: Sequence[Example], *, threshold: float = 0.5) -> EvalReport:
    """Evaluate an in-memory corpus. The positive class is malicious."""

    if not examples:
        raise ValueError("corpus has no rows")
    if examples[0].split is not None:
        return _evaluate_split(examples, threshold)
    return _evaluate_kfold(examples, threshold)


def metrics_from_labels(y_true: Sequence[int], y_pred: Sequence[int]) -> tuple[int, int, int, int]:
    """Return ``(tp, fp, tn, fn)`` for binary labels."""

    if len(y_true) != len(y_pred):
        raise ValueError("y_true and y_pred must have the same length")
    tp = fp = tn = fn = 0
    for truth, predicted in zip(y_true, y_pred, strict=True):
        if truth not in (0, 1) or predicted not in (0, 1):
            raise ValueError("labels must be 0 or 1")
        if truth == 1 and predicted == 1:
            tp += 1
        elif truth == 0 and predicted == 1:
            fp += 1
        elif truth == 0 and predicted == 0:
            tn += 1
        else:
            fn += 1
    return tp, fp, tn, fn


def _evaluate_split(examples: Sequence[Example], threshold: float) -> EvalReport:
    train_rows = [example for example in examples if example.split == "train"]
    test_rows = [example for example in examples if example.split == "test"]
    if not train_rows or not test_rows:
        raise ValueError("a split corpus needs both train and test rows")
    model = fit_examples(train_rows)
    warden = Warden(threshold, model=model)
    predicted = [1 if warden.scan(example.text).flagged else 0 for example in test_rows]
    return _report([example.y for example in test_rows], predicted, "train-split")


def _evaluate_kfold(examples: Sequence[Example], threshold: float) -> EvalReport:
    count = len(examples)
    predicted = [0] * count
    for fold in range(FOLDS):
        train_rows = [example for index, example in enumerate(examples) if index % FOLDS != fold]
        test_indexes = [index for index in range(count) if index % FOLDS == fold]
        if not test_indexes:
            continue
        if len(train_rows) < MIN_EXAMPLES:
            raise ValueError(
                f"fold {fold} training set has {len(train_rows)} examples; "
                f"need at least {MIN_EXAMPLES}. Add rows or provide a split."
            )
        try:
            model = fit_examples(train_rows)
        except ValueError as exc:
            raise ValueError(f"fold {fold}: {exc}") from exc
        warden = Warden(threshold, model=model)
        for index in test_indexes:
            predicted[index] = 1 if warden.scan(examples[index].text).flagged else 0
    return _report([example.y for example in examples], predicted, f"kfold-{FOLDS}")


def _report(y_true: Sequence[int], y_pred: Sequence[int], method: str) -> EvalReport:
    tp, fp, tn, fn = metrics_from_labels(y_true, y_pred)
    precision = _rate(tp, tp + fp)
    recall = _rate(tp, tp + fn)
    if precision + recall == 0.0:
        f1 = 0.0
    else:
        f1 = 2.0 * precision * recall / (precision + recall)
    return EvalReport(
        precision=precision,
        recall=recall,
        f1=f1,
        fpr=_rate(fp, fp + tn),
        tp=tp,
        fp=fp,
        tn=tn,
        fn=fn,
        n=len(y_true),
        method=method,
    )


def _rate(numerator: int, denominator: int) -> float:
    if denominator == 0:
        return 0.0
    return numerator / denominator


def _parse_row(line: str, number: int) -> Example:
    try:
        raw = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ValueError(f"corpus line {number} is not valid JSON") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"corpus line {number} must be a JSON object")
    text = raw.get("text")
    label = raw.get("label")
    category = raw.get("category")
    if not isinstance(text, str):
        raise ValueError(f"corpus line {number} field text must be a string")
    if label not in _LABELS:
        raise ValueError(f"corpus line {number} field label must be 'malicious' or 'benign'")
    if category not in _CATEGORIES:
        raise ValueError(
            f"corpus line {number} field category must be 'injection', 'pii', or 'benign'"
        )
    if label == "benign" and category != "benign":
        raise ValueError(f"corpus line {number} benign rows must use category 'benign'")
    if label == "malicious" and category == "benign":
        raise ValueError(f"corpus line {number} malicious rows cannot use category 'benign'")
    split: str | None
    if "split" in raw:
        value = raw.get("split")
        if value not in _SPLITS:
            raise ValueError(f"corpus line {number} field split must be 'train' or 'test'")
        split = value
    else:
        split = None
    return Example(text=text, label=label, category=category, split=split)
