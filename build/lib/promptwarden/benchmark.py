"""Benchmark harness for PromptWarden scanners (dependency-injected)."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VALID_LABELS = frozenset({"malicious", "benign"})
VALID_CATEGORIES = frozenset({"injection", "pii", "benign"})
SWEEP_THRESHOLDS = tuple(round(x * 0.1, 1) for x in range(1, 10))  # 0.1 .. 0.9


@dataclass(frozen=True)
class Example:
    """One labeled corpus example."""

    text: str
    label: str
    category: str


@dataclass(frozen=True)
class ScanResult:
    """Minimal scan result shape expected from ``scan_fn``."""

    score: float
    flagged: bool
    categories: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()


@dataclass(frozen=True)
class ConfusionCounts:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0


@dataclass(frozen=True)
class ThresholdMetrics:
    threshold: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    counts: ConfusionCounts


@dataclass(frozen=True)
class BenchmarkResult:
    threshold: float
    counts: ConfusionCounts
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    per_category_recall: dict[str, float]
    sweep: tuple[ThresholdMetrics, ...]
    best_f1_threshold: float
    best_f1: float
    n_examples: int = 0
    extras: dict[str, Any] = field(default_factory=dict)


def _safe_div(num: float, den: float) -> float:
    if den == 0:
        return 0.0
    return num / den


def _metrics_from_counts(counts: ConfusionCounts) -> tuple[float, float, float, float]:
    precision = _safe_div(counts.tp, counts.tp + counts.fp)
    recall = _safe_div(counts.tp, counts.tp + counts.fn)
    f1 = _safe_div(2 * precision * recall, precision + recall)
    fpr = _safe_div(counts.fp, counts.fp + counts.tn)
    return precision, recall, f1, fpr


def load_corpus(path: str | Path) -> list[Example]:
    """Load and validate a JSONL corpus.

    Raises:
        ValueError: on malformed lines, invalid fields, inconsistent
            label/category, or duplicate texts.
    """
    path = Path(path)
    examples: list[Example] = []
    seen: set[str] = set()

    try:
        raw_lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError(f"cannot read corpus: {path}") from exc

    for line_no, line in enumerate(raw_lines, start=1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"line {line_no}: invalid JSON ({exc})") from exc

        if not isinstance(obj, dict):
            # Uniform loader API: all schema failures are ValueError.
            raise ValueError(f"line {line_no}: expected a JSON object")  # noqa: TRY004

        for key in ("text", "label", "category"):
            if key not in obj:
                raise ValueError(f"line {line_no}: missing field {key!r}")

        text = obj["text"]
        label = obj["label"]
        category = obj["category"]

        if not isinstance(text, str) or not text:
            raise ValueError(f"line {line_no}: text must be a non-empty string")
        if not isinstance(label, str) or label not in VALID_LABELS:
            raise ValueError(f"line {line_no}: invalid label {label!r}")
        if not isinstance(category, str) or category not in VALID_CATEGORIES:
            raise ValueError(f"line {line_no}: invalid category {category!r}")

        expected_label = "benign" if category == "benign" else "malicious"
        if label != expected_label:
            raise ValueError(
                f"line {line_no}: label {label!r} inconsistent with category {category!r}"
            )

        if text in seen:
            raise ValueError(f"line {line_no}: duplicate text")
        seen.add(text)

        examples.append(Example(text=text, label=label, category=category))

    if not examples:
        raise ValueError("corpus is empty")

    return examples


def _score_as_flagged(score: float, threshold: float) -> bool:
    return score >= threshold


def _extract_score(result: Any) -> float:
    score = getattr(result, "score", None)
    if score is None and isinstance(result, dict):
        score = result.get("score")
    if not isinstance(score, (int, float)):
        raise TypeError("scan_fn must return an object with a numeric score")
    return float(score)


def _confusion(
    examples: Sequence[Example],
    scores: Sequence[float],
    threshold: float,
) -> ConfusionCounts:
    tp = fp = tn = fn = 0
    for ex, score in zip(examples, scores, strict=True):
        pred_malicious = _score_as_flagged(score, threshold)
        actual_malicious = ex.label == "malicious"
        if pred_malicious and actual_malicious:
            tp += 1
        elif pred_malicious and not actual_malicious:
            fp += 1
        elif not pred_malicious and not actual_malicious:
            tn += 1
        else:
            fn += 1
    return ConfusionCounts(tp=tp, fp=fp, tn=tn, fn=fn)


def _per_category_recall(
    examples: Sequence[Example],
    scores: Sequence[float],
    threshold: float,
) -> dict[str, float]:
    """Recall for each malicious category (injection, pii); benign omitted."""
    hits: dict[str, int] = {}
    totals: dict[str, int] = {}
    for ex, score in zip(examples, scores, strict=True):
        if ex.category == "benign":
            continue
        totals[ex.category] = totals.get(ex.category, 0) + 1
        if _score_as_flagged(score, threshold):
            hits[ex.category] = hits.get(ex.category, 0) + 1
    return {cat: _safe_div(hits.get(cat, 0), totals[cat]) for cat in sorted(totals)}


def run_benchmark(
    scan_fn: Callable[[str], Any],
    examples: Sequence[Example],
    threshold: float = 0.5,
) -> BenchmarkResult:
    """Run ``scan_fn`` over ``examples`` and compute detection metrics.

    Predictions use ``score >= threshold`` (and the same rule for the sweep).
    ``scan_fn`` is injected — this module does not import a concrete Warden.
    """
    if not examples:
        raise ValueError("examples must be non-empty")
    if not 0.0 <= threshold <= 1.0:
        raise ValueError("threshold must be in [0, 1]")

    scores = [_extract_score(scan_fn(ex.text)) for ex in examples]

    counts = _confusion(examples, scores, threshold)
    precision, recall, f1, fpr = _metrics_from_counts(counts)
    per_cat = _per_category_recall(examples, scores, threshold)

    sweep_rows: list[ThresholdMetrics] = []
    for t in SWEEP_THRESHOLDS:
        c = _confusion(examples, scores, t)
        p, r, f, rate = _metrics_from_counts(c)
        sweep_rows.append(
            ThresholdMetrics(
                threshold=t,
                precision=p,
                recall=r,
                f1=f,
                false_positive_rate=rate,
                counts=c,
            )
        )

    best = max(sweep_rows, key=lambda row: (row.f1, -row.threshold))

    return BenchmarkResult(
        threshold=threshold,
        counts=counts,
        precision=precision,
        recall=recall,
        f1=f1,
        false_positive_rate=fpr,
        per_category_recall=per_cat,
        sweep=tuple(sweep_rows),
        best_f1_threshold=best.threshold,
        best_f1=best.f1,
        n_examples=len(examples),
    )


def format_report(result: BenchmarkResult) -> str:
    """Render a readable text table summarizing ``result``."""
    c = result.counts
    lines = [
        "PromptWarden Benchmark Report",
        "=" * 40,
        f"Examples          : {result.n_examples}",
        f"Threshold         : {result.threshold:.1f}",
        "",
        "Confusion matrix",
        "-" * 40,
        f"TP {c.tp:<6} FP {c.fp}",
        f"FN {c.fn:<6} TN {c.tn}",
        "",
        "Metrics",
        "-" * 40,
        f"Precision         : {result.precision:.4f}",
        f"Recall            : {result.recall:.4f}",
        f"F1                : {result.f1:.4f}",
        f"False positive rate: {result.false_positive_rate:.4f}",
        "",
        "Per-category recall",
        "-" * 40,
    ]
    if result.per_category_recall:
        for cat, val in result.per_category_recall.items():
            lines.append(f"{cat:<18}: {val:.4f}")
    else:
        lines.append("(none)")

    lines.extend(
        [
            "",
            "Threshold sweep (0.1 .. 0.9)",
            "-" * 40,
            f"{'thr':>5}  {'P':>7}  {'R':>7}  {'F1':>7}  {'FPR':>7}",
        ]
    )
    for row in result.sweep:
        lines.append(
            f"{row.threshold:5.1f}  {row.precision:7.4f}  {row.recall:7.4f}  "
            f"{row.f1:7.4f}  {row.false_positive_rate:7.4f}"
        )

    lines.extend(
        [
            "",
            f"Best F1 threshold : {result.best_f1_threshold:.1f}",
            f"Best F1           : {result.best_f1:.4f}",
        ]
    )
    return "\n".join(lines) + "\n"
