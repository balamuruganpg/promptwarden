#!/usr/bin/env python3
"""Measure the bundled model and default-corpus CV; never fit on the holdout.

    python scripts/evaluate_default_model.py

The full benchmark includes training rows and is a descriptive number only.
The benchmark holdout is good-not-pristine because development inspected it.
The default 5-fold evaluation trains only on the other default rows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from dataclasses import asdict
from datetime import date
from pathlib import Path
from typing import TypedDict

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from train_default_model import BUNDLED_EPOCHS, BUNDLED_L2, CLASSIFIER_CUTOFF  # noqa: E402

from promptwarden import Warden, __version__  # noqa: E402
from promptwarden.benchmark import Example as BenchmarkExample  # noqa: E402
from promptwarden.benchmark import ScanResult as BenchmarkScanResult  # noqa: E402
from promptwarden.benchmark import run_benchmark  # noqa: E402
from promptwarden.evaluate import (  # noqa: E402
    Example,
    evaluate_corpus,
    fit_examples,
    load_corpus,
    stratified_half,
)
from promptwarden.features import extract  # noqa: E402
from promptwarden.normalize import normalize  # noqa: E402
from promptwarden.rules import detect, rule_score  # noqa: E402
from promptwarden.warden import bundled_model_path  # noqa: E402


class _OperatingPoint(TypedDict):
    classifier_cutoff: float
    counts: dict[str, int]
    precision: float
    recall: float
    f1: float
    fpr: float


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _benchmark(warden: Warden, examples: list[Example]) -> dict[str, object]:
    rows = [BenchmarkExample(row.text, row.label, row.category) for row in examples]
    return asdict(run_benchmark(warden.scan, rows, threshold=warden.threshold))


def _training_cv(examples: list[Example]) -> dict[str, object]:
    """Select a model cutoff using only out-of-fold training predictions."""

    predictions: dict[str, tuple[float, float]] = {}
    for fold in range(5):
        model = fit_examples(
            [row for i, row in enumerate(examples) if i % 5 != fold],
            epochs=BUNDLED_EPOCHS,
            l2=BUNDLED_L2,
        )
        for i, row in enumerate(examples):
            if i % 5 == fold:
                fired = detect(row.text)
                probability = model.predict_proba(extract(row.text, [s.name for s in fired]))
                predictions[row.text] = probability, rule_score(fired)
    reports: list[_OperatingPoint] = []
    rows = [BenchmarkExample(row.text, row.label, row.category) for row in examples]
    for cutoff in (0.5, 0.55, 0.6, 0.65, 0.7, 0.75, 0.8, 0.85, 0.9):

        def scan(text: str) -> BenchmarkScanResult:
            probability, rules = predictions[text]
            # Only the 0.5 operating point is reported here. This is equivalent
            # to subtracting logit(cutoff) from the model's fitted intercept.
            score = max(rules, 0.5 if probability >= cutoff else 0.0)
            return BenchmarkScanResult(score=score, flagged=score >= 0.5)

        result = run_benchmark(scan, rows)
        reports.append(
            {
                "classifier_cutoff": cutoff,
                "counts": asdict(result.counts),
                "precision": result.precision,
                "recall": result.recall,
                "f1": result.f1,
                "fpr": result.false_positive_rate,
            }
        )
    eligible = [row for row in reports if row["fpr"] <= 0.10]
    if not eligible:
        raise ValueError("no classifier cutoff meets the training-CV FPR limit")
    chosen = max(eligible, key=lambda row: (row["f1"], -row["classifier_cutoff"]))
    return {
        "method": "training-only kfold-5, index % 5",
        "epochs": BUNDLED_EPOCHS,
        "l2": BUNDLED_L2,
        "n": len(examples),
        "operating_points": reports,
        "max_fpr": 0.10,
        "selected_classifier_cutoff": chosen["classifier_cutoff"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="also save the JSON report")
    parser.add_argument(
        "--training-cv", action="store_true", help="evaluate cutoffs on the fitting split only"
    )
    args = parser.parse_args()
    default_path = ROOT / "examples" / "default_corpus.jsonl"
    benchmark_path = ROOT / "evals" / "corpus.jsonl"
    rows = load_corpus(benchmark_path)
    training, held_out = stratified_half(rows, seed=13)
    training_texts = {normalize(row.text) for row in training}
    if training_texts.intersection(normalize(row.text) for row in held_out):
        raise ValueError("benchmark holdout overlaps normalized training text")
    if args.training_cv:
        rendered = json.dumps(_training_cv(training), indent=2, sort_keys=True) + "\n"
        if args.out is not None:
            args.out.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 0
    warden = Warden()
    report = {
        "protocol": {
            "date": date.today().isoformat(),
            "package_version": __version__,
            "python": platform.python_version(),
            "threshold": warden.threshold,
            "seed": 13,
            "benchmark_train_rows_1based": [i + 1 for i, row in enumerate(rows) if row in training],
            "benchmark_test_rows_1based": [i + 1 for i, row in enumerate(rows) if row in held_out],
            "default_corpus_sha256": _sha256(default_path),
            "benchmark_sha256": _sha256(benchmark_path),
            "model_sha256": _sha256(bundled_model_path()),
            "model_training_rows": len(training),
            "model_epochs": BUNDLED_EPOCHS,
            "model_l2": BUNDLED_L2,
            "model_classifier_cutoff": CLASSIFIER_CUTOFF,
            "full_benchmark_status": "Descriptive. Includes benchmark fitting rows.",
            "held_out_benchmark_status": (
                "Good-not-pristine. Excluded from model fitting and inspected during development."
            ),
        },
        "full_benchmark": _benchmark(warden, rows),
        "held_out_benchmark": _benchmark(warden, held_out),
        "default_corpus_5fold": asdict(evaluate_corpus(default_path)),
    }
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out is not None:
        args.out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
