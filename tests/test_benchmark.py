"""Benchmark harness tests using stub scanners only (no Warden)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from promptwarden.benchmark import Example, format_report, load_corpus, run_benchmark


@dataclass(frozen=True)
class StubResult:
    score: float
    flagged: bool
    categories: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()


def _ex(text: str, label: str, category: str) -> Example:
    return Example(text=text, label=label, category=category)


SAMPLE = [
    _ex("inj-1", "malicious", "injection"),
    _ex("inj-2", "malicious", "injection"),
    _ex("pii-1", "malicious", "pii"),
    _ex("pii-2", "malicious", "pii"),
    _ex("ok-1", "benign", "benign"),
    _ex("ok-2", "benign", "benign"),
    _ex("ok-3", "benign", "benign"),
    _ex("ok-4", "benign", "benign"),
]


def perfect_scan(text: str) -> StubResult:
    malicious = text.startswith(("inj-", "pii-"))
    score = 0.9 if malicious else 0.1
    return StubResult(score=score, flagged=malicious)


def always_benign_scan(text: str) -> StubResult:
    return StubResult(score=0.0, flagged=False)


def scripted_scan(text: str) -> StubResult:
    """Hand-designed predictions for SAMPLE at threshold 0.5.

    Scores:
      inj-1 -> 0.9  (TP)
      inj-2 -> 0.2  (FN)
      pii-1 -> 0.8  (TP)
      pii-2 -> 0.8  (TP)
      ok-1  -> 0.7  (FP)
      ok-2  -> 0.1  (TN)
      ok-3  -> 0.1  (TN)
      ok-4  -> 0.6  (FP)

    At 0.5: TP=3, FP=2, TN=2, FN=1
      P = 3/5 = 0.6
      R = 3/4 = 0.75
      F1 = 2*0.6*0.75 / (0.6+0.75) = 0.9/1.35 = 2/3 ≈ 0.6667
      FPR = 2/4 = 0.5
    """
    table = {
        "inj-1": 0.9,
        "inj-2": 0.2,
        "pii-1": 0.8,
        "pii-2": 0.8,
        "ok-1": 0.7,
        "ok-2": 0.1,
        "ok-3": 0.1,
        "ok-4": 0.6,
    }
    score = table[text]
    return StubResult(score=score, flagged=score >= 0.5)


def test_perfect_stub_scores_one() -> None:
    result = run_benchmark(perfect_scan, SAMPLE, threshold=0.5)
    assert result.counts.tp == 4
    assert result.counts.fp == 0
    assert result.counts.tn == 4
    assert result.counts.fn == 0
    assert result.precision == 1.0
    assert result.recall == 1.0
    assert result.f1 == 1.0
    assert result.false_positive_rate == 0.0
    assert result.per_category_recall == {"injection": 1.0, "pii": 1.0}


def test_always_benign_stub_has_zero_recall() -> None:
    result = run_benchmark(always_benign_scan, SAMPLE, threshold=0.5)
    assert result.recall == 0.0
    assert result.counts.fn == 4
    assert result.counts.tp == 0
    assert result.counts.fp == 0
    assert result.counts.tn == 4
    assert result.precision == 0.0
    assert result.f1 == 0.0
    assert result.false_positive_rate == 0.0


def test_scripted_stub_hand_computed_metrics() -> None:
    result = run_benchmark(scripted_scan, SAMPLE, threshold=0.5)
    assert result.counts.tp == 3
    assert result.counts.fp == 2
    assert result.counts.tn == 2
    assert result.counts.fn == 1
    assert result.precision == pytest.approx(0.6)
    assert result.recall == pytest.approx(0.75)
    assert result.f1 == pytest.approx(2 / 3)
    assert result.false_positive_rate == pytest.approx(0.5)
    # injection: inj-1 hit, inj-2 miss -> 0.5; pii: both hit -> 1.0
    assert result.per_category_recall["injection"] == pytest.approx(0.5)
    assert result.per_category_recall["pii"] == pytest.approx(1.0)


def test_threshold_sweep_and_best_f1() -> None:
    result = run_benchmark(scripted_scan, SAMPLE, threshold=0.5)
    assert len(result.sweep) == 9
    thresholds = [row.threshold for row in result.sweep]
    assert thresholds == [round(x * 0.1, 1) for x in range(1, 10)]

    # Recompute best F1 from sweep rows
    best_row = max(result.sweep, key=lambda r: (r.f1, -r.threshold))
    assert result.best_f1 == pytest.approx(best_row.f1)
    assert result.best_f1_threshold == best_row.threshold

    # At threshold 0.1: scores >= 0.1 flags everything except none (all scores >= 0.1)
    # All eight examples flagged -> TP=4 FP=4 TN=0 FN=0
    row_01 = next(r for r in result.sweep if r.threshold == 0.1)
    assert row_01.counts.tp == 4
    assert row_01.counts.fp == 4
    assert row_01.recall == pytest.approx(1.0)

    # At 0.9: only inj-1 (0.9) flagged
    row_09 = next(r for r in result.sweep if r.threshold == 0.9)
    assert row_09.counts.tp == 1
    assert row_09.counts.fp == 0
    assert row_09.counts.fn == 3
    assert row_09.precision == pytest.approx(1.0)
    assert row_09.recall == pytest.approx(0.25)


def test_format_report_contains_key_figures() -> None:
    result = run_benchmark(scripted_scan, SAMPLE, threshold=0.5)
    report = format_report(result)
    assert "Precision" in report
    assert "Recall" in report
    assert "F1" in report
    assert "0.6000" in report
    assert "0.7500" in report
    assert f"{result.f1:.4f}" in report
    assert "False positive rate" in report
    assert "0.5000" in report
    assert "Best F1" in report
    assert str(result.counts.tp) in report
    assert "injection" in report
    assert "Threshold sweep" in report


def test_load_corpus_happy_path(tmp_path: Path) -> None:
    path = tmp_path / "c.jsonl"
    path.write_text(
        '{"text": "a", "label": "malicious", "category": "injection"}\n'
        '{"text": "b", "label": "benign", "category": "benign"}\n',
        encoding="utf-8",
    )
    examples = load_corpus(path)
    assert len(examples) == 2
    assert examples[0].category == "injection"
    assert examples[1].label == "benign"


def test_load_corpus_rejects_duplicates(tmp_path: Path) -> None:
    path = tmp_path / "dup.jsonl"
    path.write_text(
        '{"text": "same", "label": "malicious", "category": "pii"}\n'
        '{"text": "same", "label": "malicious", "category": "pii"}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_corpus(path)


def test_load_corpus_rejects_bad_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text("{not json\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid JSON"):
        load_corpus(path)


def test_load_corpus_rejects_missing_field(tmp_path: Path) -> None:
    path = tmp_path / "miss.jsonl"
    path.write_text('{"text": "x", "label": "benign"}\n', encoding="utf-8")
    with pytest.raises(ValueError, match="missing field"):
        load_corpus(path)


def test_load_corpus_rejects_invalid_category(tmp_path: Path) -> None:
    path = tmp_path / "cat.jsonl"
    path.write_text(
        '{"text": "x", "label": "malicious", "category": "malware"}\n',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="invalid category"):
        load_corpus(path)


def test_load_corpus_rejects_empty(tmp_path: Path) -> None:
    path = tmp_path / "empty.jsonl"
    path.write_text("\n\n", encoding="utf-8")
    with pytest.raises(ValueError, match="empty"):
        load_corpus(path)


def test_run_benchmark_rejects_empty_examples() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        run_benchmark(perfect_scan, [])
