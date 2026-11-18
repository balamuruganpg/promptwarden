"""Hand-computed checks for benchmark precision, recall, F1, FPR, and the sweep.

Fractions below were calculated from the score tables in this file
(predict malicious when score >= threshold). They do not reuse the
implementation's metric helpers.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from promptwarden.benchmark import Example, run_benchmark


@dataclass(frozen=True)
class _Result:
    score: float


def _ex(text: str, label: str, category: str) -> Example:
    return Example(text=text, label=label, category=category)


# Scores at a 0.5 operating point:
#   inj-1 0.9 TP, inj-2 0.2 FN, pii-1 0.8 TP, pii-2 0.8 TP,
#   ok-1 0.7 FP, ok-2 0.1 TN, ok-3 0.1 TN, ok-4 0.6 FP.
# Counts: TP=3, FP=2, TN=2, FN=1.
_SAMPLE = [
    _ex("inj-1", "malicious", "injection"),
    _ex("inj-2", "malicious", "injection"),
    _ex("pii-1", "malicious", "pii"),
    _ex("pii-2", "malicious", "pii"),
    _ex("ok-1", "benign", "benign"),
    _ex("ok-2", "benign", "benign"),
    _ex("ok-3", "benign", "benign"),
    _ex("ok-4", "benign", "benign"),
]
_SCORES = {
    "inj-1": 0.9,
    "inj-2": 0.2,
    "pii-1": 0.8,
    "pii-2": 0.8,
    "ok-1": 0.7,
    "ok-2": 0.1,
    "ok-3": 0.1,
    "ok-4": 0.6,
}

# threshold -> (tp, fp, tn, fn, precision, recall, f1, fpr)
# F1 at 0.8: P=1, R=3/4, 2*(1)*(3/4)/(1+3/4) = (3/2)/(7/4) = 6/7.
_HAND_SWEEP = {
    0.1: (4, 4, 0, 0, 1 / 2, 1, 2 / 3, 1),
    0.2: (4, 2, 2, 0, 2 / 3, 1, 4 / 5, 1 / 2),
    0.3: (3, 2, 2, 1, 3 / 5, 3 / 4, 2 / 3, 1 / 2),
    0.4: (3, 2, 2, 1, 3 / 5, 3 / 4, 2 / 3, 1 / 2),
    0.5: (3, 2, 2, 1, 3 / 5, 3 / 4, 2 / 3, 1 / 2),
    0.6: (3, 2, 2, 1, 3 / 5, 3 / 4, 2 / 3, 1 / 2),
    0.7: (3, 1, 3, 1, 3 / 4, 3 / 4, 3 / 4, 1 / 4),
    0.8: (3, 0, 4, 1, 1, 3 / 4, 6 / 7, 0),
    0.9: (1, 0, 4, 3, 1, 1 / 4, 2 / 5, 0),
}


def _scripted(text: str) -> _Result:
    return _Result(score=_SCORES[text])


def test_scripted_sweep_matches_hand_table() -> None:
    result = run_benchmark(_scripted, _SAMPLE, threshold=0.5)
    assert [row.threshold for row in result.sweep] == list(_HAND_SWEEP)
    for row in result.sweep:
        tp, fp, tn, fn, precision, recall, f1, fpr = _HAND_SWEEP[row.threshold]
        assert (row.counts.tp, row.counts.fp, row.counts.tn, row.counts.fn) == (
            tp,
            fp,
            tn,
            fn,
        )
        assert row.precision == pytest.approx(precision)
        assert row.recall == pytest.approx(recall)
        assert row.f1 == pytest.approx(f1)
        assert row.false_positive_rate == pytest.approx(fpr)

    assert result.precision == pytest.approx(3 / 5)
    assert result.recall == pytest.approx(3 / 4)
    assert result.f1 == pytest.approx(2 / 3)
    assert result.false_positive_rate == pytest.approx(1 / 2)
    assert result.per_category_recall["injection"] == pytest.approx(1 / 2)
    assert result.per_category_recall["pii"] == pytest.approx(1)
    # Unique maximum on the hand table is 6/7 at 0.8.
    assert result.best_f1_threshold == 0.8
    assert result.best_f1 == pytest.approx(6 / 7)


def test_per_category_recall_when_a_category_is_missed() -> None:
    """At 0.9 only inj-1 (0.9) fires; both PII scores are 0.8."""
    result = run_benchmark(_scripted, _SAMPLE, threshold=0.9)
    assert result.counts.tp == 1
    assert result.counts.fn == 3
    assert result.counts.fp == 0
    assert result.counts.tn == 4
    assert result.precision == pytest.approx(1)
    assert result.recall == pytest.approx(1 / 4)
    assert result.f1 == pytest.approx(2 / 5)
    assert result.false_positive_rate == pytest.approx(0)
    assert result.per_category_recall["injection"] == pytest.approx(1 / 2)
    assert result.per_category_recall["pii"] == pytest.approx(0)


def test_best_f1_tie_keeps_the_lower_threshold() -> None:
    """F1 is 4/5 at 0.3, 0.4, 0.5, and 0.6, and lower everywhere else.

    Malicious scores 0.92 and 0.62; benign scores 0.62 and 0.22.
    At 0.3: TP=2, FP=1, TN=1, FN=0 -> P=2/3, R=1, F1=4/5.
    At 0.7: TP=1, FP=0, TN=2, FN=1 -> P=1, R=1/2, F1=2/3.
    The sweep selects the lowest threshold among the tied best F1.
    """
    examples = [
        _ex("m-high", "malicious", "injection"),
        _ex("m-mid", "malicious", "pii"),
        _ex("b-mid", "benign", "benign"),
        _ex("b-low", "benign", "benign"),
    ]
    scores = {"m-high": 0.92, "m-mid": 0.62, "b-mid": 0.62, "b-low": 0.22}

    def scan(text: str) -> _Result:
        return _Result(score=scores[text])

    result = run_benchmark(scan, examples, threshold=0.5)
    by_threshold = {row.threshold: row for row in result.sweep}
    low = by_threshold[0.3]
    assert (low.counts.tp, low.counts.fp, low.counts.tn, low.counts.fn) == (2, 1, 1, 0)
    assert low.precision == pytest.approx(2 / 3)
    assert low.recall == pytest.approx(1)
    assert low.f1 == pytest.approx(4 / 5)
    assert low.false_positive_rate == pytest.approx(1 / 2)
    high = by_threshold[0.7]
    assert (high.counts.tp, high.counts.fp, high.counts.tn, high.counts.fn) == (
        1,
        0,
        2,
        1,
    )
    assert high.f1 == pytest.approx(2 / 3)
    assert result.best_f1 == pytest.approx(4 / 5)
    assert result.best_f1_threshold == 0.3
    assert result.per_category_recall == {"injection": 1.0, "pii": 1.0}


def test_score_equal_to_threshold_is_a_positive() -> None:
    examples = [
        _ex("hit", "malicious", "injection"),
        _ex("false", "benign", "benign"),
    ]

    def scan(text: str) -> _Result:
        return _Result(score=0.5)

    result = run_benchmark(scan, examples, threshold=0.5)
    assert (result.counts.tp, result.counts.fp, result.counts.tn, result.counts.fn) == (
        1,
        1,
        0,
        0,
    )
    assert result.precision == pytest.approx(1 / 2)
    assert result.recall == pytest.approx(1)
    assert result.f1 == pytest.approx(2 / 3)
    assert result.false_positive_rate == pytest.approx(1)


def test_false_positive_rate_is_zero_when_there_are_no_negatives() -> None:
    examples = [
        _ex("miss", "malicious", "injection"),
        _ex("hit", "malicious", "pii"),
    ]
    scores = {"miss": 0.2, "hit": 0.9}

    def scan(text: str) -> _Result:
        return _Result(score=scores[text])

    result = run_benchmark(scan, examples, threshold=0.5)
    assert (result.counts.tp, result.counts.fp, result.counts.tn, result.counts.fn) == (
        1,
        0,
        0,
        1,
    )
    assert result.precision == pytest.approx(1)
    assert result.recall == pytest.approx(1 / 2)
    assert result.f1 == pytest.approx(2 / 3)
    # FP+TN = 0, so the rate is defined as 0.
    assert result.false_positive_rate == 0.0
    assert result.per_category_recall["injection"] == pytest.approx(0)
    assert result.per_category_recall["pii"] == pytest.approx(1)
