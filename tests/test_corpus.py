"""Corpus validity checks for evals/corpus.jsonl."""

from __future__ import annotations

import json
import re
from collections import Counter
from pathlib import Path

import pytest

from promptwarden import benchmark

ROOT = Path(__file__).resolve().parents[1]

CORPUS_PATH = ROOT / "evals" / "corpus.jsonl"

# Audited totals: the original 60/40/50 mix, plus 31 round-2 rows
# (21 injection, 10 benign). The PII count is unchanged.
EXPECTED_COUNTS = {"injection": 81, "pii": 40, "benign": 60}
EXPECTED_TOTAL = sum(EXPECTED_COUNTS.values())

# Luhn-valid card numbers expected in pii card examples (digits only).
CARD_DIGIT_RE = re.compile(r"\d[\d\s-]{12,}\d")


def _luhn_valid(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def test_corpus_loads_and_has_enough_examples() -> None:
    examples = benchmark.load_corpus(CORPUS_PATH)
    assert len(examples) == EXPECTED_TOTAL


def test_category_counts_in_expected_ranges() -> None:
    examples = benchmark.load_corpus(CORPUS_PATH)
    counts = Counter(ex.category for ex in examples)
    assert counts["injection"] == EXPECTED_COUNTS["injection"]
    assert counts["pii"] == EXPECTED_COUNTS["pii"]
    assert counts["benign"] == EXPECTED_COUNTS["benign"]


def test_no_duplicate_texts() -> None:
    examples = benchmark.load_corpus(CORPUS_PATH)
    texts = [ex.text for ex in examples]
    assert len(texts) == len(set(texts))


def test_label_category_consistency() -> None:
    examples = benchmark.load_corpus(CORPUS_PATH)
    for ex in examples:
        if ex.category == "benign":
            assert ex.label == "benign"
        else:
            assert ex.category in {"injection", "pii"}
            assert ex.label == "malicious"


def test_raw_jsonl_schema() -> None:
    """Belt-and-suspenders parse without going through load_corpus."""
    lines = CORPUS_PATH.read_text(encoding="utf-8").splitlines()
    assert len(lines) == EXPECTED_TOTAL
    for i, line in enumerate(lines, start=1):
        obj = json.loads(line)
        assert set(obj) >= {"text", "label", "category"}
        assert isinstance(obj["text"], str) and obj["text"]
        assert obj["label"] in {"malicious", "benign"}
        assert obj["category"] in {"injection", "pii", "benign"}


def test_card_examples_use_luhn_valid_numbers() -> None:
    """PII lines that look like payment cards must contain a Luhn-valid number."""
    examples = benchmark.load_corpus(CORPUS_PATH)
    card_keywords = ("card", "visa", "mastercard", "amex", "discover", "charge", "cvv")
    found = 0
    for ex in examples:
        if ex.category != "pii":
            continue
        lower = ex.text.lower()
        if not any(k in lower for k in card_keywords):
            continue
        matches = CARD_DIGIT_RE.findall(ex.text)
        assert matches, f"expected card digits in: {ex.text!r}"
        assert any(_luhn_valid(m) for m in matches), f"no Luhn-valid card in: {ex.text!r}"
        found += 1
    assert found >= 4


def test_luhn_helper_known_vectors() -> None:
    assert _luhn_valid("4242424242424242")
    assert _luhn_valid("4000000000000002")
    assert not _luhn_valid("4242424242424243")
    assert not _luhn_valid("4111111111111112")


@pytest.mark.parametrize(
    "bad_line",
    [
        '{"text": "x", "label": "malicious", "category": "benign"}',
        '{"text": "x", "label": "benign", "category": "injection"}',
    ],
)
def test_inconsistent_label_rejected_via_loader(tmp_path: Path, bad_line: str) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text(bad_line + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="inconsistent"):
        benchmark.load_corpus(path)


def test_label_audit_placeholders_removed() -> None:
    """Canonical specimen identifiers from the label audit stay out of the corpus."""
    text = CORPUS_PATH.read_text(encoding="utf-8")
    absent = (
        "AKIAIOSFODNN7EXAMPLE",
        "078-05-1120",
        "DE89 3704 0044 0532 0130 00",
        "example.org",
        "ABCDE1234F",
        "eyJzdWIiOiIxMjM0NTY3ODkw",
        "TLS material starts with",
        "2345 6789 0123",
        "Page 1 instructs the LLM",
    )
    for needle in absent:
        assert needle not in text
    assert "BQGPK4821M" in text
    assert "486-29-7314" in text
    assert "AKIA4N7QZ8M2L6P3H9TW" in text
    assert "DE06 6701 2984 0583 7261 94" in text
    assert "-----BEGIN EC PRIVATE KEY-----" in text


def test_round2_shapes_present() -> None:
    """Obfuscation, extra languages, indirect quotes, and hard benign negatives."""
    text = CORPUS_PATH.read_text(encoding="utf-8")
    required = (
        "\u200b",
        "\u200c",
        "\u200d",
        "\u0456",
        "\u03bf",
        "snoitcurtsni",
        "忽略",
        "تجاهل",
        "instruções",
        "시스템",
        "geçersiz kıl",
        "linee guida",
        "Forwarded message",
        "DOCUMENT CONTROL",
        "Appendix C",
        "Security postmortem",
        "Code review:",
        "Documentation sample",
        "Detection write-up",
        "Review comment:",
        "4000000000000001",
        "sk-test-placeholder-not-real",
        "Research note:",
        "Admin guide:",
        "leetspeak test",
    )
    for needle in required:
        assert needle in text, needle
