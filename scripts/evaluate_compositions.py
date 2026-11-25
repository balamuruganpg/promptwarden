"""Fixed, offline PromptWarden regression replay. Prints aggregate counts only.

Run with PYTHONPATH pointing to the scanner's src directory. TrustBreaker is
read from the adjacent checkout by default. No model fitting or sampling.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from base64 import urlsafe_b64encode
from collections import Counter
from collections.abc import Iterator
from functools import lru_cache
from itertools import product
from pathlib import Path
from urllib.parse import quote

from promptwarden import Warden, __version__

ROOT = Path(__file__).resolve().parents[1]
CORPUS_SHA = "8ea62c6aef2063c0d251ffd2df3bc813dab208779909a836cdb60bda3a7b2a4d"
CATALOG_SHA = "91bdb691194b51a13f70bd0d096863e2b0d4220a2d623d34f5d2487f89102b96"
# One-based injection rows that the v0.6.0 bundled scanner missed.
MISSED_ORIGINALS = {51, 55, 57}
REVERSALS = {"char_reverse", "word_reverse"}
LEGACY_PAIRS = {
    frozenset((left, right)): family
    for left, right, family in (
        ("char_reverse", "space_out", "reversal + spacing"),
        ("word_reverse", "space_out", "reversal + spacing"),
        ("char_reverse", "leet", "reversal + leet"),
        ("word_reverse", "leet", "reversal + leet"),
        ("char_reverse", "synonym", "reversal + synonym"),
        ("word_reverse", "synonym", "reversal + synonym"),
        ("leet", "space_out", "leet + spacing"),
        ("leet", "punct_split", "leet + punctuation"),
        ("b64_wrap", "b64_wrap", "double base64"),
        ("b64_wrap", "space_out", "base64 + spacing"),
        ("b64_wrap", "punct_split", "base64 + punctuation"),
        ("b64_wrap", "leet", "base64 + leet"),
    )
}


def url64(text: str) -> str:
    # A UTF-8 decoration makes both URL alphabet symbols observable even on
    # ASCII originals. Trailing spaces ensure the padded/unpadded cases differ.
    raw = ("🌿🌿\n" + text).encode()
    raw += b" " * ((1 - len(raw)) % 3)
    token = urlsafe_b64encode(raw).decode()
    assert "-" in token and "_" in token and token.endswith("==")
    return token


def target_pipelines(text: str) -> Iterator[tuple[str, tuple[str, ...]]]:
    yield "URL-safe padded", ("url64",)
    yield "URL-safe unpadded", ("url64_unpadded",)
    for name in ("url64", "url64_unpadded"):
        yield "URL-safe + standard base64", (name, "b64_wrap")
        yield "URL-safe + standard base64", ("b64_wrap", name)
    for op in ("space_out", "punct_split", "zero_width", "diacritic", "homoglyph"):
        yield "URL-safe + " + op, ("url64", op)
        yield "URL-safe + " + op, (op, "url64")
    for ops in product(("b64_wrap", "url64"), repeat=3):
        yield (
            ("triple standard base64" if ops == ("b64_wrap",) * 3 else "triple with URL-safe"),
            ops,
        )
    yield "double percent", ("percent", "percent")
    yield "double hex", ("hex", "hex")
    yield "system fence then word reversal", ("fence", "word_reverse")
    if text.startswith("```system"):
        yield "original fence then word reversal", ("word_reverse",)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trustbreaker", type=Path, default=ROOT.parent / "trustbreaker")
    parser.add_argument("--suite", choices=("targets", "pairs", "historical", "all"), default="all")
    args = parser.parse_args()
    sys.path.insert(0, str(args.trustbreaker / "src"))
    from trustbreaker.operators import OPERATORS, PIPELINES

    # The historical fixture addresses recipes by their index in this catalog.
    catalog = "\n".join("+".join(ops) for ops in PIPELINES).encode()
    if hashlib.sha256(catalog).hexdigest() != CATALOG_SHA:
        raise ValueError("TrustBreaker operator catalog differs from the frozen replay")

    corpus = (ROOT / "evals/corpus.jsonl").read_bytes()
    if hashlib.sha256(corpus).hexdigest() != CORPUS_SHA:
        raise ValueError("fixed replay requires the original corpus and its row order")
    rows = [json.loads(line) for line in corpus.splitlines()]
    operators = {
        **OPERATORS,
        "url64": url64,
        "url64_unpadded": lambda s: url64(s).rstrip("="),
        "percent": lambda s: quote(s, safe=""),
        "hex": lambda s: s.encode().hex(),
        "fence": lambda s: f"```system\n{s}\n```",
    }
    warden = Warden()
    if warden.rules_only:
        raise ValueError("fixed replay requires the bundled classifier")

    scan = lru_cache(maxsize=512)(warden.scan)
    fence_hits: Counter[str] = Counter()

    totals: Counter[str] = Counter()
    misses: Counter[str] = Counter()

    def count(source: str, ops: tuple[str, ...], *families: str) -> None:
        variant = source
        for op in ops:
            variant = operators[op](variant)
        if variant != source:
            result = scan(variant)
            for family in families:
                totals[family] += 1
                misses[family] += not result.flagged
                if family in (
                    "system fence then word reversal",
                    "original fence then word reversal",
                ):
                    fence_hits[family] += "system_fence" in result.signals

    for i, row in enumerate(rows, 1):
        if row["category"] != "injection" or i in MISSED_ORIGINALS:
            continue
        source = row["text"]
        if args.suite in ("all", "targets"):
            for family, ops in target_pipelines(source):
                count(source, ops, family)
        if args.suite in ("all", "pairs"):
            for pair in product(OPERATORS, repeat=2):
                families = ["all shipped pairs"]
                if sum(op in REVERSALS for op in pair) == 1:
                    families.append("reversal pairs")
                if pair in (("b64_wrap", "leet"), ("b64_wrap", "case_mix")):
                    families.append("base64 then " + pair[1])
                family = LEGACY_PAIRS.get(frozenset(pair))
                if family:
                    families.append(family)
                count(source, pair, *families)
    if args.suite in ("all", "historical"):
        # Indices into TrustBreaker's published, ordered PIPELINES tuple. The
        # frozen schedule contains no variant text or per-variant verdicts.
        schedule = json.loads((ROOT / "evals/v030-replay.json").read_text())
        for number, indices in schedule.items():
            for index in indices:
                ops = PIPELINES[index]
                families = ["v0.3 fixed set"]
                families.extend("fixed " + rev for rev in sorted(REVERSALS.intersection(ops)))
                count(rows[int(number) - 1]["text"], ops, *families)
    print(
        json.dumps(
            {
                "version": __version__,
                "families": {k: [misses[k], totals[k]] for k in sorted(totals)},
                "system_fence_hits": dict(fence_hits),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
