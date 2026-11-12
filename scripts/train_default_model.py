#!/usr/bin/env python3
"""Rebuild the bundled model from the default corpus.

From the repository root, with the package importable::

    python scripts/train_default_model.py

Equivalent command::

    python -m promptwarden train \\
        --corpus examples/default_corpus.jsonl \\
        --out src/promptwarden/default_model.json

The command fits every row. It does not hold a row out. Cross-validated
numbers in the README come from ``promptwarden eval``, which retrains per fold.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from promptwarden.evaluate import fit_examples, load_corpus  # noqa: E402


def main() -> int:
    corpus = ROOT / "examples" / "default_corpus.jsonl"
    destination = ROOT / "src" / "promptwarden" / "default_model.json"
    model = fit_examples(load_corpus(corpus))
    model.save(destination)
    print(f"wrote {destination} dim={model.dim} bias={model.bias:.6f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
