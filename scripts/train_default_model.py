#!/usr/bin/env python3
"""Rebuild from the fixed 90-row benchmark training half.

From the repository root, with the package importable::

    python scripts/train_default_model.py

The benchmark split is category-stratified, seed 13; see SPEC.md for the exact
algorithm. The remaining 91 benchmark rows are never used to fit the model.
Default-corpus cross-validation still retrains per fold on default rows only.
The fit reuses 1200 epochs, L2 0.001 and the existing classifier cutoff of 0.85.
An intercept shift applies the cutoff at the public threshold of 0.5.
"""

from __future__ import annotations

import math
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from promptwarden.evaluate import fit_examples, load_corpus, stratified_half  # noqa: E402
from promptwarden.normalize import normalize  # noqa: E402

BUNDLED_EPOCHS = 1200
BUNDLED_L2 = 0.001
CLASSIFIER_CUTOFF = 0.85


def main() -> int:
    destination = ROOT / "src" / "promptwarden" / "default_model.json"
    training, held_out = stratified_half(load_corpus(ROOT / "evals" / "corpus.jsonl"), seed=13)
    training_texts = {normalize(row.text) for row in training}
    if training_texts.intersection(normalize(row.text) for row in held_out):
        raise ValueError("benchmark holdout overlaps normalized training text")
    model = fit_examples(training, epochs=BUNDLED_EPOCHS, l2=BUNDLED_L2)
    offset = math.log(CLASSIFIER_CUTOFF / (1.0 - CLASSIFIER_CUTOFF))
    model = replace(model, bias=model.bias - offset)
    model.save(destination)
    print(
        f"wrote {destination} dim={model.dim} bias={model.bias:.6f} "
        f"training={len(training)} benchmark_held_out={len(held_out)} "
        f"classifier_cutoff={CLASSIFIER_CUTOFF} bias_offset={offset:.6f}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
