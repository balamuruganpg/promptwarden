# Changelog

## 0.7.0 — 2026-11-25

The instruction scanner now decodes standard or URL-safe base64, hex and percent escapes on one breadth-first queue. Four layers cover a triple wrapper around an already encoded instruction. Each candidate contributes up to 4,096 ASCII characters. All codecs, orientations and repairs share 64 attempts and 32,768 input bytes. Failed attempts consume budget. Each distinct (codec, token) pair and each distinct recovered text is processed once. Extra outer repairs and reversals cover the first 16,384 characters. Intact candidates are scanned throughout the input.

Decoded and reordered readings contribute decisive instruction matches. The same reporting and negation masks apply before transformation and after restoration, including inside a decoded message. Reordered system fences use the existing fence pattern. A recognized source code-language opener keeps its delimiter when words move, protecting ordinary code examples. Existing tests that specified single-pass percent decoding or unsuppressed encoded reports now assert the new contracts. The classifier, its feature layout and training data did not change.

### Target families

Bypass is the count of applicable variants that `Warden().scan` leaves unflagged at 0.5. We measured v0.6.0 before changing the scanner. The 78 flagged injection originals and ordered pipelines were fixed for both versions. Each changed (row, pipeline) counts once. Family rows can overlap. URL-safe fixtures include a UTF-8 prefix that produces both URL-specific symbols and trailing whitespace to exercise actual padding. Triple-wrapper rows cover all eight standard/URL-safe orders. The five URL-safe surface-repair rows include both operator orders.

| Family | Applicable | v0.6.0 misses | v0.7.0 misses |
|---|---:|---:|---:|
| URL-safe base64, padded | 78 | 76 (97.44%) | 0 (0.00%) |
| URL-safe base64, unpadded | 78 | 78 (100.00%) | 0 (0.00%) |
| URL-safe and standard base64, both orders | 312 | 310 (99.36%) | 0 (0.00%) |
| Three standard base64 wrappers | 78 | 78 (100.00%) | 0 (0.00%) |
| Three wrappers including URL-safe base64 | 546 | 546 (100.00%) | 0 (0.00%) |
| Double percent | 78 | 76 (97.44%) | 0 (0.00%) |
| Double hex | 78 | 78 (100.00%) | 0 (0.00%) |
| Word-order rewrite of the original corpus fence | 1 | 1 (100.00%) | 0 (0.00%) |
| Fence wrapper then word reversal | 78 | 1 (1.28%) | 0 (0.00%) |
| URL-safe base64 with spacing | 156 | 154 (98.72%) | 2 (1.28%) |
| URL-safe base64 with punctuation splits | 156 | 155 (99.36%) | 81 (51.92%) |
| URL-safe base64 with zero-width characters | 156 | 154 (98.72%) | 0 (0.00%) |
| URL-safe base64 with diacritics | 156 | 154 (98.72%) | 0 (0.00%) |
| URL-safe base64 with homoglyphs | 156 | 143 (91.67%) | 0 (0.00%) |

The corpus contains one original system fence. Wrapping all 78 rows also tests the signal itself. v0.6.0 already flagged 77 of those reordered variants. The `system_fence` rule fired on 1/78 before and 77/78 after. One rewrite produced a literal Python opener. The code-fence guard preserved it and another signal flagged the row.

### Previous fixed families

The first replay enumerates all 121 ordered pairs of the 11 shipped TrustBreaker operators. The historical 2,960-variant replay uses the original v0.3.0 selection. Its row and pipeline indices were recovered from the seed-13, budget-40 reference and verified against the published 2,613/2,960 v0.3.0 misses. Neither scanner under comparison selects test variants.

| Family | Applicable | v0.6.0 misses | v0.7.0 misses |
|---|---:|---:|---:|
| All shipped ordered pairs | 9,056 | 1,029 (11.36%) | 915 (10.10%) |
| Pairs with exactly one reversal | 2,784 | 257 (9.23%) | 220 (7.90%) |
| Reversal with spacing | 306 | 63 (20.59%) | 58 (18.95%) |
| Reversal with leet | 312 | 86 (27.56%) | 84 (26.92%) |
| Reversal with synonym substitution | 306 | 20 (6.54%) | 18 (5.88%) |
| Leet with spacing | 156 | 48 (30.77%) | 46 (29.49%) |
| Leet with punctuation splits | 156 | 48 (30.77%) | 46 (29.49%) |
| Two standard base64 wrappers | 78 | 6 (7.69%) | 0 (0.00%) |
| Base64 with spacing | 156 | 22 (14.10%) | 14 (8.97%) |
| Base64 with punctuation splits | 156 | 23 (14.74%) | 17 (10.90%) |
| Base64 with leet | 156 | 100 (64.10%) | 98 (62.82%) |
| Base64 followed by leet | 78 | 78 (100.00%) | 78 (100.00%) |
| Base64 followed by case mixing | 78 | 78 (100.00%) | 78 (100.00%) |
| Historical fixed set | 2,960 | 569 (19.22%) | 524 (17.70%) |
| Historical set containing character reversal | 710 | 118 (16.62%) | 113 (15.92%) |
| Historical set containing word reversal | 710 | 139 (19.58%) | 120 (16.90%) |

### Release gates

| Corpus at 0.5 | Precision | Recall | F1 | FPR | Injection recall | PII recall | TP / FP / TN / FN |
|---|---:|---:|---:|---:|---:|---:|---|
| Full, 181 rows | 0.9626 | 0.8512 | 0.9035 | 0.0667 | 78/81 | 25/40 | 103 / 4 / 56 / 18 |
| Seed-13 holdout, 91 rows | 0.9630 | 0.8525 | 0.9043 | 0.0667 | 40/41 | 12/20 | 52 / 2 / 28 / 9 |

The full set includes the model's 90 historical fitting rows. The holdout was inspected during development. All 229 public scan results across the benchmark and default examples matched v0.6.0 exactly, including all 88 benign scores, verdicts and signals. No classifier refit or benchmark training was performed.

On CPython 3.12.3, 382 tests passed (335 existing cases plus 47 new cases). The pathological-input test exercised 30 base64 layers, a 1 MiB carrier, a repeated-candidate input and 2,000 nested percent escapes. The decoder took 0.55 s across the four inputs and peaked at 327,992 traced bytes, excluding the prebuilt inputs. Including the two end-to-end scans took 4.75 s. The scans peaked at 2,108,644 traced bytes. The test enforces a 4 MiB decoder peak, an 8 MiB scan peak and a 30-second subprocess timeout. Run `PYTHONPATH=src python -m pytest -q` for the suite or `PYTHONPATH=src python tests/test_decoding.py` for the resource measurements.

From this checkout, run `PYTHONPATH=src python scripts/evaluate_compositions.py` with sibling TrustBreaker at `a8e182134708255930ba498b550fdcde7ce83adf`. For the baseline, point `PYTHONPATH` at the `src` of PromptWarden `0863462` and run the same script. The version and aggregate counts are printed. [Replay evaluator](scripts/evaluate_compositions.py) · [Historical schedule](evals/v030-replay.json)

### Remaining limits

Punctuation splitting can make a genuine URL-safe hyphen indistinguishable from an inserted separator. Some spaced compositions also miss. Leet and case mixing can destroy base64 bits. Synonym substitution has no general inverse. Reversed PII remains outside the instruction view. Inputs may exceed the depth, size or attempt budgets. The published 21.67% fresh adaptive bypass describes v0.6.0. No fresh v0.7.0 adaptive rate was measured.

## 0.6.0 — 2026-11-18

- Add composed instruction views (`compose.py`). A de-spaced reading of reversed text, a reversed reading of de-leeted text, and a second standard-base64 decode now feed the same decisive instruction patterns as the direct view. Context masking runs on every reading, before and after the repair. The shared normalizer, n-grams, PII checks, and the bundled classifier are unchanged. The model was not refit.
- Measured on a fixed depth-2 set: every ordered pair of TrustBreaker's shipped operators, applied to the 81 corpus injection rows. A variant counts when v0.5.0 flags the original and the pipeline changes the text (9,056 applicable). Bypass is an applicable variant this scanner does not flag. Aggregates only.

| Composition family | v0.5.0 bypass | v0.6.0 bypass |
|---|---:|---:|
| Depth-2 overall | 30.80% (2,789/9,056) | 11.36% (1,029/9,056) |
| Reversal∘spacing | 63.73% (195/306) | 20.59% (63/306) |
| Reversal∘leet | 30.13% (94/312) | 27.56% (86/312) |
| Leet∘spacing | 88.46% (138/156) | 30.77% (48/156) |
| Leet∘punctuation splits | 75.64% (118/156) | 30.77% (48/156) |
| Nested base64 | 100% (78/78) | 7.69% (6/78) |
| Base64∘spacing | 76.28% (119/156) | 14.10% (22/156) |
| Base64∘punctuation splits | 58.97% (92/156) | 14.74% (23/156) |
| Base64∘leet | 80.77% (126/156) | 64.10% (100/156) |
| Reversal∘synonym | 6.54% (20/306) | 6.54% (20/306) |

- The six remaining nested-base64 misses are injections no decisive rule names. A composed or decoded view cannot add a classifier-only hit. `b64_wrap` then `leet`, and `b64_wrap` then `case_mix`, stay at 78/78: both destroy base64 bits, and the repair does not guess them.
- Corpus operating point is unchanged at threshold 0.5. Full benchmark: precision 0.9626, recall 0.8512, F1 0.9035, FPR 0.0667, injection recall 0.9630 (78/81), PII recall 0.6250, TP/FP/TN/FN 103/4/56/18. Held out (seed 13, 91 rows): precision 0.9630, recall 0.8525, F1 0.9043, FPR 0.0667, injection recall 0.9756, PII recall 0.6000, 52/2/28/9.
- Replaying the fixed 2,960 variants from the v0.3.0 TrustBreaker run: overall bypass 42.91% → 19.22% (1,270/2,960 → 569/2,960). char_reverse 34.93% (248/710) → 16.62% (118/710). word_reverse 33.24% (236/710) → 19.58% (139/710).
- Still open: synonym substitution (no inverse map), leet or case-mixing inside a base64 blob, a third encoding layer, URL-safe base64, the 4096-character decode cap, word-order-only system fences, and PII on reversed text. Percent-encoding and hex stay single-pass, so `%2520` does not become a second unescape. Some spaced base64 carriers still rejoin to an alphabet whose length is not a multiple of 4.

## 0.5.0 — 2026-11-19

- Add a reversal pass (`reversal.py`): alongside the existing normalized view, the scanner now evaluates character-reversed and word-reversed views of the input through the rule layer, but a reversed view may only contribute a decisive instruction pattern — the signal families the direct view treats as conclusive — never a weak or classifier-only signal. Context masking applies to the reversed views exactly as to the direct view, so quoted reversed text in benign prose stays quiet. The bundled classifier and its training are unchanged.
- Measured effect (full corpus @0.5): F1 0.8889 → 0.9035, injection recall 0.9259 → 0.9630 (78/81), FPR unchanged at 0.0667; held-out F1 0.8750 → 0.9043 at the same FPR. On TrustBreaker's fixed variant set, char_reverse bypass falls 86.48% → 34.93% and word_reverse 91.97% → 33.24%; composed families fall with them (diacritic 62.48% → 38.91%, punct_split 64.67% → 39.27%).
- Still open, by measurement: reversal composed with spacing across word boundaries or with synonym substitution (not invertible), nested/multi-layer encodings, non-Latin hyphen splits, and word-order-only system fences. PII detection on reversed text remains out of scope.

## 0.4.0 — 2026-11-18

- Extend the shared instruction and feature normalization with Latin diacritic folding, de-leeting for word-shaped tokens, and rejoining of single-letter spacing and short punctuation-delimited fragments. Keep the existing zero-width and lookalike folding. PII and encoded-candidate parsing use the original text. Decoded instructions use the shared normalization.
- Refit the bundled model on the 90 existing category-stratified benchmark training rows (seed 13). The 91 holdout rows and 48 default examples were excluded from the bundle fit. Reuse 1200 epochs, learning rate 1.0, L2 0.001, the 0.85 classifier cutoff, and the public scan threshold of 0.5.
- Leave character and word-order reversal out of scope. Unmarked reversals can turn ordinary text into apparent instructions and change the cues used by context masking. Short letter runs, ambiguous splits, and multi-layer encoding remain open.

| Evaluation at 0.5 | Precision | Recall | F1 | FPR | Injection recall | PII recall |
|---|---:|---:|---:|---:|---:|---:|
| Full benchmark (181, includes fitting rows) | 0.9615 | 0.8264 | 0.8889 | 0.0667 | 0.9259 | 0.6250 |
| Held out (91, inspected during development) | 0.9608 | 0.8033 | 0.8750 | 0.0667 | 0.9024 | 0.6000 |

Replaying the 2,960 applicable variants saved from the v0.3.0 TrustBreaker run reduced bypass from 88.28% to 71.72%. This comparison fixes the original variant set and its family assignments. The adaptive v0.4.0 measurement remains unverified.

## 0.3.0 — 2026-11-18

- Mask supported reporting quotes and locally negated actions for prose instruction rules and n-grams. Nearby activation, conditions and document-processing cues preserve suspicious text. Control syntax, encoded candidates and PII bypass the mask.
- Expand bounded override, persona, extraction, and multi-step patterns. Add French, Spanish, German, Japanese, Russian and Hindi override constructions, system tags, and single-pass percent decoding. Require an instruction-rule hit in decoded text.
- Refit the bundled model on the same 138 seed-13 fitting rows with 1200 epochs, L2 0.001 and the existing 0.85 classifier cutoff. The public threshold remains 0.5. Both corpora are unchanged.

| Evaluation | Precision | Recall | F1 | FPR | Injection recall | PII recall |
|---|---:|---:|---:|---:|---:|---:|
| Full benchmark (181, descriptive) | 0.9706 | 0.8182 | 0.8879 | 0.0500 | 0.9136 | 0.6250 |
| Held out (91, good-not-pristine) | 0.9800 | 0.8033 | 0.8829 | 0.0333 | 0.9024 | 0.6000 |

Full-benchmark benign flags fell from 10 to 3 and injection hits rose from 50 to 74. Default-corpus 5-fold evaluation flagged all 20 malicious rows and none of the 28 benign rows. [Benchmark results](evals/results/benchmark-v0.3.0.json)

## 0.2.0 — 2026-11-17

### Changed

- Normalize instruction rules and feature extraction with a documented finite Cyrillic/Greek homoglyph map, deletion of U+200B/U+200C/U+200D/U+FEFF, and casefolding. Preserve original text for PII and case-sensitive base64/JWT decoding; normalize decoded instructions afterward.
- Add bounded Chinese, Arabic, Portuguese, Korean, Turkish, and Italian override patterns, plus audited English policy cancellation, mode hijack, and developer/initialization prompt extraction constructions. Signal names, weights, feature width, and public threshold 0.5 remain unchanged.
- Rebuild the bundled stdlib logistic model from 48 default rows plus a fixed category-stratified benchmark training half (90 rows, seed 13); exclude 91 benchmark rows from fitting. Use 1200 epochs, L2 0.001, and a conservative intercept shift selected by training-only 5-fold CV. Keep generic train/eval defaults unchanged.
- Add reproducible benchmark/cutoff evaluation, split indices, model/corpus hashes, actual before/initial/after reports, and explicit disclosure of fitting-data overlap and development-holdout limitations.

### Measured — 2026-11-17

All comparisons use public threshold 0.5, CPython 3.12.3. The 91-row holdout is good-not-pristine.

| Evaluation | Precision before → after | Recall before → after | F1 before → after | FPR before → after |
|---|---|---|---|---|
| Full benchmark (181; includes 90 fitting rows after) | 0.8750 → 0.8824 | 0.4050 → 0.6198 | 0.5537 → 0.7282 | 0.1167 → 0.1667 |
| Benchmark holdout (91) | 0.8889 → 0.8780 | 0.3934 → 0.5902 | 0.5455 → 0.7059 | 0.1000 → 0.1667 |
| Default corpus, 5-fold (48) | 1.0000 → 1.0000 | 0.8000 → 0.8000 | 0.8889 → 0.8889 | 0.0000 → 0.0000 |

- Injection recall: 0.2963 → 0.6173 full; 0.2927 → 0.5854 held out. PII recall stays 0.6250 full / 0.6000 held out.
- The initial expanded model's held-out FPR was 0.4333. Conservative cutoff selection reduces it to 0.1667 while giving up 11 true positives; FPR still exceeds the original 0.1000. See README.md for all counts and the tuning tradeoff.
- Regression suite: 130 tests, including obfuscated/non-English injections, training/inference feature parity, benign native-language text, disjoint fixed splits, and preserved PII/checksums/encoded payloads.

## 0.1.0 — 2026-11-12

### Added

- First release of PromptWarden, a stdlib-only first-stage scan for prompt injection and sensitive-data leakage.
- Deterministic rule signals for instruction override, role hijack, system-prompt extraction, fake system turns, fenced system blocks, chat-template tokens, encoded payloads, and urgency or secrecy markers.
- PII and secret shapes: email, phone (including Indian 10-digit numbers), PAN, Aadhaar with a Verhoeff checksum, credit cards with a Luhn check, API-key shapes, and private-key headers.
- Hashed token and character n-gram features plus the rule-signal vector.
- Full-batch L2 logistic regression (`train`, `predict_proba`, JSON save/load). Training refuses fewer than 20 rows or a single class.
- `Warden.scan` score is `max(rule score, P(malicious))` when a model is loaded, and the rule score alone when the model file is missing (`rules_only`).
- CLI: `scan` (exit 1 when flagged), `train`, and `eval` (train/test split when the corpus has one, otherwise deterministic 5-fold cross-validation).
- Bundled model `src/promptwarden/default_model.json`, fit on every row of `examples/default_corpus.jsonl` (48 labeled rows).

### Measured

Default-corpus 5-fold cross-validation, CPython 3.12.3, `promptwarden eval --corpus examples/default_corpus.jsonl`:

| | |
|---|---|
| precision | 1.000000 |
| recall | 0.800000 |
| F1 | 0.888889 |
| FPR | 0.000000 |
| n / tp / fp / tn / fn | 48 / 16 / 0 / 28 / 4 |

A rules-only pass over the same 48 rows produces the same confusion counts. The four false negatives are paraphrase attacks that match no rule. See README.md.
