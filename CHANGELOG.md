# Changelog

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
