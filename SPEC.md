# PromptWarden specification

PromptWarden is the fourth piece in a trustworthy-LLM line, after VeraScan, CertiRoute, and PromptRegress. It scans text going into or out of a model and flags prompt injection and sensitive-data leakage.

This is a first-stage guardrail, not a guarantee. A clear rule hit should be stopped here. A paraphrase, another language, or a novel secret shape can pass. Callers that need a bound on residual risk still need a second stage.

Python `>= 3.11`. Runtime dependencies: none. The package imports only the standard library.

## Public contract

```python
from promptwarden import Warden, ScanResult

Warden(threshold: float = 0.5)
Warden().scan(text: str) -> ScanResult
```

`ScanResult` is a frozen dataclass:

| Field | Meaning |
|---|---|
| `score` | Float in `[0, 1]`. |
| `flagged` | `True` when `score >= threshold`. The comparison is inclusive. |
| `categories` | Subset of `{"injection", "pii"}`, in that order. Empty when the text is not flagged, and empty when the flag comes only from the classifier. |
| `signals` | Names of the rule signals that fired, in detector order. `classifier` is appended when a model is loaded and its probability is at least the threshold. `rules_only` is appended when no model is loaded. The two markers never appear together. |

`threshold` outside `[0, 1]`, a non-numeric threshold, or a non-string `text` raises. A threshold of `0` flags every scan, including a score of `0`.

`Warden` accepts keyword-only `model` or `model_path` for tests and for `eval`. The default loads `default_model.json` from the package. A missing file selects rules-only mode. A present file that is corrupt, or whose width does not match the feature layout, raises `ValueError`. The scanner does not fail open on a broken model.

## Pipeline

```mermaid
flowchart TD
  T[Original text] --> U[Normalize instruction text]
  U --> C[Bounded context masking]
  U --> R[Control syntax rules]
  C --> A[Prose instruction rules]
  T --> I[PII and encoded-blob rules]
  C --> N[Hashed n-grams]
  I --> S
  I --> V
  R --> S[Rule score]
  R --> V[Signal bits]
  A --> S
  A --> V
  N --> F[Feature vector]
  V --> F
  F --> P["P(malicious)"]
  S --> M["score = max(rule score, P)"]
  P --> M
  M --> D{score >= threshold}
```

### Normalization and the original text

`promptwarden.normalize.normalize` removes U+200B (zero-width space), U+200C (zero-width non-joiner), U+200D (zero-width joiner), and U+FEFF (including mid-text). It then translates only the finite Cyrillic/Greek lookalike map below and applies Unicode `str.casefold()`. Translation precedes casefolding so Greek `Υ` becomes `y` while `υ` becomes `u`. A final pass through the same map folds characters introduced by casefolding (for example `ϐ` casefolds to `β`, then maps to `b`), making the operation idempotent. It does not transliterate whole languages, apply NFKC, remove accents, rewrite digits, decode URL escapes, collapse spaced letters, or repair leetspeak.

The table gives the complete explicit source map and its final Latin output after casefolding. Characters absent from the table undergo ordinary casefolding, the four deletions, and mapping of any resulting listed characters.

| Latin output | Cyrillic sources | Greek sources |
|---|---|---|
| `a` | `А а` | `Α α` |
| `b` | `В` | `Β β` |
| `c` | `С с` | `Ϲ ϲ` |
| `e` | `Е е` | `Ε ε` |
| `h` | `Н` | `Η` |
| `i` | `І і` | `Ι ι` |
| `j` | `Ј ј` | — |
| `k` | `К` | `Κ κ` |
| `m` | `М` | `Μ` |
| `n` | — | `Ν` |
| `o` | `О о` | `Ο ο` |
| `p` | `Р р` | `Ρ ρ` |
| `s` | `Ѕ ѕ` | — |
| `t` | `Т` | `Τ τ` |
| `u` | — | `υ` |
| `v` | — | `ν` |
| `x` | `Х х` | `Χ χ` |
| `y` | `У у` | `Υ` |
| `z` | — | `Ζ` |

`rules.detect` normalizes before instruction matching. `features.extract` normalizes before truncating or building n-grams. Every PII detector uses the original text, preserving identifier case, digit sequences, and separators. Card and Aadhaar validation use Luhn and Verhoeff on original digits.

Encoded candidates also use the original text. Base64 and JWT components are case-sensitive. Decoded UTF-8 instructions are normalized before rule checks. The scanner leaves the input intact.

### Bounded context masking

`promptwarden.context.instruction_view` replaces eligible spans with spaces and preserves offsets and line breaks in the normalized text. The override, role, extraction and urgency or secrecy rules and model n-grams use this view. The same feature representation is used for training and inference.

- Single-line spans of up to 1000 characters inside ASCII or curly quotes or single backticks can be masked when an explicit reporting frame borders the span in the same sentence. Examples include a log recording literal words or a test using a fixture. Quotation marks and labels such as `Blocked prompt:` alone leave the text visible.
- An execution cue, conditional qualifier, or recognizable document-processing request in either adjacent 160-character window leaves the quote visible. A cue inside the quote that addresses the model also leaves it visible.
- A locally negated supported action can be masked. The mask stops at clause boundaries and other action verbs. Nearby conditional or exception language leaves the instruction visible. Negating obedience to prior instructions can itself signal an override.

Control syntax (system turns and fences, chat-template tokens), encoded candidates and all PII bypass masking. Context is inferred from the text itself and can be misleading. A payload can still pass if it resembles an inert report closely enough, or uses an activation cue outside the supported wording or window.

## Rules

`promptwarden.rules.detect` returns each signal at most once. Weights are already on the score scale. The rule score is the sum of fired weights, clipped to `[0, 1]`. Every weight is at least `0.60`, so one fired signal flags at the default threshold of `0.5` with no model at all.

| Signal | Family | Weight | What fires it |
|---|---|---|---|
| `instruction_override` | injection | 0.85 | A bounded override of prior instructions or safeguards, including the language constructions below |
| `role_hijack` | injection | 0.70 | A persona assignment naming DAN or JailbreakGPT or coupled with a waiver of restrictions, or a request or assertion that assigns unrestricted, developer or privileged mode |
| `system_prompt_extraction` | injection | 0.80 | A disclosure verb within 64 same-clause characters of a supported target such as `system prompt` or `hidden developer instructions`. Also recognizes bounded queries for the prompt, initialization-policy requests, story-framed continuation, and `print everything above` |
| `fake_system_turn` | injection | 0.75 | A line beginning with `system:` or a `<system>` / `</system>` tag |
| `system_fence` | injection | 0.75 | A fence opened as ` ```system ` |
| `chat_template_token` | injection | 0.90 | `<\|im_start\|>`, `<\|im_end\|>`, `<\|system\|>`, `<\|user\|>`, `<\|assistant\|>`, `[INST]`, `[/INST]`, `<<SYS>>`, `<</SYS>>` |
| `encoded_payload` | injection | 0.85 | A base64, hex or percent-escaped candidate whose UTF-8 decoding matches an instruction rule |
| `urgency_secrecy` | injection | 0.60 | `do not tell anyone`, `keep this secret`, `bypass your safety`, `no one will know`, and close pairs of `urgent` with `ignore` / `bypass` / `override` / `secret` |
| `email` | pii | 0.70 | `local@domain.tld` |
| `phone` | pii | 0.65 | Indian 10-digit mobiles (`[6-9]` plus 9 digits, optional leading `0` or `+91`, optional grouping) and NANP numbers that use separators |
| `pan` | pii | 0.80 | `ABCDE1234F` shape, five letters, four digits, one letter |
| `aadhaar` | pii | 0.85 | `#### #### ####` (spaces or hyphens) or 12 contiguous digits, first digit 2–9, Verhoeff checksum 0 |
| `credit_card` | pii | 0.85 | 13–19 digits, grouped or contiguous, that pass Luhn. Format alone is not a signal |
| `api_key` | pii | 0.90 | `sk-` / `sk-proj-` / `sk-ant-` / `sk-live-` / `sk-test-` plus 20 alphanumerics, `ghp_` plus 36, `AKIA` plus 16, `xoxb-` with two or more segments, or a JWT whose header decodes to a JSON object containing `alg` |
| `private_key` | pii | 0.95 | `-----BEGIN … PRIVATE KEY-----` including RSA, OPENSSH, EC, DSA, and PGP |

### Bounded override patterns

English overrides pair verbs such as `ignore`, `disregard`, `discard`, `drop` or `disable` with an instruction or safeguard object, with up to five specified modifiers in between. The pattern also covers commands such as `do not follow your previous instructions`. Other constructions include disregarding everything before the current message, pretending prior rules do not apply, answering without safety filters, translating to bypass rules, and a bounded two-step confirmation followed by a request to continue uncensored.

The following regexes also emit `instruction_override`. They are compiled after applying the same normalization as the input, including lookalike folding for the Russian pattern. Each covers a specific construction.

| Language | Regex |
|---|---|
| Chinese | `忽略.{0,24}(?:之前|先前|以前).{0,12}(?:指令|指示)` |
| Arabic | `تجاهل\s+(?:كل\s+)?(?:القواعد\|التعليمات)\s+السابقة` |
| Portuguese | `\b(?:ignore\|desconsidere)\s+(?:todas?\s+)?(?:as?\s+)?(?:instruções\|regras)\s+anteriores\b` |
| Korean | `지금부터\s*(?:너는\s*)?제한\s*없는\s*dan` |
| Turkish | `\bgüvenlik\s+(?:ilkelerini\|kurallarını)\s+geçersiz\s+kıl\b` |
| Italian | `\b(?:dimentica\|ignora)\s+(?:le\s+)?(?:linee\s+guida\|istruzioni)\s+precedenti\b` |
| French | `\b(?:ignore\|ignorez)\s+(?:toutes?\s+)?(?:les?\s+)?(?:instructions\|règles)\s+précédentes\b` |
| Spanish | `\bignora\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones\|reglas)\s+anteriores\b` |
| German | `\bignoriere\s+(?:alle\s+)?(?:vorherigen\|bisherigen)\s+(?:anweisungen\|regeln)\b` |
| Japanese | `(?:前\|以前)の(?:指示\|命令)を(?:すべて)?無視` |
| Russian | `\bигнорируй\s+(?:все\s+)?предыдущие\s+(?:инструкции\|правила)\b` |
| Hindi | `पिछले\s+(?:सभी\s+)?निर्देशों\s+को\s+नजरअंदाज\s+करें` |

The backslashes before table pipes are Markdown escaping. The Korean construction begins “from now on” and assigns an unrestricted DAN persona.

### Luhn

`luhn_ok` walks the digits from the right. The check digit is not doubled. Every second digit to its left is doubled, and a product above 9 is reduced by 9. The number passes when the total is divisible by 10. The card detector applies this only inside a 13–19 digit window. `79927398713` passes. `79927398714` does not. `4111111111111111` passes. `4111111111111112` does not, and it is not a signal.

### Verhoeff

`verhoeff_ok` uses the standard dihedral tables. The checksum of a valid number is 0. Wikipedia's worked example is the anchor: the check digit of `236` is `3`, so `2363` is valid and `2369` is not. Aadhaar candidates that fail the checksum are not signals. A 12-digit string whose first digit is 0 or 1 is not a candidate.

### Encoded payloads

Base64 candidates are runs of at least 32 standard alphabet characters with optional padding and a total length divisible by four after the 4096-character decoding cap. Hex candidates are runs of at least 32 hex digits and are decoded up to the same cap in pairs. A contiguous URL-style token qualifies when it contains at least one `%HH` byte escape within the cap. Literal plus signs are preserved. The bytes must decode as UTF-8 and contain at least eight letters. The normalized result must match a prose instruction or control syntax rule. Each candidate is decoded once and checked without context masking.

## Features

`promptwarden.features.extract` builds one deterministic vector. Python's salted `hash` is not used. The hash is FNV-1a 32-bit.

The layout is `FEATURE_DIM = 256 + len(SIGNAL_NAMES)` (271 in this version):

- `[0, 256)` — binary hashed token unigrams, token bigrams, and character trigrams, then L2-normalised. Only the first 4000 characters and the first 512 tokens are featurised. Collisions are expected.
- `[256, 271)` — one column per rule signal, `1.0` when that signal fired. This block is not normalised, so a fired rule stays large next to the unit-norm n-gram block.

The same context view and signal names always produce the same vector. Normalization and masking precede the character cap and tokenization. Custom models trained before v0.3.0 should be refit for the updated lexical and rule features. The 271-column layout and model JSON schema still load.

## Classifier

`promptwarden.classifier.train` fits a binary logistic regression.

- Weights and the intercept start at 0. There is no shuffle and no RNG.
- Each epoch is full-batch gradient descent on the mean Bernoulli log loss plus `(l2 / 2) * ||w||^2`. The intercept is not penalised.
- Defaults: learning rate `1.0`, `400` epochs, L2 `0.01`.
- `train` raises `ValueError` on fewer than 20 rows, on a single class, on a label other than `0` or `1`, and on non-finite or ragged features.
- `Model.predict_proba` returns `P(label = 1)`. Logits are clipped to `[-30, 30]` before the sigmoid.
- `save` / `load` use JSON (`promptwarden-model-v1`). Full-width models also store `ngram_dim` and the signal list, and `load` rejects a schema that does not match the code.

## Scoring

```
rule_score = min(1, sum of fired weights)
p          = predict_proba(features)     # only when a model is loaded
score      = rule_score                  # rules-only
score      = max(rule_score, p)          # model loaded
flagged    = score >= threshold
```

`max` is the combination. A Luhn hit, a private-key header, or an instruction override is already on the 0–1 scale. Averaging it with a low probability would let the model hide a credential or an obvious injection. The classifier can raise the score when the rules are silent. It cannot clear a rule.

`categories` lists the families of the rule signals that fired, and only when `flagged` is true. The model is binary, so a classifier-only flag has empty categories. `signals` still lists `classifier` in that case.

The intercept is not L2-penalised. Increasing the malicious proportion can increase model-only false positives, especially with n-gram collisions. The v0.3.0 bundled intercept, including its shift, is `-2.9909049290200249`. `promptwarden scan "The cat sat on the mat."` prints `score: 0.034886`.

## Corpus and bundled model

`examples/default_corpus.jsonl` has 48 rows. Each line is `{"text", "label", "category"}` with `label` of `malicious` or `benign` and `category` of `injection`, `pii`, or `benign`. There is no `split` field.

| Rows | Count | Rules |
|---|---|---|
| Malicious, injection, a rule fires | 13 | One or more injection signals, including base64 and hex payloads |
| Malicious, pii, a rule fires | 7 | Email, phone, PAN, Aadhaar, card, API-key shapes, private-key header |
| Benign, no rule fires | 28 | Hard negatives (near misses, invalid Luhn, public-key header, short `sk-test`) and ordinary prose, including short utterances |

v0.3.0 rules catch four paraphrases missed by v0.2.0. They cover pretending prior directions no longer apply, assigning an unfiltered assistant role, restating a policy set before the conversation, and translating a request to skip rules.

Every rule signal name appears at least once. No benign row fires a rule. Secrets in the file are shapes and documentation samples (`jane.doe@example.com`, `AKIAIOSFODNN7EXAMPLE`, a Verhoeff-valid synthetic Aadhaar `2345 6789 0124`, the header `BEGIN RSA PRIVATE KEY` with the body `not-a-real-key`).

Rebuild the bundled model from the repository root:

```bash
python scripts/train_default_model.py
```

The command fits **all 48 default rows followed by 90 benchmark training rows**, in file order within each source (138 total, with 53 injection, 27 PII and 58 benign). v0.3.0 reuses the v0.2.0 split and refits on the updated rule and lexical features. Both corpus files are unchanged.

`evaluate.stratified_half` fixes the split of `evals/corpus.jsonl` (181 rows):

1. Create one local `random.Random(13)`.
2. For categories in sorted order (`benign`, `injection`, `pii`), collect zero-based corpus indices and shuffle that list with the same RNG.
3. Assign the first `len(category) // 2` indices to training, leaving the rest held out.
4. Return both partitions in original corpus order. Training counts are 30 benign / 40 injection / 20 PII; holdout counts are 30 / 41 / 20.

The bundle uses learning rate 1.0, **1200 epochs, L2 0.001**, selected on training rows to remove classifier false positives on default-corpus benign fixtures (the initial 400-epoch, L2 0.01 fit introduced three). Default-corpus 5-fold still uses 400 epochs and L2 0.01, training only on default rows; it is a separate comparison and does not reuse the bundle.

For v0.2.0, training-only 5-fold cross-validation on the 138 training rows selected classifier cutoff **0.85** from 0.50–0.90 in steps of 0.05. The objective was highest pooled F1 subject to pooled FPR <= 0.10, with ties going to the smaller cutoff. The selected training-CV point had F1 0.7770 and FPR 0.0862. v0.3.0 retains this classifier cutoff and the public scan threshold of 0.5.

After fitting all 138 rows, subtract `log(0.85 / (1 - 0.85)) = 1.7346010553881064` from the fitted intercept and save the model. Thus at the public threshold 0.5 the classifier requires an unshifted probability of at least 0.85. The runtime still computes `max(rule_score, model.predict_proba(features))`; no rule score changes and no new runtime calibration code are needed. At other public thresholds, the shifted probability remains monotonic but is a conservative score, not a calibrated frequency estimate.

The report records both corpus hashes, the model hash, and 1-based split indices. Run the headline harness from the repository root.

```bash
python scripts/evaluate_default_model.py --out evals/results/benchmark-v0.3.0.json
```

Historical reports show the original v0.1.0 bundle, the unshifted and shipped v0.2.0 bundles, and the v0.2.0 training-only cutoff audit. [v0.1.0](evals/results/2026-11-17-before.json) · [v0.2.0 unshifted](evals/results/2026-11-17-initial.json) · [v0.2.0 shipped](evals/results/2026-11-17-after.json) · [v0.2.0 training CV](evals/results/2026-11-17-training-cv.json)

## Evaluation

`promptwarden eval --corpus F` scores the positive class `malicious` with `Warden.scan`, so the numbers include the rules.

- If every row has `split` of `train` or `test`, one model is trained on the train rows and metrics are computed on the test rows only (`method: train-split`).
- Otherwise the rows are split into 5 folds by `index % 5`. Each fold trains on the other rows, in file order, and scores the held-out rows. Metrics are pooled (`method: kfold-5`). A fold whose training set has fewer than 20 rows, or a single class, raises.

Reported metrics are precision, recall, F1, and false-positive rate, plus the confusion counts. A rate whose denominator is 0 is reported as 0.

`promptwarden train` is separate. It fits every row and ignores `split`.

On `examples/default_corpus.jsonl`, 5-fold evaluation and rules alone both give counts of 20 TP, 0 FP, 28 TN and 0 FN at 0.5. The corpus contains 48 rows and served as development data.

`scripts/evaluate_default_model.py` reports the shipped model on all 181 benchmark rows and the 91 rows excluded from fitting at threshold 0.5. It checks normalized-text disjointness from combined training. The full score is descriptive because it includes 90 fitting rows. The holdout is good-not-pristine because development inspected it, including during v0.2.0. The CLI's `eval` command trains models in its own split or folds.

From v0.2.0 to v0.3.0, full-benchmark F1 rose from 0.7282 to 0.8879, injection recall from 0.6173 to 0.9136, and FPR fell from 0.1667 to 0.0500. On the good-not-pristine holdout, F1 rose from 0.7059 to 0.8829, injection recall from 0.5854 to 0.9024, and FPR fell from 0.1667 to 0.0333. PII recall was 0.6250 full and 0.6000 on the good-not-pristine holdout in both versions. Rules alone and the v0.3.0 bundle flag the same benchmark rows at 0.5. [Benchmark tables](README.md#audited-benchmark-181-adversarial-examples) · [v0.3.0 results](evals/results/benchmark-v0.3.0.json)

## Command line

| Command | Behaviour | Exit |
|---|---|---|
| `promptwarden scan TEXT` | Print score, flagged, categories, signals | 1 if flagged, else 0 |
| `promptwarden scan --file F` | Same, text read as UTF-8 | 1 if flagged, else 0 |
| `promptwarden train --corpus F --out F` | Fit every row and write a model JSON | 0, or 2 on a data error |
| `promptwarden eval --corpus F` | Print the report described above | 0, or 2 on a data error |

Passing both `TEXT` and `--file`, or neither, exits 2. `--threshold` overrides the default `0.5` on `scan` and `eval`.

## Threat model and limits

v0.3.0 covers the English and twelve additional-language constructions above, the documented homoglyph map and zero-width deletions, the supported encodings, and the listed identifier shapes.

Known limits, measured or structural:

- Reported prose may resemble an instruction closely enough to flag. A real instruction may resemble inert reporting closely enough to be masked. Control syntax and encoded instruction examples can flag in documentation.
- Other language constructions and unmapped homoglyphs can pass. Removing U+200C/U+200D and folding lookalikes is lossy for genuine native-language text. Fullwidth substitutions can evade the rules. v0.6.0 repairs single-letter spacing, short punctuation splits, leetspeak, and reversal on decisive instruction views, including a second transform stacked on the first. Synonym substitution is not inverted. A system fence is not checked on a word-order view.
- Aadhaar and card checks reject format-only matches. A different 12-digit or 13–19 digit string that happens to satisfy the checksum still fires. Random digit strings pass Verhoeff or Luhn about one time in ten.
- API-key signals are shapes. `AKIAIOSFODNN7EXAMPLE` is the AWS documentation sample and it fires, because the shape matches.
- URL-safe base64, a third encoding layer, leet or case-mixing inside a base64 blob, and instructions beyond the 4096-character decoding cap can pass. A second standard base64 layer is decoded. Percent-encoding and hex stay single-pass.
- Hashed n-grams collide in 256 buckets. The bundled linear model fits 138 rows and uses a conservative intercept shift. Lexical matches and classifier scores provide limited coverage of new paraphrases.
- PII detection is intentionally on original text. Obfuscated identifiers (including zero-width characters within an identifier) and unsupported shapes such as addresses, passwords, SSNs, IBANs, and passports may be missed.
- The scanner does not know who wrote the text. A system prompt, a user message, and a tool result are scored the same way.
- `categories` is empty for a classifier-only flag. Downstream policy that branches on category must treat that case as an unspecified positive.

Ship this in front of a stronger checker or a human review queue. Do not treat a score under the threshold as proof that the text is safe.
