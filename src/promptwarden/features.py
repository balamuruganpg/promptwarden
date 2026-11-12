"""Hashed n-gram features plus the rule-signal vector.

The vector is deterministic and seed-free. Python's built-in ``hash`` is not
used, because it is salted per process.

Layout, length :data:`FEATURE_DIM` = :data:`NGRAM_DIM` + ``len(SIGNAL_NAMES)``:

* ``[0, NGRAM_DIM)`` — binary hashed token unigrams, token bigrams, and
  character trigrams. The block is L2-normalised so a long document does not
  dominate the linear model. Hash collisions are expected; the dimension is
  fixed at 256.
* ``[NGRAM_DIM, FEATURE_DIM)`` — one column per name in
  :data:`promptwarden.rules.SIGNAL_NAMES`, ``1.0`` when that signal fired and
  ``0.0`` otherwise. This block is not normalised, so a fired rule stays a
  large feature next to a unit-norm n-gram block.

Tokenisation keeps runs of letters, digits, and the characters ``_<>|./+-``.
Character trigrams are taken from the lowercased text with whitespace
collapsed to a single space. Only the first :data:`NGRAM_CHARS` characters and
the first :data:`NGRAM_TOKENS` tokens are featurised. Rule signals are computed
by the caller on the full text and passed in; this module does not re-run them.

The hash is FNV-1a 32-bit (offset basis ``2166136261``, prime ``16777619``)
modulo :data:`NGRAM_DIM`. The hashed string is ``t1``, ``t2``, or ``c3``, a
NUL, then the gram, so the three families do not share a key space.
"""

from __future__ import annotations

import math
import re
from collections.abc import Sequence

from promptwarden.rules import SIGNAL_NAMES

NGRAM_DIM = 256
NGRAM_CHARS = 4000
NGRAM_TOKENS = 512
FEATURE_DIM = NGRAM_DIM + len(SIGNAL_NAMES)

_FNV_OFFSET = 2166136261
_FNV_PRIME = 16777619
_TOKEN = re.compile(r"[A-Za-z0-9_<>|./+-]+")
_SIGNAL_INDEX = {name: index for index, name in enumerate(SIGNAL_NAMES)}


def fnv1a_32(text: str) -> int:
    """FNV-1a 32-bit hash of a Unicode string's UTF-8 bytes."""

    digest = _FNV_OFFSET
    for byte in text.encode("utf-8"):
        digest ^= byte
        digest = (digest * _FNV_PRIME) & 0xFFFFFFFF
    return digest


def feature_dim() -> int:
    """Length of the vector :func:`extract` returns."""

    return FEATURE_DIM


def extract(text: str, fired_signals: Sequence[str] = ()) -> list[float]:
    """Return the feature vector for ``text`` given signals that already fired.

    ``fired_signals`` must be names from :data:`SIGNAL_NAMES`. Unknown names
    raise ``ValueError``. The same text and the same signal names always
    produce the same vector.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    vector = [0.0] * FEATURE_DIM
    _fill_ngrams(vector, text)
    for name in fired_signals:
        index = _SIGNAL_INDEX.get(name)
        if index is None:
            raise ValueError(f"unknown signal {name!r}")
        vector[NGRAM_DIM + index] = 1.0
    return vector


def _fill_ngrams(vector: list[float], text: str) -> None:
    sample = text[:NGRAM_CHARS]
    tokens = [match.group(0).lower() for match in _TOKEN.finditer(sample)]
    if len(tokens) > NGRAM_TOKENS:
        tokens = tokens[:NGRAM_TOKENS]
    for token in tokens:
        vector[_bucket("t1", token)] = 1.0
    for left, right in zip(tokens, tokens[1:], strict=False):
        vector[_bucket("t2", left + "\x00" + right)] = 1.0
    compact = re.sub(r"\s+", " ", sample.lower())
    for index in range(len(compact) - 2):
        vector[_bucket("c3", compact[index : index + 3])] = 1.0
    norm = math.sqrt(sum(value * value for value in vector[:NGRAM_DIM]))
    if norm > 0.0:
        for index in range(NGRAM_DIM):
            if vector[index]:
                vector[index] /= norm


def _bucket(kind: str, gram: str) -> int:
    return fnv1a_32(kind + "\x00" + gram) % NGRAM_DIM
