"""Finite, deliberately lossy normalization for instruction matching and features.

This is not transliteration or Unicode compatibility normalization. Identifiers
and encoded payloads must still be inspected in the original text. See SPEC.md
for the complete map and the two text paths used by the scanner.
"""

from __future__ import annotations

# Explicit upper/lower pairs matter: Greek capital upsilon resembles Y, while
# small upsilon resembles u. Casefolding before translation would lose that.
_HOMOGLYPHS = {
    "А": "A",
    "а": "a",
    "В": "B",
    "Е": "E",
    "е": "e",
    "К": "K",
    "М": "M",
    "Н": "H",
    "О": "O",
    "о": "o",
    "Р": "P",
    "р": "p",
    "С": "C",
    "с": "c",
    "Т": "T",
    "Х": "X",
    "х": "x",
    "У": "Y",
    "у": "y",
    "І": "I",
    "і": "i",
    "Ј": "J",
    "ј": "j",
    "Ѕ": "S",
    "ѕ": "s",
    "Α": "A",
    "α": "a",
    "Β": "B",
    "β": "b",
    "Ε": "E",
    "ε": "e",
    "Ζ": "Z",
    "Η": "H",
    "Ι": "I",
    "ι": "i",
    "Κ": "K",
    "κ": "k",
    "Μ": "M",
    "Ν": "N",
    "ν": "v",
    "Ο": "O",
    "ο": "o",
    "Ρ": "P",
    "ρ": "p",
    "Τ": "T",
    "τ": "t",
    "Υ": "Y",
    "υ": "u",
    "Χ": "X",
    "χ": "x",
    "Ϲ": "C",
    "ϲ": "c",
}
_TRANSLATION = str.maketrans({**_HOMOGLYPHS, **dict.fromkeys("\u200b\u200c\u200d\ufeff", "")})


def normalize(text: str) -> str:
    """Remove four zero-width characters, fold lookalikes, and casefold.

    ASCII digits and separators are unchanged. The input is never modified.
    The operation is idempotent and is shared by training and inference.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    # Casefold can itself introduce a mapped character (e.g. Greek beta
    # symbol ϐ -> β). A final translation makes normalization idempotent.
    return text.translate(_TRANSLATION).casefold().translate(_TRANSLATION)
