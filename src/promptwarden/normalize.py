"""Canonicalize the text used by instruction rules and lexical features."""

from __future__ import annotations

import re
import unicodedata

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
_LOOKALIKES = str.maketrans(_HOMOGLYPHS)
_ZERO_WIDTH = str.maketrans("", "", "\u200b\u200c\u200d\ufeff")
_LEET = str.maketrans("431057", "aeiost")
_LEET_WORD = re.compile(r"\b[a-z013457]{3,19}\b")
_DIGIT_RUN = re.compile(r"[0-9]{3}")

# A single horizontal separator joins letters. Wider gaps and line breaks
# preserve word and control-syntax boundaries.
_SPACED = re.compile(r"(?<![\w-])[a-z013457](?:[ \t][a-z013457]){3,}(?![\w-])")
_HYPHEN_SPLIT = re.compile(r"(?<![\w-])[a-z013457]{1,2}(?:-[a-z013457]{1,2}){2,}(?![\w-])")
_PUNCT_SPLIT = re.compile(
    r"(?<![\w._·])[a-z013457](?P<separator>[._·])[a-z013457]"
    r"(?:(?P=separator)[a-z013457]){2,}(?!\w|[._·]\w)"
)
_SEPARATORS = str.maketrans("", "", " \t-._·")
_SHORT_WORDS = frozenset(
    "a am an as at be by do go he i if in is it me my no of oh ok on or so to up us we".split()
)


def fold_unicode(text: str) -> str:
    """Fold case, lookalikes and Latin diacritics for text or rule patterns."""

    text = text.translate(_ZERO_WIDTH)
    if text.isascii():
        return text.casefold()
    # Canonically equivalent accents must take the same path through the map.
    text = unicodedata.normalize("NFC", text).translate(_LOOKALIKES)
    # Casefold can introduce a mapped character, such as ϐ -> β.
    text = unicodedata.normalize("NFC", text.casefold()).translate(_LOOKALIKES)
    folded = []
    latin_base = False
    for char in unicodedata.normalize("NFD", text):
        if not unicodedata.category(char).startswith("M"):
            latin_base = unicodedata.name(char, "").startswith("LATIN ")
        elif latin_base:
            continue
        folded.append(char)
    return unicodedata.normalize("NFC", "".join(folded))


def _is_leet_word(word: str) -> bool:
    return (
        not word.isalpha()
        and sum(char.isalpha() for char in word) >= 2
        and _DIGIT_RUN.search(word) is None
    )


def _join_fragments(match: re.Match[str]) -> str:
    text = match[0]
    # Short hyphenated phrases like "up-to-us" have the same shape as splits.
    if "-" in text and all(fragment in _SHORT_WORDS for fragment in text.split("-")):
        return text
    word = text.translate(_SEPARATORS)
    if len(word) >= 4 and (word.isalpha() or (_LEET_WORD.fullmatch(word) and _is_leet_word(word))):
        return word
    return text


def normalize(text: str) -> str:
    """Fold Unicode and repair word-shaped letter splits and leetspeak.

    Training and inference share this view. PII checks and encoded-candidate
    parsing use the original input.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    folded = fold_unicode(text)
    for pattern in (_SPACED, _HYPHEN_SPLIT, _PUNCT_SPLIT):
        folded = pattern.sub(_join_fragments, folded)
    return _LEET_WORD.sub(
        lambda match: match[0].translate(_LEET) if _is_leet_word(match[0]) else match[0], folded
    )
