"""Composed instruction views.

TrustBreaker stacks two operators. Several of those stacks do not commute with
a single normalize-then-reverse pass:

* spacing after reversal erases word boundaries, so reversing the joined blob
  flips the whole concatenation instead of each word
* leet inside a three-digit run (``710`` in ``instructions``) is refused by the
  shared normalizer, which also feeds the classifier
* a second base64 wrap, or spaces, hyphens, marks, or lookalikes inside a
  base64 blob, never reaches the one-shot decoder

This module builds the missing readings. Callers may use them only for
decisive instruction patterns. The shared normalizer, the n-gram view, and PII
stay on the direct text. Context masking runs on every reading, before and
after the repair, the same way the reversal views mask.
"""

from __future__ import annotations

import re
from unicodedata import category

from promptwarden.context import instruction_view
from promptwarden.normalize import (
    _LEET,
    _LOOKALIKES,
    _SEPARATORS,
    _SHORT_WORDS,
    _ZERO_WIDTH,
    fold_unicode,
)
from promptwarden.reversal import (
    _VOCAB,
    InstructionView,
    char_reverse,
    instruction_bases,
    word_reverse,
)

# Longer than the reversal segment cap so a fused sentence still splits, and
# shorter than a document so the dynamic program stays bounded.
_FUSED_MAX = 256

# Fragments of one or two characters. Longer hyphenated words stay words.
# These classes are ASCII on purpose. A Unicode letter class matches a
# Devanagari base and leaves its vowel sign behind, which corrupts the word.
# Non-ASCII graphemes are rejoined by :func:`_join_graphemes`.
_LEET_HYPHEN = re.compile(r"(?<![\w-])[a-z013457]{1,2}(?:-[a-z013457]{1,2}){2,}(?![\w-])")
_LEET_PUNCT = re.compile(
    r"(?<![\w._·])[a-z013457](?P<separator>[._·])[a-z013457]"
    r"(?:(?P=separator)[a-z013457]){2,}(?!\w|[._·]\w)"
)
_LEET_SPACE = re.compile(r"(?<![\w-])[a-z013457](?:[ \t][a-z013457]){3,}(?![\w-])")

# Words from the multilingual override patterns. Spacing fuses adjacent long
# words; the segmenter puts the boundaries back. Folded at import so the list
# matches the view.
_MULTILINGUAL_WORDS: tuple[str, ...] = (
    "忽略",
    "之前",
    "先前",
    "以前",
    "指令",
    "指示",
    "تجاهل",
    "كل",
    "القواعد",
    "التعليمات",
    "السابقة",
    "desconsidere",
    "todas",
    "toda",
    "as",
    "instruções",
    "regras",
    "anteriores",
    "지금부터",
    "너는",
    "제한",
    "없는",
    "güvenlik",
    "ilkelerini",
    "kurallarını",
    "geçersiz",
    "kıl",
    "dimentica",
    "ignora",
    "linee",
    "guida",
    "istruzioni",
    "precedenti",
    "ignorez",
    "toutes",
    "toute",
    "les",
    "règles",
    "précédentes",
    "las",
    "instrucciones",
    "reglas",
    "ignoriere",
    "alle",
    "vorherigen",
    "bisherigen",
    "anweisungen",
    "regeln",
    "指示",
    "命令",
    "すべて",
    "無視",
    "игнорируй",
    "все",
    "предыдущие",
    "инструкции",
    "правила",
    "पिछले",
    "सभी",
    "निर्देशों",
    "को",
    "नजरअंदाज",
    "करें",
)
_FOLDED_MULTILINGUAL: tuple[str, ...] = tuple(
    dict.fromkeys(fold_unicode(word) for word in _MULTILINGUAL_WORDS)
)
_WIDE_VOCAB: tuple[str, ...] = tuple(
    sorted(set(_VOCAB).union(_FOLDED_MULTILINGUAL), key=len, reverse=True)
)
_WIDE_REV_VOCAB: tuple[str, ...] = tuple(
    sorted({char_reverse(word) for word in _WIDE_VOCAB}, key=len, reverse=True)
)
_LOOSE_TOKEN = re.compile(r"[a-z013457]{3,160}")
_LEET_DIGITS = frozenset("431057")
_OTHER_DIGITS = frozenset("2689")

# A base64 blob whose alphabet characters were split by a space or a hyphen.
# Case is preserved: base64 is case-sensitive, so this repair must not casefold.
_ENCODED_SPLIT = re.compile(
    r"(?<![A-Za-z0-9_+/])[A-Za-z0-9_+/-](?P<sep>[ \t-])"
    r"(?:[A-Za-z0-9_+/-](?P=sep)){2,}[A-Za-z0-9_+/-](?![A-Za-z0-9_+/])"
)
_ENCODED_PADDING = re.compile(r"(?<![A-Za-z0-9+/_-])([A-Za-z0-9+/_-]{32,})(?:[ \t]*=)+")


def _strip_ascii_marks(text: str) -> str:
    """Drop combining marks that sit on ASCII letters or digits.

    ``fold_unicode`` already drops marks on Latin letters. A mark that survived
    on a digit is a vowel accent left behind by leet (``i`` + acute → ``1`` +
    acute). Marks on non-ASCII bases stay, so Devanagari vowel signs are kept.
    """

    kept: list[str] = []
    ascii_base = False
    for char in text:
        if category(char).startswith("M"):
            if ascii_base:
                continue
            kept.append(char)
            continue
        kept.append(char)
        ascii_base = char.isascii() and char.isalnum()
    return "".join(kept)


def _fold_view(text: str) -> str:
    return _strip_ascii_marks(fold_unicode(text))


def _force_join(match: re.Match[str]) -> str:
    raw = match.group(0)
    if "-" in raw and all(part in _SHORT_WORDS for part in raw.split("-")):
        return raw
    # Three letters is the floor. ``all``, ``and`` and ``все`` are split by
    # punctuation into single characters, and a leftover fragment sits in the
    # middle of an override and blocks it. Two-character pairs stay split:
    # ``a-b`` and ``4-5`` are ordinary text.
    word = raw.translate(_SEPARATORS)
    if len(word) >= 3:
        return word
    return raw


def _grapheme_end(text: str, index: int) -> int:
    """Index after one alphabetic grapheme, or ``index`` when there is none."""

    if index >= len(text) or not text[index].isalpha():
        return index
    end = index + 1
    while end < len(text) and category(text[end]).startswith("M"):
        end += 1
    return end


def _isolated_grapheme_end(text: str, index: int) -> int:
    """End of a one-grapheme token, or ``index`` when the word continues.

    ``as`` must not donate its ``a`` to a preceding spaced run. A base plus its
    combining marks is still one token, so a Devanagari syllable stays whole.
    """

    end = _grapheme_end(text, index)
    if end == index or (end < len(text) and text[end].isalpha()):
        return index
    return end


def _join_graphemes(text: str, separator: str, minimum: int) -> str:
    """Rejoin a run of single graphemes split by ``separator``.

    Combining marks stay on their base, so a Devanagari vowel sign is not a
    separator and is not dropped. A grapheme that is only the first letter of
    a longer word is not a fragment. Runs shorter than ``minimum`` graphemes
    stay split. Spacing asks for four, so ``s o s`` stays. Hyphens ask for
    two, and the joined form must still be at least three code points, so
    ``all`` and ``все`` rejoin while ``a-b`` stays split.
    """

    out: list[str] = []
    index = 0
    limit = len(text)
    while index < limit:
        previous = text[index - 1] if index else ""
        blocked = bool(previous) and (previous.isalnum() or previous in "_-")
        end = _isolated_grapheme_end(text, index)
        if end == index or blocked:
            out.append(text[index])
            index += 1
            continue
        pieces = [text[index:end]]
        cursor = end
        while cursor < limit and text[cursor] == separator:
            nxt = _isolated_grapheme_end(text, cursor + 1)
            if nxt == cursor + 1:
                break
            pieces.append(text[cursor + 1 : nxt])
            cursor = nxt
        word = "".join(pieces)
        if (
            len(pieces) >= minimum
            and len(word) >= 3
            and not (separator == "-" and all(piece in _SHORT_WORDS for piece in pieces))
        ):
            out.append(word)
            index = cursor
            continue
        out.append(text[index])
        index += 1
    return "".join(out)


def _join_splits(text: str) -> str:
    for pattern in (_LEET_HYPHEN, _LEET_PUNCT, _LEET_SPACE):
        text = pattern.sub(_force_join, text)
    # After the ASCII repairs, so ``ig-no-re`` is already one word and this
    # pass only sees graphemes the ASCII classes cannot cross.
    # Two graphemes is enough for a short word (``सभी``, ``करें``). The joined
    # form still has to be at least three code points, so ASCII ``a-b`` stays.
    text = _join_graphemes(text, "-", 2)
    return _join_graphemes(text, " ", 4)


def _cover_token(token: str, vocab: tuple[str, ...]) -> str:
    """Split vocabulary words out of a fused token, including words in the middle.

    A prefix-only split misses ``forget your prior instructions`` when a
    non-vocabulary word was reversed to the front of the blob. One vocabulary
    hit is not enough, so ``overall`` does not lose its ``all``. Unknown
    stretches stay as single pieces.
    """

    if len(token) < 4 or len(token) > _FUSED_MAX:
        return token
    limit = len(token)
    covered = [-1] * (limit + 1)
    words = [0] * (limit + 1)
    # Predecessor index, and the vocabulary word that ended here (None = gap).
    pred: list[tuple[int, str | None]] = [(-1, None)] * (limit + 1)
    covered[0] = 0

    def better(index: int, cover: int, count: int) -> bool:
        return covered[index] < cover or (covered[index] == cover and words[index] > count)

    for index in range(limit):
        if covered[index] < 0:
            continue
        cover = covered[index]
        count = words[index]
        if better(index + 1, cover, count):
            covered[index + 1] = cover
            words[index + 1] = count
            pred[index + 1] = (index, None)
        for word in vocab:
            end = index + len(word)
            if end > limit or not token.startswith(word, index):
                continue
            if better(end, cover + len(word), count + 1):
                covered[end] = cover + len(word)
                words[end] = count + 1
                pred[end] = (index, word)
    if words[limit] < 2:
        return token
    pieces: list[tuple[str, str]] = []
    cursor = limit
    while cursor > 0:
        previous, placed = pred[cursor]
        if placed is None:
            pieces.append(("gap", token[previous:cursor]))
        else:
            pieces.append(("word", placed))
        cursor = previous
    chunks: list[str] = []
    last_gap = False
    for kind, text in reversed(pieces):
        if kind == "gap" and last_gap:
            chunks[-1] += text
        else:
            chunks.append(text)
        last_gap = kind == "gap"
    merged: list[str] = []
    for text in chunks:
        if not merged:
            merged.append(text)
            continue
        # Chinese and Japanese patterns match the characters adjacent. A space
        # there hides the override. Other scripts need the space fusion removed.
        if _unspaced_script(merged[-1][-1]) and _unspaced_script(text[0]):
            merged[-1] += text
        else:
            merged.append(text)
    if len(merged) < 2:
        return token
    return " ".join(merged)


def _unspaced_script(char: str) -> bool:
    """True for Han, Hiragana and Katakana, which do not take spaces between words."""

    code = ord(char)
    return 0x3400 <= code <= 0x9FFF or 0x3040 <= code <= 0x30FF or 0xFF66 <= code <= 0xFF9D


def _segment_wide(text: str, vocab: tuple[str, ...]) -> str:
    """Segment letter runs, keeping combining marks inside the run.

    The minimum is four characters so two fused function words still split.
    A run changes only when two or more vocabulary words sit inside it.
    """

    out: list[str] = []
    index = 0
    limit = len(text)
    while index < limit:
        if not text[index].isalpha():
            out.append(text[index])
            index += 1
            continue
        end = index + 1
        while end < limit and (text[end].isalpha() or category(text[end]).startswith("M")):
            end += 1
        out.append(_cover_token(text[index:end], vocab))
        index = end
    return "".join(out)


def _loose_deleet(text: str) -> str:
    """Map leet digits even when the token contains a three-digit run.

    The shared normalizer refuses that run so ``710`` inside an identifier
    does not become ``tio`` on the classifier view. A decisive-only reading
    can accept it. Tokens that contain a non-leet digit (``2``, ``6``, ``8``,
    ``9``) are left alone so phone numbers and ids are not rewritten.
    """

    def replace(match: re.Match[str]) -> str:
        word = match.group(0)
        if word.isalpha():
            return word
        if sum(char.isalpha() for char in word) < 2:
            return word
        if any(char in _OTHER_DIGITS for char in word):
            return word
        if not any(char in _LEET_DIGITS for char in word):
            return word
        return word.translate(_LEET)

    return _LOOSE_TOKEN.sub(replace, text)


def _readings(text: str) -> list[tuple[str, bool]]:
    """Repair one base into decisive readings, retaining orientation metadata."""

    folded = _fold_view(text)
    joined = _join_splits(folded)
    deleeted = _loose_deleet(joined)
    if joined == folded and deleeted == joined:
        return []
    forward = _segment_wide(deleeted, _WIDE_VOCAB) if joined != folded else deleeted
    readings = [(forward, True), (word_reverse(forward), False)]
    flipped = char_reverse(deleeted)
    if flipped != deleeted:
        readings.append((flipped, True))
        readings.append((word_reverse(flipped), False))
    if joined != folded:
        backward = _segment_wide(deleeted, _WIDE_REV_VOCAB)
        if backward != deleeted:
            restored = char_reverse(backward)
            readings.append((restored, True))
            readings.append((word_reverse(restored), False))
    return readings


def composed_instruction_views(text: str, *, mask_first: bool) -> tuple[InstructionView, ...]:
    """Repair the same bases as the reversal pass and mask each restored reading."""

    bases = instruction_bases(text, mask_first=mask_first)
    seen: set[str] = set()
    views: list[InstructionView] = []
    for base in bases:
        for reading, characters_only in _readings(base):
            finished = instruction_view(reading)
            if finished in seen:
                continue
            seen.add(finished)
            views.append(InstructionView(finished, characters_only))
    return tuple(views)


def encoding_surface(text: str) -> str:
    """Restore a base64 blob that was split, marked, or lookalike-folded.

    Case is preserved. Leet and case-mixing are not undone: both destroy
    base64 bits, and guessing them would decode unrelated alphabet soup.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    repaired = _strip_ascii_marks(text.translate(_ZERO_WIDTH).translate(_LOOKALIKES))

    def rejoin(match: re.Match[str]) -> str:
        return match[0][::2]

    repaired = _ENCODED_SPLIT.sub(rejoin, repaired)

    def padding(match: re.Match[str]) -> str:
        return match.group(1) + ("=" * match.group(0).count("="))

    return _ENCODED_PADDING.sub(padding, repaired)
