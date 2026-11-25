"""Canonicalize the text used by instruction rules and lexical features.

NFKC compatibility folding and removal of format and non-whitespace control
characters happen before casefolding, so every instruction view is built from
the same character sequence.
"""

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
_KEEP_CONTROLS = frozenset("\t\n\r")
# Instruction words used to decide whether a removed character was a word break.
# A whole run that is one of these words stays one word. A run that splits into
# two or more of them gets the spaces back. Reporting-frame anchors are included
# so a mark inside "recorded" cannot unmask a quoted instruction.
_BOUNDARY_WORDS = (
    "ignore disregard forget override cancel discard abort drop disable follow obey "
    "respect apply comply instructions instruction prompts prompt rules rule directions "
    "direction guidelines guideline commands command constraints constraint policies "
    "policy filters filter moderation restrictions restriction guardrails guardrail "
    "refusal heuristics checks check safety content previous prior above earlier current "
    "existing published everything before reveal show print repeat display output leak "
    "dump give quote paste restate restating read recite list emit system hidden initial "
    "developer message original initialization confidential configuration unrestricted "
    "uncensored unfiltered assistant model agent persona ethics refusals never refuse "
    "nothing bypass skip switch enter unlock privileged secret urgent urgently anyone "
    "human notice without answer respond pretend assume simulate roleplay jailbreak "
    "maintenance mode your all every the its any and now then next from this that with "
    "have been were was are you not do does my stack ignores ignoring longer exist "
    "matter say reply confirm translate rewrite rephrase skips bypasses first begin "
    "contained included recorded detected "
    "start bedtime story tradition configured provided set given beginning chat "
    "conversation session what is dan into root shell open new role for pose no user "
    "them know see keep tell in on of to by or an be it as if at me up we so act "
    "忽略 之前 先前 以前 指令 指示 تجاهل كل القواعد التعليمات السابقة desconsidere todas "
    "toda as instruções regras anteriores 지금부터 너는 제한 없는 güvenlik ilkelerini "
    "kurallarını geçersiz kıl dimentica ignora linee guida istruzioni precedenti "
    "ignorez toutes toute les règles précédentes las instrucciones reglas anteriores "
    "ignoriere alle vorherigen bisherigen anweisungen regeln 命令 すべて 無視 игнорируй "
    "все предыдущие инструкции правила पिछले सभी निर्देशों को नजरअंदाज करें"
).split()
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


def _boundary_key(word: str) -> str:
    """Fold one alphanumeric run the same way as ``fold_unicode``, without recursion."""

    word = unicodedata.normalize("NFC", word).translate(_LOOKALIKES)
    word = unicodedata.normalize("NFC", word.casefold()).translate(_LOOKALIKES)
    if word.isascii():
        return word
    folded: list[str] = []
    latin_base = False
    for char in unicodedata.normalize("NFD", word):
        if not unicodedata.category(char).startswith("M"):
            latin_base = unicodedata.name(char, "").startswith("LATIN ")
            folded.append(char)
        elif not latin_base:
            folded.append(char)
    return unicodedata.normalize("NFC", "".join(folded))


_BOUNDARY_LEXICON = frozenset(_boundary_key(word) for word in _BOUNDARY_WORDS if word)
# "a" and "i" are boundaries only when a whole fused run splits into instruction
# words. Treating them as boundaries while walking letter-by-letter splits the
# zero-width spellings already in the corpus.
_SEGMENT_LEXICON = _BOUNDARY_LEXICON | {"a", "i"}
# A format mark inside a reversed instruction word must not become a space.
# Short reverses collide with ordinary words, so only longer ASCII words count.
_REVERSED_LEXICON = frozenset(
    key[::-1] for key in _BOUNDARY_LEXICON if len(key) >= 4 and key.isascii()
)
_MAX_SEGMENT = max(len(word) for word in _SEGMENT_LEXICON)


def _is_ignorable(char: str) -> bool:
    """Format characters and controls other than tab, LF, and CR.

    U+200D ZERO WIDTH JOINER is category Cf and is included. It is deleted
    everywhere, including inside emoji ZWJ sequences. A joiner kept between
    emoji but stripped in words needs a second parser an attacker can aim at,
    and instruction features do not read emoji sequences.
    """

    if char in _KEEP_CONTROLS:
        return False
    category = unicodedata.category(char)
    return category == "Cf" or category == "Cc"


def delete_ignorables(text: str) -> str:
    """Delete format characters and controls other than tab, LF, and CR.

    No spaces are inserted. Encoded carriers use this so a hidden character
    cannot split an alphabet token and a restored boundary cannot break one.
    """

    if not any(_is_ignorable(char) for char in text):
        return text
    return "".join(char for char in text if not _is_ignorable(char))


def _is_word_char(char: str) -> bool:
    """Letters, digits, and combining marks. Format and controls are not included."""

    return char.isalnum() or unicodedata.category(char).startswith("M")


def _segment_key(key: str) -> list[str] | None:
    """Split a folded run into instruction words, or return None.

    The whole run must be consumed. A named word stays intact because the
    caller checks the lexicon before asking for a split.
    """

    parts: list[str] = []
    index = 0
    limit = len(key)
    while index < limit:
        found = 0
        upper = min(limit, index + _MAX_SEGMENT)
        for end in range(upper, index, -1):
            if key[index:end] in _SEGMENT_LEXICON:
                found = end
                break
        if not found:
            return None
        parts.append(key[index:found])
        index = found
    if len(parts) < 2:
        return None
    return parts


def _join_groups(groups: list[str]) -> str:
    """Space two unknown runs of length at least two. Keep every other mark inside the word."""

    pieces: list[str] = []
    tail: list[str] = [groups[0]]
    tail_len = len(groups[0])
    for group in groups[1:]:
        if tail_len >= 2 and len(group) >= 2:
            token = "".join(tail)
            joined = _boundary_key(token + group)
            if joined in _BOUNDARY_LEXICON or joined in _REVERSED_LEXICON:
                tail.append(group)
                tail_len += len(group)
            else:
                pieces.append(token)
                tail = [group]
                tail_len = len(group)
        else:
            tail.append(group)
            tail_len += len(group)
    pieces.append("".join(tail))
    return " ".join(pieces)


def _resolve_span(span: str) -> str:
    """Drop ignorables inside one delimiter-bounded run and restore real word gaps."""

    groups: list[str] = []
    buffer: list[str] = []
    for char in span:
        if _is_ignorable(char):
            if buffer:
                groups.append("".join(buffer))
                buffer = []
        else:
            buffer.append(char)
    if buffer:
        groups.append("".join(buffer))
    if len(groups) <= 1:
        return "".join(groups)
    letters = "".join(groups)
    key = _boundary_key(letters)
    if key in _BOUNDARY_LEXICON or key in _REVERSED_LEXICON:
        return letters
    parts = _segment_key(key)
    if parts is not None:
        return " ".join(parts)
    return _join_groups(groups)


def _strip_ignorables(text: str) -> str:
    """Delete ignorables. Put a space back when they separated two words.

    Combining marks stay with their base. A run bounded by real delimiters is
    one word when it is a named instruction word, including a reversed word.
    Otherwise it is split only into a sequence of instruction words. Two
    unknown letter runs of length at least two are still a boundary. A
    one-character piece is not, unless the whole run segments into words.
    """

    output: list[str] = []
    index = 0
    limit = len(text)
    while index < limit:
        if _is_word_char(text[index]):
            start = index
            index += 1
            while index < limit and (_is_word_char(text[index]) or _is_ignorable(text[index])):
                index += 1
            while index > start and _is_ignorable(text[index - 1]):
                index -= 1
            span = text[start:index]
            if any(_is_ignorable(char) for char in span):
                output.append(_resolve_span(span))
            else:
                output.append(span)
            continue
        if _is_ignorable(text[index]):
            end = index + 1
            while end < limit and _is_ignorable(text[end]):
                end += 1
            previous = output[-1][-1] if output and output[-1] else ""
            following = text[end] if end < limit else ""
            if (
                previous
                and following
                and not previous.isspace()
                and not following.isspace()
                and _is_word_char(following)
                and not _is_word_char(previous)
            ):
                # "STOP.\u202eNew": the ignorable replaced the space after punctuation.
                output.append(" ")
            index = end
            continue
        output.append(text[index])
        index += 1
    return "".join(output)


def _preserve_mapped_compat(text: str) -> str:
    """Keep lookalikes whose NFKC image is a different, unmapped character.

    Lunate sigma is in the explicit map and NFKC turns it into ordinary sigma.
    A mapped base that carries a combining mark is left alone so composition
    still runs. ``Υ`` plus diaeresis and acute stays the Greek word.
    """

    chars: list[str] = []
    limit = len(text)
    for index, char in enumerate(text):
        mapped = _HOMOGLYPHS.get(char)
        if mapped is None:
            chars.append(char)
            continue
        if index + 1 < limit and unicodedata.category(text[index + 1]).startswith("M"):
            chars.append(char)
            continue
        folded = unicodedata.normalize("NFKC", char)
        if folded != char and folded != mapped:
            chars.append(mapped)
        else:
            chars.append(char)
    return "".join(chars)


def _canonicalize(text: str) -> str:
    """NFKC, then drop format and non-whitespace controls.

    Compatibility forms, including fullwidth letters, become their ASCII
    equivalents before any instruction view is built. Tab, LF, and CR stay.
    Mapped compatibility characters are translated first when NFKC would
    erase the lookalike.
    """

    if any(ord(char) > 127 for char in text):
        text = unicodedata.normalize("NFKC", _preserve_mapped_compat(text))
    if any(_is_ignorable(char) for char in text):
        text = _strip_ignorables(text)
    return text


def fold_unicode(text: str) -> str:
    """Fold compatibility, case, lookalikes and Latin diacritics.

    Format characters (category Cf, including U+200D) and control characters
    other than tab, LF, and CR are removed first. A control or format character
    that is the only separator between two instruction words becomes a space.
    """

    text = _canonicalize(text)
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

    Training and inference share this view. Compatibility folding and format
    stripping happen before spaced-letter, hyphen, and leetspeak repairs, so
    every later view sees the same text. PII checks and encoded-candidate
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
