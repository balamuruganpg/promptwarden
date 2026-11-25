"""Reversed instruction views for the rule layer.

TrustBreaker reverses characters inside each word (``char_reverse``) and
reverses word order (``word_reverse``). Both are involutions on its word
spans: a letter or digit run, or ``_``, with combining marks kept on their
base. This module rebuilds those views and feeds them back through the same
normalization the direct rules already use.

A reversed view may contribute only a decisive instruction match. It does not
add a feature column, and it does not run PII checks: reversing digits would
mint checksum hits. Context masking is applied in the original orientation
before reversal, then again after it, so a quoted reversed instruction stays
blank and a restored negation is still a negation.

Punctuation splits, intra-word zero-width characters, and single-letter
spacing do not commute with reversal, so each masked base is reversed both
before and after normalization. Format characters are word boundaries for
``word_reverse`` and are deleted before those views are built. When any
format or non-whitespace control sits in the first ``PRESERVE_CHARS``
characters, the word order is restored on that window first and the
canonical reading is checked forward. Reported quotes and negated actions
are blanked on that window before the words move, using the canonical
sentence so a mark inside a word such as ``recorded`` still counts.
That window is the same 16,384
characters the decoder uses for an extra root reading. Hyphen runs shorter
than four letters are rejoined on these views only; the shared normalizer
leaves them split so that ``up-to-us`` stays a phrase. Leet decoding on the
reversed view accepts a digit run, a one-letter remnant, and a pure leet
digit token. The strict decoder refuses ``710`` inside the leet form of
``instructions``, which would otherwise hide that word. A fused token is
split when vocabulary words cover it, and also when a vocabulary word of
at least four letters sits beside a leftover of at least four letters. A
leftover shorter than four stays put, so ``ignorance`` and ``overall`` are
not cut open.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from unicodedata import category

from promptwarden.context import _QUOTED, instruction_view
from promptwarden.normalize import (
    _LEET,
    _SHORT_WORDS,
    _canonicalize,
    _is_ignorable,
    delete_ignorables,
    fold_unicode,
    normalize,
)

# Same window as decoding.SURFACE_CHARS. Imported there would cycle.
PRESERVE_CHARS = 16 * 1024
_LOOSE_LEET = re.compile(r"\b[a-z013457]{2,32}\b")
_LEET_DIGITS = frozenset("431057")
_OTHER_DIGITS = frozenset("2689")
_TOKEN = re.compile(r"[a-z0-9]+")
_ANCHOR_MIN = 4
# The shared normalizer keeps a joined fragment only at length >= 4, so
# punct-split "n-o-w" / "a-l-l" stay broken and word reversal then slides
# the long words into the wrong slots. Rejoin those short runs here only.
_SHORT_HYPHEN = re.compile(r"(?<![\w-])[a-z](?:-[a-z])+(?![\w-])")
_SEGMENT_MAX = 96

# Instruction lexicon already named by the rule patterns. A fused token is
# split only when every piece is in this list. Unknown leftovers stay intact,
# so a normal word is not cut open.
_VOCAB: tuple[str, ...] = tuple(
    sorted(
        {
            "ignore",
            "disregard",
            "forget",
            "override",
            "cancel",
            "discard",
            "abort",
            "drop",
            "disable",
            "follow",
            "obey",
            "respect",
            "apply",
            "comply",
            "instructions",
            "instruction",
            "prompts",
            "prompt",
            "rules",
            "rule",
            "directions",
            "direction",
            "guidelines",
            "guideline",
            "commands",
            "command",
            "constraints",
            "constraint",
            "policies",
            "policy",
            "filters",
            "filter",
            "moderation",
            "restrictions",
            "restriction",
            "guardrails",
            "guardrail",
            "refusal",
            "heuristics",
            "checks",
            "check",
            "safety",
            "content",
            "previous",
            "prior",
            "above",
            "earlier",
            "current",
            "existing",
            "published",
            "everything",
            "before",
            "reveal",
            "show",
            "print",
            "repeat",
            "display",
            "output",
            "leak",
            "dump",
            "give",
            "quote",
            "paste",
            "restate",
            "restating",
            "read",
            "recite",
            "list",
            "emit",
            "system",
            "hidden",
            "initial",
            "developer",
            "message",
            "original",
            "initialization",
            "confidential",
            "configuration",
            "unrestricted",
            "uncensored",
            "unfiltered",
            "assistant",
            "model",
            "agent",
            "persona",
            "ethics",
            "refusals",
            "never",
            "refuse",
            "nothing",
            "bypass",
            "skip",
            "switch",
            "enter",
            "unlock",
            "privileged",
            "secret",
            "urgent",
            "urgently",
            "anyone",
            "human",
            "notice",
            "without",
            "answer",
            "respond",
            "pretend",
            "assume",
            "simulate",
            "roleplay",
            "jailbreak",
            "maintenance",
            "mode",
            "your",
            "all",
            "every",
            "the",
            "its",
            "any",
            "and",
            "now",
            "then",
            "next",
            "from",
            "this",
            "that",
            "with",
            "have",
            "been",
            "were",
            "was",
            "are",
            "you",
            "not",
            "do",
            "does",
        },
        key=len,
        reverse=True,
    )
)


def _word_spans(text: str) -> Iterator[tuple[int, int]]:
    start: int | None = None
    for index, char in enumerate(text):
        if char.isalnum() or char == "_":
            if start is None:
                start = index
        elif start is not None and not category(char).startswith("M"):
            yield start, index
            start = None
    if start is not None:
        yield start, len(text)


def _graphemes(word: str) -> list[str]:
    start = 0
    pieces: list[str] = []
    for index, char in enumerate(word[1:], 1):
        if not category(char).startswith("M"):
            pieces.append(word[start:index])
            start = index
    pieces.append(word[start:])
    return pieces


def _map_words(text: str, transform: Callable[[str], str]) -> str:
    parts: list[str] = []
    end = 0
    for start, stop in _word_spans(text):
        parts.append(text[end:start])
        parts.append(transform(text[start:stop]))
        end = stop
    parts.append(text[end:])
    return "".join(parts)


def char_reverse(text: str) -> str:
    """Reverse characters inside each word. Separators stay put."""

    return _map_words(text, lambda word: "".join(reversed(_graphemes(word))))


def word_reverse(text: str) -> str:
    """Reverse word order. Separators stay in their original slots."""

    words = [text[start:end] for start, end in _word_spans(text)]
    return _map_words(text, lambda _word: words.pop())


def _rejoin_short_hyphens(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        parts = match.group(0).split("-")
        if all(part in _SHORT_WORDS for part in parts):
            return match.group(0)
        return "".join(parts)

    return _SHORT_HYPHEN.sub(replace, text)


def _prepare(text: str) -> str:
    return _rejoin_short_hyphens(_loose_deleet(normalize(text)))


def _loose_deleet(text: str) -> str:
    """Map leet digits, including a one-letter remnant and a pure digit token.

    The shared normalizer refuses both, and it refuses a three-digit run, so
    ``7h3`` and ``710`` stay leetspeak on the classifier view. This reading is
    decisive-only. A token that contains any other digit is left alone.
    """

    def replace(match: re.Match[str]) -> str:
        word = match.group(0)
        if word.isalpha():
            return word
        if any(char in _OTHER_DIGITS for char in word):
            return word
        if not any(char in _LEET_DIGITS for char in word):
            return word
        return word.translate(_LEET)

    return _LOOSE_LEET.sub(replace, text)


def segment_token(
    token: str,
    vocab: tuple[str, ...],
    *,
    max_len: int = _SEGMENT_MAX,
    min_len: int = 8,
) -> str:
    """Split one fused token. Unchanged unless two or more pieces cover it."""

    if len(token) < min_len or len(token) > max_len:
        return token
    best: list[list[str] | None] = [None] * (len(token) + 1)
    best[0] = []
    for index, pieces in enumerate(best):
        if pieces is None:
            continue
        for word in vocab:
            end = index + len(word)
            if end <= len(token) and token.startswith(word, index):
                candidate = pieces + [word]
                current = best[end]
                if current is None or len(candidate) < len(current):
                    best[end] = candidate
    done = best[-1]
    if done is not None and len(done) >= 2:
        return " ".join(done)
    anchored = _anchor_split(token, vocab)
    if anchored is not None:
        return anchored
    return token


def _anchor_split(token: str, vocab: tuple[str, ...]) -> str | None:
    """Split a long vocabulary word off a fused token.

    The strict cover requires every character to be a vocabulary word. Spacing
    also fuses an ordinary word onto one (``please`` + ``ignore``). A vocabulary
    word shorter than four letters is not an anchor, so ``overall`` keeps
    ``all``. A leftover shorter than four letters rejects the split, so
    ``ignorance`` keeps its ending.
    """

    if len(token) < 8:
        return None
    pieces: list[tuple[bool, str]] = []
    index = 0
    limit = len(token)
    found = False
    while index < limit:
        match: str | None = None
        for word in vocab:
            if len(word) < _ANCHOR_MIN or len(word) > limit - index:
                continue
            if token.startswith(word, index):
                match = word
                break
        if match is None:
            if pieces and not pieces[-1][0]:
                pieces[-1] = (False, pieces[-1][1] + token[index])
            else:
                pieces.append((False, token[index]))
            index += 1
            continue
        pieces.append((True, match))
        found = True
        index += len(match)
    if not found or len(pieces) < 2:
        return None
    if any(not is_word and len(gap) < _ANCHOR_MIN for is_word, gap in pieces):
        return None
    return " ".join(piece for _is_word, piece in pieces)


def segment_fused(
    text: str,
    *,
    vocab: tuple[str, ...] | None = None,
    max_len: int = _SEGMENT_MAX,
) -> str:
    """Split fused ASCII tokens into ``vocab`` words.

    A token is left unchanged unless vocabulary words cover it, or one
    vocabulary word of at least four letters sits beside a leftover of at
    least four letters. Ordinary words are not cut open. ``max_len`` bounds
    the dynamic program.
    """

    words = _VOCAB if vocab is None else vocab

    def split(match: re.Match[str]) -> str:
        return segment_token(match.group(0), words, max_len=max_len)

    return _TOKEN.sub(split, text)


def _segment(text: str) -> str:
    return segment_fused(text)


# A literal language fence already identifies its opening delimiter. Preserve
# that evidence before reordering, which can move e.g. print('system') there.
_LANGUAGE_OPENER = re.compile(
    r"(?<!`)`{3,}(?=[ \t]*(?:python|py|javascript|js|typescript|ts|json|yaml|"
    r"toml|bash|sh|shell|sql|html|css|xml|java|c(?:pp|sharp)?|go|rust|ruby)[ \t]*(?:\r?\n|\Z))",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class InstructionView:
    """A transformed reading and whether it preserves the source word order."""

    text: str
    characters_only: bool


def _expansions(text: str) -> tuple[tuple[str, bool], ...]:
    characters = char_reverse(text)
    words = word_reverse(text)
    return (
        (characters, True),
        (words, False),
        (char_reverse(words), False),
        (word_reverse(characters), False),
    )


def _finish(view: str) -> str:
    return instruction_view(_segment(_prepare(view)))


def _views_from(base: str) -> list[InstructionView]:
    views = [
        InstructionView(_finish(text), characters_only)
        for text, characters_only in _expansions(base)
    ]
    prepared = _prepare(base)
    views.extend(
        InstructionView(instruction_view(_segment(text)), characters_only)
        for text, characters_only in _expansions(prepared)
    )
    # Spacing fuses adjacent long words, and word reversal of that blob is a
    # no-op. Split first, then reverse, so the original word order comes back.
    segmented = _segment(prepared)
    if segmented != prepared:
        views.extend(
            InstructionView(instruction_view(text), characters_only)
            for text, characters_only in _expansions(segmented)
        )
    return views


def _masked_needles(canon: str, masked: str) -> list[str]:
    """Return the canonical slices ``instruction_view`` replaced."""

    needles: list[str] = []
    index = 0
    limit = len(canon)
    while index < limit:
        if masked[index] == canon[index]:
            index += 1
            continue
        end = index + 1
        while end < limit and masked[end] != canon[end]:
            end += 1
        needles.append(canon[index:end])
        index = end
    return needles


def _find_with_ignorables(raw: str, needle: str, start: int) -> tuple[int, int] | None:
    """Find ``needle`` in ``raw``, allowing format and control characters inside it."""

    limit = len(raw)
    origin = start
    while origin < limit:
        if _is_ignorable(raw[origin]):
            origin += 1
            continue
        cursor = origin
        matched = True
        for char in needle:
            while cursor < limit and _is_ignorable(raw[cursor]):
                cursor += 1
            if cursor >= limit or raw[cursor] != char:
                matched = False
                break
            cursor += 1
        if matched:
            return origin, cursor
        origin += 1
    return None


def _blank_canonical_masks(raw: str) -> str:
    """Blank spans the canonical sentence masks, keeping mark positions.

    ``instruction_view`` sees the sentence after format characters are
    deleted, so ``rec`` + ZWSP + ``orded`` is still a reporting verb. The
    same span on the raw window has to be blank before ``word_reverse``
    moves words across the quote.
    """

    canon = _canonicalize(raw)
    masked = instruction_view(canon)
    if masked == canon:
        return raw
    chars = list(raw)
    cursor = 0
    for needle in _masked_needles(canon, masked):
        found = _find_with_ignorables(raw, needle, cursor)
        if found is None:
            continue
        start, end = found
        cursor = end
        for index in range(start, end):
            if chars[index] not in "\r\n":
                chars[index] = " "
    return "".join(chars)


def presplit_word_order(text: str, *, mask_first: bool = False) -> str | None:
    """Restore word order while format characters are still boundaries.

    ``word_reverse`` treats a format or non-whitespace control as a word
    break. The other views delete those characters first, which glues the
    letters into the wrong groups. Reversing the leading window first puts
    the breaks back. The result is canonical. Reported quotes and negated
    actions are blanked first, in the original orientation, so a restored
    reading cannot carry a quoted instruction out of its quotes. ``None``
    when the window has no such character or the orientation does not
    change it.
    """

    window = text[:PRESERVE_CHARS]
    if not any(_is_ignorable(char) for char in window):
        return None
    source = _blank_canonical_masks(window) if mask_first else window
    reordered = word_reverse(source)
    if reordered == source:
        return None
    # Drop the boundary marks without the shared segmenter. That segmenter
    # splits "openai" into "open a i" once a mark has separated the letters.
    # Zero-width reversal keeps the real spaces, so deletion is the inverse.
    restored = delete_ignorables(reordered)
    restored = _canonicalize(restored)
    if restored == _canonicalize(delete_ignorables(window)):
        return None
    return restored


def masked_surface(text: str) -> str:
    """Preserve carrier bytes while copying reported-quote masks from normalized prose."""

    raw = instruction_view(text)
    # Apply the same context checks to byte-preserving text with format and
    # non-whitespace controls removed. A hidden character in "not" should not
    # expose an otherwise negated carrier. Keep original word boundaries on
    # active text. Deletion does not insert spaces: this surface also feeds
    # case-sensitive carriers.
    visible = delete_ignorables(text)
    if visible != text:
        masked = instruction_view(visible)
        if masked != visible:
            text, raw = visible, masked
    if not _QUOTED.search(text):
        return raw
    prepared = normalize(text)
    contextual = instruction_view(prepared)
    if prepared == contextual and raw == text:
        return text
    chars = list(raw)
    # Quote delimiters separate tokens. Normalizing successive intervals
    # maps their offsets even when folding or joining changes their lengths.
    source_end = prepared_end = 0
    for match in _QUOTED.finditer(text):
        start, end = match.span()
        prepared_start = prepared_end + len(normalize(text[source_end:start]))
        prepared_end = prepared_start + len(normalize(match[0]))
        if not contextual[prepared_start:prepared_end].strip():
            chars[start:end] = " " * (end - start)
        elif not raw[start:end].strip():
            # A normalized activation cue can also make a reported quote
            # operative. Restore its case-sensitive bytes and local negations.
            chars[start:end] = instruction_view(match[0])
        source_end = end
    return "".join(chars)


def instruction_bases(text: str, *, mask_first: bool) -> tuple[str, ...]:
    """Build original-orientation bases shared by reversal and composed repairs."""

    # Format, controls, and compatibility forms are folded before reversal or
    # composition so every view is built from the same character sequence.
    text = _canonicalize(text)
    bases: tuple[str, ...]
    if mask_first:
        raw = masked_surface(text)
        bases = (raw, instruction_view(normalize(raw)), instruction_view(fold_unicode(raw)))
    else:
        bases = (text,)
    return tuple(dict.fromkeys(_LANGUAGE_OPENER.sub("~~~", base) for base in bases))


def instruction_views(text: str, *, mask_first: bool) -> tuple[InstructionView, ...]:
    """Reverse before and after normalization, masking each restored reading."""

    seen: set[str] = set()
    views: list[InstructionView] = []
    for base in instruction_bases(text, mask_first=mask_first):
        for view in _views_from(base):
            if view.text not in seen:
                seen.add(view.text)
                views.append(view)
    restored = presplit_word_order(text, mask_first=mask_first)
    if restored is not None:
        # The restored window can itself be a reversed instruction (a corpus
        # row that was already reversed, then reversed again around a format
        # mark). Run the ordinary reversal readings on it, and also keep the
        # forward reading so a restored clear instruction is not flipped back.
        for view in _views_from(restored):
            if view.text not in seen:
                seen.add(view.text)
                views.append(view)
        # Loose deleet runs in _prepare. The strict normalizer would leave
        # "7h3" and "574ck" in a restored leet sentence.
        forward = _segment(_prepare(restored))
        if mask_first:
            forward = instruction_view(forward)
        if forward not in seen:
            seen.add(forward)
            views.append(InstructionView(forward, True))
    return tuple(views)
