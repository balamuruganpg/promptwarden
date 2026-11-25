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
before and after normalization. Hyphen runs shorter than four letters are
rejoined on these views only; the shared normalizer leaves them split so
that ``up-to-us`` stays a phrase. Leet decoding on the reversed view also
accepts a digit run. The strict decoder refuses ``710`` inside the leet form
of ``instructions``, which would otherwise hide that word. Tokens that
spacing rejoins into one blob are split only when the whole token is a
sequence of words the instruction rules already name.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from unicodedata import category

from promptwarden.context import _QUOTED, instruction_view
from promptwarden.normalize import _LEET, _SHORT_WORDS, _ZERO_WIDTH, fold_unicode, normalize

_LOOSE_LEET = re.compile(r"\b[a-z013457]{3,32}\b")
_TOKEN = re.compile(r"[a-z0-9]+")
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
    def replace(match: re.Match[str]) -> str:
        word = match.group(0)
        if word.isalpha() or sum(char.isalpha() for char in word) < 2:
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
    """Split one fused token. Unchanged unless two or more words cover it."""

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
    if done is None or len(done) < 2:
        return token
    return " ".join(done)


def segment_fused(
    text: str,
    *,
    vocab: tuple[str, ...] | None = None,
    max_len: int = _SEGMENT_MAX,
) -> str:
    """Split fused ASCII tokens into ``vocab`` words when the whole token is covered.

    A token is left unchanged unless every character belongs to at least two
    vocabulary words. Ordinary words are not cut open. ``max_len`` bounds the
    dynamic program.
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
    return views


def masked_surface(text: str) -> str:
    """Preserve carrier bytes while copying reported-quote masks from normalized prose."""

    raw = instruction_view(text)
    # Apply the same context checks to byte-preserving text with invisible
    # separators removed. A hidden character in "not" should not expose an
    # otherwise negated carrier. Keep original word boundaries on active text.
    if not text.isascii():
        visible = text.translate(_ZERO_WIDTH)
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
    return tuple(views)
