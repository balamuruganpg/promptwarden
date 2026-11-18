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
from promptwarden.normalize import _LEET, _SHORT_WORDS, fold_unicode, normalize

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


@dataclass(frozen=True)
class InstructionView:
    """One reversed candidate.

    ``characters_only`` is true when word order was not changed. A system fence
    is checked only on those views: word-order reversal can slide an unrelated
    ``system`` token into a `` ```python `` fence.
    """

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


def _align_quote_masks(text: str) -> str:
    """Mask raw quotes that the folded instruction view already blanks.

    A zero-width character in a reporting frame hides that frame from the raw
    matcher. Folding makes the frame visible. Copy those quote masks back so
    reversal cannot restore the quoted text. Quotes the folded view leaves
    visible stay visible here too.
    """

    folded = fold_unicode(text)
    folded_view = instruction_view(folded)
    chars = list(instruction_view(text))
    if folded == folded_view or not _QUOTED.search(text):
        return "".join(chars)
    for match in _QUOTED.finditer(text):
        start, end = match.span()
        fold_start = len(fold_unicode(text[:start]))
        fold_end = len(fold_unicode(text[:end]))
        if fold_end <= fold_start or fold_end > len(folded_view):
            continue
        original = folded[fold_start:fold_end]
        masked = folded_view[fold_start:fold_end]
        if original.strip() and not masked.strip():
            for index in range(start, end):
                if chars[index] not in "\r\n":
                    chars[index] = " "
    return "".join(chars)


def instruction_views(text: str, *, mask_first: bool) -> tuple[InstructionView, ...]:
    """Return reversed instruction views of ``text``.

    ``mask_first`` copies the original-orientation masks before reversal.
    Decoded payloads pass ``False``: encoded candidates already bypass the
    mask on the direct path, and the final ``instruction_view`` still blanks
    a negation that reversal restored.
    """

    bases: tuple[str, ...]
    if mask_first:
        bases = (
            _align_quote_masks(text),
            instruction_view(normalize(text)),
            instruction_view(fold_unicode(text)),
        )
    else:
        bases = (text,)
    seen: set[str] = set()
    views: list[InstructionView] = []
    for base in bases:
        for view in _views_from(base):
            if view.text not in seen:
                seen.add(view.text)
                views.append(view)
    return tuple(views)
