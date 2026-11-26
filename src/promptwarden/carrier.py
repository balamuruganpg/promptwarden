"""Bounded plain-prose readings of a damaged base64 alphabet."""

from __future__ import annotations

import base64
import re
import string
from itertools import product

from promptwarden.normalize import _LEET, _SHORT_WORDS

MAX_REPAIR_CHARS = 256
MAX_SUBSTITUTIONS = 64
MAX_READINGS = 8
# Per position: at most nine adjacent sextet pairs, then at most eight
# surviving paths to walk and eight whole readings to assemble and verify.
REPAIR_COST = 9 + 2 * MAX_READINGS

_SYMBOLS = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
_VALUES = {c: i for i, c in enumerate(_SYMBOLS)}
_VALUES.update({"-": 62, "_": 63})
_LITERAL: dict[str, tuple[int, ...]] = {c: (i,) for c, i in _VALUES.items()}
_LEET_VALUES = _LITERAL.copy()
for _digit, _letter in _LEET.items():
    _LEET_VALUES[chr(_digit)] = (
        _VALUES[chr(_digit)],
        _VALUES[chr(_letter)],
        _VALUES[chr(_letter).upper()],
    )
_CASE_VALUES: dict[str, tuple[int, ...]] = {
    c: (i, _VALUES[c.swapcase()]) if c.isalpha() else (i,) for c, i in _VALUES.items()
}
_PROSE = frozenset(b"abcdefghijklmnopqrstuvwxyz .,!?;:'\"-")
_INITIAL = _PROSE | frozenset(string.ascii_uppercase.encode())
_WORDS = re.compile(rb"[a-z]+")
_FUNCTION_WORDS = _SHORT_WORDS.union(
    "all and any are but can for from has have into its not on our that the their them then "
    "there these they this those was were will with you your".split()
)


def repair_alphabet(token: str) -> dict[str, tuple[int, ...]] | None:
    """Recognize a whole-span footprint. A genuine digit is always a possible reading."""
    if len(token) > MAX_REPAIR_CHARS:
        return None
    leeted = not re.search("[aeiostAEIOST]", token) and bool(re.search("[013457]", token))
    letters = [c for c in token if c.isalpha()]
    mixed = len(letters) >= 8 and all(
        a.isupper() != b.isupper() for a, b in zip(letters, letters[1:])
    )
    if leeted and not mixed:
        return _LEET_VALUES
    if mixed and not leeted:
        return _CASE_VALUES
    return None


def _quantum(
    group: str, alphabet: dict[str, tuple[int, ...]], first: bool, limit: int
) -> tuple[bytes, ...]:
    """Find viable adjacent sextets backwards, then walk only complete paths."""
    # A canonical final sextet has zero unused bits (4, 2 or 0).
    mask = (1 << (8 - 2 * len(group))) - 1
    viable = [value for value in alphabet[group[-1]] if not value & mask]
    edges = []
    for index in range(len(group) - 1, 0, -1):
        shift = 6 - 2 * index
        allowed = _INITIAL if first and index == 1 else _PROSE
        links: dict[int, list[tuple[int, int]]] = {}
        for left in alphabet[group[index - 1]]:
            for right in viable:
                byte = ((left << (6 - shift)) & 255) | (right >> shift)
                if byte in allowed:
                    links.setdefault(left, []).append((right, byte))
        if not links:
            return ()
        edges.append(links)
        viable = list(links)
    paths = [(left, b"") for left in viable]
    for links in reversed(edges):
        following: list[tuple[int, bytes]] = []
        for left, prefix in paths:
            for right, byte in links[left]:
                if len(following) == limit:
                    return ()
                following.append((right, prefix + bytes((byte,))))
        paths = following
    return tuple(chunk for _, chunk in paths)


def _prose(raw: bytes) -> bool:
    if raw.count(b" ") < 2 or re.search(rb"([a-z])\1{3}", raw.lower()):
        return False
    words = _WORDS.findall(raw.lower())
    if len(words) < 3 or not any(word.decode() in _FUNCTION_WORDS for word in words):
        return False
    return all(len(word) < 3 or re.search(b"[aeiouy]", word) for word in words)


def recover_prose(token: str, alphabet: dict[str, tuple[int, ...]]) -> tuple[str, ...]:
    """Return every admissible reading or abstain on the entire span."""
    symbols = token.rstrip("=")
    quanta = []
    count = 1
    for start in range(0, len(symbols), 4):
        chunks = _quantum(symbols[start : start + 4], alphabet, start == 0, MAX_READINGS // count)
        if not chunks:
            return ()
        quanta.append(chunks)
        count *= len(chunks)
    observed = symbols.replace("-", "+").replace("_", "/")
    readings = []
    for blocks in product(*quanta):
        raw = b"".join(blocks)
        canonical = base64.b64encode(raw).decode().rstrip("=")
        edits = sum(a != b for a, b in zip(canonical, observed, strict=True))
        if edits > MAX_SUBSTITUTIONS or not _prose(raw):
            return ()
        readings.append(raw.decode("ascii"))
    return tuple(readings)
