"""Bounded worklist of UTF-8 readings for decisive instruction checks."""

from __future__ import annotations

import base64
import re
from collections import deque
from collections.abc import Iterator
from urllib.parse import unquote_to_bytes

from promptwarden.compose import encoding_surface
from promptwarden.reversal import char_reverse, masked_surface, word_reverse

# Four layers cover three transport wrappers around an already encoded input.
# Tokens are ASCII: charging input length before each attempt upper-bounds
# decoded bytes too, including failed/overlapping parses of base64 and hex.
MAX_DEPTH = 4
TOKEN_CHARS = 4096
SURFACE_CHARS = 16 * 1024
TOTAL_BYTES = 32 * 1024
MAX_ATTEMPTS = 64

_B64 = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{32,}={0,2}(?![A-Za-z0-9+/_=-])")
_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])")
_URL_TOKEN = re.compile(r"[A-Za-z0-9._~+%/-]+")
_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_BROKEN_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def _base64(token: str) -> bytes:
    # Padding can be omitted, but a supplied pad must be complete and valid.
    missing = -len(token) % 4
    if missing and "=" in token:
        raise ValueError("incomplete base64 padding")
    token += "=" * missing
    return base64.b64decode(token, altchars=b"-_", validate=True)


def _preserve_escape_order(match: re.Match[str]) -> str:
    """Reserve intact percent syntax for the source-order decoder.

    Reassigning a valid escape to a different word can detach an instruction
    from its reported quote. Keep the punctuation slots for other codecs.
    Damaged escape syntax can still be restored by reversing the carrier.
    """
    token = match[0]
    if "%" in token and not _BROKEN_ESCAPE.search(token):
        return token.replace("%", "!")
    return token


def _surfaces(text: str, *, root: bool) -> Iterator[str]:
    masked = masked_surface(text)
    yield masked
    # Intact tokens can occur anywhere in a document. Cap the extra copies
    # for case-preserving repair/reversal, including when one token is huge.
    sample = masked[:SURFACE_CHARS]
    seen = {sample}
    reversible = (
        _URL_TOKEN.sub(_preserve_escape_order, sample) if root and "%" in sample else sample
    )
    transforms = (None, char_reverse, word_reverse) if root else (None,)
    for transform in transforms:
        view = sample
        if transform is not None:
            view = masked_surface(transform(reversible))
            if view in seen:
                continue
            seen.add(view)
            yield view
        repaired = encoding_surface(view)
        if repaired != view:
            repaired = masked_surface(repaired)
            if repaired not in seen:
                seen.add(repaired)
                yield repaired


def _candidates(text: str) -> Iterator[tuple[str, str]]:
    for kind, pattern in (("hex", _HEX), ("base64", _B64), ("percent", _URL_TOKEN)):
        if kind == "percent" and "%" not in text:
            continue
        for match in pattern.finditer(text):
            start, end = match.span()
            token = text[start : min(end, start + TOKEN_CHARS)]
            if kind != "percent" or _ESCAPE.search(token):
                yield kind, token


def decoded_views(text: str) -> Iterator[str]:
    """Yield each distinct decoded reading once, shallowest first.

    Depth, attempted bytes and candidate count are shared across codecs,
    orientations and repairs. Intermediate carriers need only be UTF-8.
    """
    queue = deque([(text, 0)])
    seen = {text}
    attempted: set[tuple[str, str]] = set()
    bytes_left = TOTAL_BYTES
    while queue:
        parent, depth = queue.popleft()
        for surface in _surfaces(parent, root=depth == 0):
            for kind, token in _candidates(surface):
                if (kind, token) in attempted or len(token) > bytes_left:
                    continue
                if len(attempted) == MAX_ATTEMPTS:
                    return
                attempted.add((kind, token))
                bytes_left -= len(token)
                try:
                    if kind == "base64":
                        raw = _base64(token)
                    elif kind == "hex":
                        raw = bytes.fromhex(token[: len(token) // 2 * 2])
                    else:
                        raw = unquote_to_bytes(token)
                    child = raw.decode("utf-8")
                except ValueError:
                    continue
                if child in seen:
                    continue
                seen.add(child)
                yield child
                if depth + 1 < MAX_DEPTH:
                    queue.append((child, depth + 1))
