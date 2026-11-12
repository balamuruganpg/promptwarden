"""Deterministic injection and sensitive-data signals.

Each detector returns a named signal with a fixed weight on the same 0–1 scale
as the decision threshold. Weights live in :data:`WEIGHTS`. :func:`detect`
emits each signal at most once, in :data:`SIGNAL_NAMES` order.

Credit-card hits require a real Luhn check. Aadhaar hits require the
``#### #### ####`` shape (spaces or hyphens, or 12 contiguous digits), a
leading digit from 2–9, and a real Verhoeff checksum. Format alone is not a
signal for either.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

# Verhoeff multiplication (D), permutation (P), and inverse tables.
# These are the standard dihedral-group tables: a digit string is valid when
# its checksum is 0. The check vector "12340" is valid; "12341" is not.
_D: tuple[tuple[int, ...], ...] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P: tuple[tuple[int, ...], ...] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_INV: tuple[int, ...] = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)

INJECTION_SIGNALS: tuple[str, ...] = (
    "instruction_override",
    "role_hijack",
    "system_prompt_extraction",
    "fake_system_turn",
    "system_fence",
    "chat_template_token",
    "encoded_payload",
    "urgency_secrecy",
)
PII_SIGNALS: tuple[str, ...] = (
    "email",
    "phone",
    "pan",
    "aadhaar",
    "credit_card",
    "api_key",
    "private_key",
)
SIGNAL_NAMES: tuple[str, ...] = INJECTION_SIGNALS + PII_SIGNALS

# Weights are already on the score scale. One signal at or above the default
# threshold (0.5) is enough to flag on rules alone. The sum is capped at 1.
WEIGHTS: dict[str, float] = {
    "instruction_override": 0.85,
    "role_hijack": 0.70,
    "system_prompt_extraction": 0.80,
    "fake_system_turn": 0.75,
    "system_fence": 0.75,
    "chat_template_token": 0.90,
    "encoded_payload": 0.85,
    "urgency_secrecy": 0.60,
    "email": 0.70,
    "phone": 0.65,
    "pan": 0.80,
    "aadhaar": 0.85,
    "credit_card": 0.85,
    "api_key": 0.90,
    "private_key": 0.95,
}
FAMILIES: dict[str, str] = {
    **{name: "injection" for name in INJECTION_SIGNALS},
    **{name: "pii" for name in PII_SIGNALS},
}

# Encoded blobs are scanned only up to this many characters. A single longer
# token is truncated before decoding, so a marker past the cap can be missed.
_ENCODED_CAP = 4096
_ENCODED_MARKERS: tuple[str, ...] = (
    "ignore previous",
    "ignore all previous",
    "disregard previous",
    "disregard all",
    "you are now",
    "system prompt",
    "jailbreak",
    "<|im_start|>",
    "do not tell",
    "bypass your safety",
    "reveal your",
)

_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override)\b(?:\s+\w+){0,4}\s+"
    r"(?:previous|prior|above|earlier|your|all)\s+"
    r"(?:instructions|prompts|rules|directions|guidelines|commands|constraints)\b",
    re.IGNORECASE,
)
_ROLE = re.compile(
    r"\byou are now\b|\bfrom now on you are\b|\bact as (?:a |an )?(?:dan|jailbreak)\b",
    re.IGNORECASE,
)
_EXTRACT = re.compile(
    r"\b(?:reveal|show|print|repeat|display|output|leak|dump|give)\b"
    r".{0,40}?"
    r"\b(?:system prompt|hidden prompt|initial prompt|developer message|"
    r"original instructions|hidden instructions)\b",
    re.IGNORECASE,
)
_EXTRACT_Q = re.compile(
    r"\bwhat (?:is|are) your (?:system prompt|hidden prompt|hidden instructions|"
    r"initial instructions)\b",
    re.IGNORECASE,
)
_EXTRACT_ABOVE = re.compile(
    r"\b(?:print|repeat|output) everything above\b",
    re.IGNORECASE,
)
_FAKE_SYSTEM = re.compile(r"(?m)^\s*system\s*:", re.IGNORECASE)
_FENCE = re.compile(r"```+\s*system\b", re.IGNORECASE)
_CHAT_TOKENS: tuple[str, ...] = (
    "<|im_start|>",
    "<|im_end|>",
    "<|system|>",
    "<|user|>",
    "<|assistant|>",
    "[inst]",
    "[/inst]",
    "<<sys>>",
    "<</sys>>",
)
_URGENCY: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bdo not tell (?:anyone|the user|a human|them)\b", re.IGNORECASE),
    re.compile(r"\bdon'?t tell (?:anyone|the user|a human)\b", re.IGNORECASE),
    re.compile(r"\bkeep this (?:a )?secret\b", re.IGNORECASE),
    re.compile(r"\bkeep it secret\b", re.IGNORECASE),
    re.compile(
        r"\bbypass (?:your |all )?(?:safety|filters|rules|restrictions|guardrails)\b",
        re.IGNORECASE,
    ),
    re.compile(r"\bno one will (?:know|notice|see)\b", re.IGNORECASE),
    re.compile(
        r"\burgent(?:ly)?\b.{0,48}?\b(?:ignore|bypass|override|secret)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:ignore|bypass|override)\b.{0,48}?\b(?:urgent|in secret)\b",
        re.IGNORECASE,
    ),
)
_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
    r"(?![A-Za-z0-9-])"
)
_PHONE_IN_BARE = re.compile(r"(?<![\d+])(?:0)?[6-9]\d{9}(?!\d)")
_PHONE_IN_GROUP = re.compile(r"(?<![\d+])[6-9]\d{4}[\s-]\d{5}(?!\d)")
_PHONE_IN_CC = re.compile(r"(?<!\d)\+91[\s-]?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
_PHONE_NANP = re.compile(r"(?<!\d)(?:\+1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?!\d)")
_PAN = re.compile(r"(?<![A-Za-z0-9])[A-Za-z]{5}[0-9]{4}[A-Za-z](?![A-Za-z0-9])")
_AADHAAR_GROUP = re.compile(r"(?<!\d)([2-9]\d{3})[ -](\d{4})[ -](\d{4})(?!\d)")
_AADHAAR_RUN = re.compile(r"(?<!\d)([2-9]\d{11})(?!\d)")
_CARD_GROUPED = re.compile(r"(?<!\d)(?:\d{4}[ -]){3}\d{4}(?!\d)")
_CARD_AMEX = re.compile(r"(?<!\d)\d{4}[ -]\d{6}[ -]\d{5}(?!\d)")
_CARD_RUN = re.compile(r"(?<!\d)\d{13,19}(?!\d)")
_SK = re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-|ant-|live-|test-)?[A-Za-z0-9]{20,}(?![A-Za-z0-9])")
_GHP = re.compile(r"(?<![A-Za-z0-9])ghp_[A-Za-z0-9]{36}(?![A-Za-z0-9])")
_AKIA = re.compile(r"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])")
_SLACK = re.compile(r"(?<![A-Za-z0-9])xoxb(?:-[A-Za-z0-9]{8,}){2,}(?![A-Za-z0-9])")
_JWT = re.compile(
    r"(?<![A-Za-z0-9_-])"
    r"(eyJ[A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})\.([A-Za-z0-9_-]{8,})"
    r"(?![A-Za-z0-9_-])"
)
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:(?:RSA|OPENSSH|EC|DSA|PGP) )?PRIVATE KEY(?: BLOCK)?-----")
_B64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{32,}={0,2}(?![A-Za-z0-9+/=])")
_HEX = re.compile(r"(?<![0-9A-Za-z])[0-9A-Fa-f]{32,}(?![0-9A-Za-z])")


@dataclass(frozen=True)
class Signal:
    """One fired rule. ``family`` is ``injection`` or ``pii``."""

    name: str
    family: str
    weight: float


def luhn_ok(number: str) -> bool:
    """Return True when ``number`` is digits and passes the Luhn check.

    Doubling runs from the right. The check digit itself (the rightmost
    digit) is not doubled. A doubled digit above 9 is reduced by 9, which is
    the same as adding its decimal digits. Length is not restricted here; the
    card detector applies the 13–19 digit window.
    """

    if not number.isdigit() or len(number) < 2:
        return False
    total = 0
    for index, char in enumerate(reversed(number)):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def verhoeff_checksum(number: str) -> int:
    """Verhoeff checksum. Valid numbers checksum to 0."""

    if not number.isdigit() or number == "":
        raise ValueError("verhoeff expects a non-empty digit string")
    check = 0
    for index, char in enumerate(reversed(number)):
        check = _D[check][_P[index % 8][int(char)]]
    return check


def verhoeff_ok(number: str) -> bool:
    """Return True when ``number`` is digits of length at least 2 and checksums to 0."""

    if not number.isdigit() or len(number) < 2:
        return False
    return verhoeff_checksum(number) == 0


def verhoeff_check_digit(number: str) -> str:
    """Return the digit that makes ``number + digit`` pass :func:`verhoeff_ok`."""

    if not number.isdigit() or number == "":
        raise ValueError("verhoeff expects a non-empty digit string")
    check = 0
    for index, char in enumerate(reversed(number)):
        check = _D[check][_P[(index + 1) % 8][int(char)]]
    return str(_INV[check])


def rule_score(signals: Sequence[Signal]) -> float:
    """Sum of fired weights, clipped to ``[0, 1]``."""

    total = 0.0
    for signal in signals:
        total += signal.weight
    if total <= 0.0:
        return 0.0
    if total >= 1.0:
        return 1.0
    return total


def detect(text: str) -> tuple[Signal, ...]:
    """Return the rule signals that fire on ``text``, in stable order."""

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    fired: list[Signal] = []
    checks = (
        ("instruction_override", _instruction_override),
        ("role_hijack", _role_hijack),
        ("system_prompt_extraction", _system_prompt_extraction),
        ("fake_system_turn", _fake_system_turn),
        ("system_fence", _system_fence),
        ("chat_template_token", _chat_template_token),
        ("encoded_payload", _encoded_payload),
        ("urgency_secrecy", _urgency_secrecy),
        ("email", _email),
        ("phone", _phone),
        ("pan", _pan),
        ("aadhaar", _aadhaar),
        ("credit_card", _credit_card),
        ("api_key", _api_key),
        ("private_key", _private_key),
    )
    for name, check in checks:
        if check(text):
            fired.append(Signal(name, FAMILIES[name], WEIGHTS[name]))
    return tuple(fired)


def _instruction_override(text: str) -> bool:
    return _OVERRIDE.search(text) is not None


def _role_hijack(text: str) -> bool:
    return _ROLE.search(text) is not None


def _system_prompt_extraction(text: str) -> bool:
    return (
        _EXTRACT.search(text) is not None
        or _EXTRACT_Q.search(text) is not None
        or _EXTRACT_ABOVE.search(text) is not None
    )


def _fake_system_turn(text: str) -> bool:
    return _FAKE_SYSTEM.search(text) is not None


def _system_fence(text: str) -> bool:
    return _FENCE.search(text) is not None


def _chat_template_token(text: str) -> bool:
    lowered = text.lower()
    return any(token in lowered for token in _CHAT_TOKENS)


def _urgency_secrecy(text: str) -> bool:
    return any(pattern.search(text) is not None for pattern in _URGENCY)


def _email(text: str) -> bool:
    return _EMAIL.search(text) is not None


def _phone(text: str) -> bool:
    return any(
        pattern.search(text) is not None
        for pattern in (_PHONE_IN_BARE, _PHONE_IN_GROUP, _PHONE_IN_CC, _PHONE_NANP)
    )


def _pan(text: str) -> bool:
    return _PAN.search(text) is not None


def _aadhaar(text: str) -> bool:
    for match in _AADHAAR_GROUP.finditer(text):
        if verhoeff_ok("".join(match.groups())):
            return True
    for match in _AADHAAR_RUN.finditer(text):
        if verhoeff_ok(match.group(1)):
            return True
    return False


def _credit_card(text: str) -> bool:
    seen: set[str] = set()
    for pattern in (_CARD_GROUPED, _CARD_AMEX, _CARD_RUN):
        for match in pattern.finditer(text):
            digits = "".join(char for char in match.group(0) if char.isdigit())
            if digits in seen:
                continue
            seen.add(digits)
            if 13 <= len(digits) <= 19 and luhn_ok(digits):
                return True
    return False


def _api_key(text: str) -> bool:
    if _SK.search(text) or _GHP.search(text) or _AKIA.search(text) or _SLACK.search(text):
        return True
    return _jwt(text)


def _jwt(text: str) -> bool:
    for match in _JWT.finditer(text):
        header = match.group(1)
        padded = header + ("=" * ((4 - len(header) % 4) % 4))
        try:
            raw = base64.urlsafe_b64decode(padded.encode("ascii"))
            data = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and "alg" in data:
            return True
    return False


def _private_key(text: str) -> bool:
    return _PRIVATE_KEY.search(text) is not None


def _encoded_payload(text: str) -> bool:
    for match in _B64.finditer(text):
        token = match.group(0)[:_ENCODED_CAP]
        if len(token) % 4 != 0:
            continue
        try:
            raw = base64.b64decode(token, validate=True)
        except (ValueError, binascii.Error):
            continue
        if _instruction_text(raw):
            return True
    for match in _HEX.finditer(text):
        token = match.group(0)[:_ENCODED_CAP]
        if len(token) % 2 != 0:
            token = token[:-1]
        try:
            raw = bytes.fromhex(token)
        except ValueError:
            continue
        if _instruction_text(raw):
            return True
    return False


def _instruction_text(raw: bytes) -> bool:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if sum(char.isalpha() for char in text) < 8:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in _ENCODED_MARKERS)
