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
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass

from promptwarden.compose import composed_instruction_views, decoded_decisive_views, dehyphen
from promptwarden.context import instruction_view
from promptwarden.decoding import TOKEN_CHARS, decoded_views
from promptwarden.normalize import fold_unicode, normalize
from promptwarden.reversal import instruction_views

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

_OVERRIDE = re.compile(
    r"\b(?:ignore|disregard|forget|override|cancel|discard|abort|drop|disable|"
    r"(?:do not|don['’]t|never)\s+(?:follow|obey|respect|apply|comply with))\b"
    r"(?:\s+(?:all|every|the|your|its|my|any|previous|prior|above|earlier|"
    r"safety|content|current|existing|published)){0,5}\s+"
    r"(?:instructions?|prompts?|rules?|directions?|guidelines?|commands?|constraints?|"
    r"policies|policy(?:\s+stack)?|filters?|moderation|restrictions?|guardrails?|"
    r"refusal(?:\s+heuristics)?|safety(?:\s+checks?)?)\b",
    re.IGNORECASE,
)
_OVERRIDE_SCOPE = re.compile(
    r"\b(?:ignore|disregard|forget|discard)\s+(?:everything|all (?:text|content))\s+"
    r"(?:above|before (?:this|the|my))\b|"
    r"\b(?:pretend|assume|act as if)\b.{0,64}?"
    r"\b(?:prior|previous|earlier|safety|content)\s+(?:instructions?|directions?|rules?|policies)"
    r"\s+(?:do not|don't|no longer)\s+(?:apply|exist|matter)\b|"
    r"\b(?:answer|respond|act|comply|continue)\b.{0,48}?"
    r"\b(?:without (?:any |the |your )?(?:safety filters?|restrictions?|content rules?)|"
    r"as if no (?:policies|rules|restrictions) exist)\b|"
    r"\b(?:first|begin|start)\b[^\r\n.!?;]{0,48}?\b(?:output|say|reply|confirm)\b[\s\S]{0,120}?"
    r"\b(?:then|next)[\s,:]+(?:continue|answer|respond)\s+(?:uncensored|unfiltered|unrestricted)\b|"
    r"\b(?:translate|rewrite|rephrase)\b.{0,120}?\b(?:skip|skips|bypass|bypasses)\s+"
    r"(?:the |your )?(?:published |safety |content ){0,2}(?:rules|policies|filters)\b",
    re.IGNORECASE,
)
# Bounded instruction-override constructions, not a general translation layer.
# Compile on normalized patterns too: Cyrillic lookalike folding is lossy for
# genuine Russian, so the pattern must use the same representation as the text.
_MULTILINGUAL_OVERRIDE: tuple[re.Pattern[str], ...] = tuple(
    re.compile(fold_unicode(pattern))
    for pattern in (
        r"忽略.{0,24}(?:之前|先前|以前).{0,12}(?:指令|指示)",
        r"تجاهل\s+(?:كل\s+)?(?:القواعد|التعليمات)\s+السابقة",
        r"\b(?:ignore|desconsidere)\s+(?:todas?\s+)?(?:as?\s+)?"
        r"(?:instruções|regras)\s+anteriores\b",
        r"지금부터\s*(?:너는\s*)?제한\s*없는\s*dan",
        r"\bgüvenlik\s+(?:ilkelerini|kurallarını)\s+geçersiz\s+kıl\b",
        r"\b(?:dimentica|ignora)\s+(?:le\s+)?(?:linee\s+guida|istruzioni)\s+precedenti\b",
        r"\b(?:ignore|ignorez)\s+(?:toutes?\s+)?(?:les?\s+)?"
        r"(?:instructions|règles)\s+précédentes\b",
        r"\bignora\s+(?:todas?\s+)?(?:las?\s+)?(?:instrucciones|reglas)\s+anteriores\b",
        r"\bignoriere\s+(?:alle\s+)?(?:vorherigen|bisherigen)\s+(?:anweisungen|regeln)\b",
        r"(?:前|以前)の(?:指示|命令)を(?:すべて)?無視",
        r"\bигнорируй\s+(?:все\s+)?предыдущие\s+(?:инструкции|правила)\b",
        r"पिछले\s+(?:सभी\s+)?निर्देशों\s+को\s+नजरअंदाज\s+करें",
    )
)
_PERSONA_START = (
    r"\b(?:you are(?: now)?|(?:act|role[ -]?play|pose) as|"
    r"pretend(?: you are| to be)?|simulate|new role for (?:this|the) chat|"
    r"open (?:a |an )?(?:root )?(?:shell )?persona)\b"
)
_UNRESTRICTED = (
    r"\b(?:(?:unrestricted|uncensored|unfiltered)\s+(?:assistant|model|agent|ai|mode|persona|bot)|"
    r"(?:no|without) (?:ethics|refusals?|restrictions?|safety rules)|"
    r"never refuse|refuse (?:nothing|no instructions?)|"
    r"ignores? (?:\w+\s+){0,2}policies|ignoring (?:\w+\s+){0,2}policies|"
    r"bypass (?:content|safety) filters|skip (?:all )?(?:safety )?checks)\b"
)
_ROLE = re.compile(
    rf"{_PERSONA_START}(?:[\s:]+(?:(?:a|an)\s+)?(?:dan|jailbreak(?:gpt)?)\b|"
    rf"[^\r\n.!?;]{{0,180}}?{_UNRESTRICTED})|"
    r"\byou are(?: now)?\s+(?:unrestricted|uncensored|unfiltered)\s*(?=[.!?;\r\n]|$)|"
    r"\b(?:switch (?:to|into)|enter|unlock|you are(?: now)? in)\s+(?:(?:the|a)\s+)?"
    r"(?:unrestricted|developer|privileged(?: maintenance)?)\s+mode\b",
    re.IGNORECASE,
)
_EXTRACT_TARGET = (
    r"\b(?:system prompt|hidden prompt|initial prompt|developer message|"
    r"original instructions|initial instructions|hidden instructions|"
    r"hidden developer (?:instructions|prompt)|"
    r"developer instructions|initialization prompt|system role message|initial system message|"
    r"hidden system message|confidential configuration)\b"
)
_EXTRACT = re.compile(
    r"\b(?:reveal|show|print|repeat|display|output|leak|dump|give|quote|paste|"
    r"restate|restating|read|recite|list|emit)\b[^\r\n.!?;]{0,64}?" + _EXTRACT_TARGET,
    re.IGNORECASE,
)
_EXTRACT_Q = re.compile(
    r"\bwhat (?:is|are)\b[^\r\n.!?;]{0,48}?\b(?:your|the)\s+" + _EXTRACT_TARGET,
    re.IGNORECASE,
)
_EXTRACT_POLICY = re.compile(
    r"\b(?:restate|restating|repeat|quote|output|print)\b[^\r\n.!?;]{0,40}?"
    r"\b(?:policy|instructions?|directions?)\b[^\r\n.!?;]{0,64}?"
    r"\b(?:configured|provided|set|given)\b[^\r\n.!?;]{0,32}?"
    r"\b(?:before|at the (?:start|beginning) of)\s+(?:this|the|our)\s+"
    r"(?:chat|conversation|session)\b",
    re.IGNORECASE,
)
_EXTRACT_STORY = re.compile(
    _EXTRACT_TARGET + r".{0,64}?\b(?:bedtime story|tradition)\b.{0,64}?"
    r"\b(?:continue|recite|repeat)\b",
    re.IGNORECASE,
)
_EXTRACT_ABOVE = re.compile(
    r"\b(?:print|repeat|output) everything above\b",
    re.IGNORECASE,
)
_FAKE_SYSTEM = re.compile(r"(?m)^\s*system\s*:|<\s*/?\s*system\s*>", re.IGNORECASE)
_LONG_WORD = re.compile(r"[A-Za-z0-9]+={0,2}")
_FENCE = re.compile(r"(?<!`)`{3,}\s*system\b", re.IGNORECASE)
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
        r"\bbypass (?:your |all |the )?(?:safety|content|filters|rules|restrictions|guardrails|"
        r"moderation)\b",
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
    """Return signals in stable order, preserving identifiers and encoded bytes.

    Prose rules use the context view. Control syntax uses normalized text, and
    PII and encoded candidates use the original. A reversed view, a composed
    repair (de-spacing, loose de-leet, nested decoding), or a dehyphenated
    view can add a decisive instruction signal. It cannot add a PII signal.
    Classifier n-grams stay on the direct normalized view. Decoded payloads
    also get a deleeted, casefolded reading inside the existing decode budget.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    normalized = normalize(text)
    contextual = instruction_view(normalized)
    extra_names = _extra_instruction_names(text)
    fired: list[Signal] = []
    for name in SIGNAL_NAMES:
        if name in PII_SIGNALS or name == "encoded_payload":
            sample = text
        elif name in _CONTROL_SIGNALS:
            sample = normalized
        else:
            sample = contextual
        if _CHECKS[name](sample) or name in extra_names:
            fired.append(Signal(name, FAMILIES[name], WEIGHTS[name]))
    return tuple(fired)


def _instruction_override(text: str) -> bool:
    return (
        _OVERRIDE.search(text) is not None
        or _OVERRIDE_SCOPE.search(text) is not None
        or any(pattern.search(text) is not None for pattern in _MULTILINGUAL_OVERRIDE)
    )


def _role_hijack(text: str) -> bool:
    return _ROLE.search(text) is not None


def _system_prompt_extraction(text: str) -> bool:
    return (
        _EXTRACT.search(text) is not None
        or _EXTRACT_Q.search(text) is not None
        or _EXTRACT_ABOVE.search(text) is not None
        or _EXTRACT_POLICY.search(text) is not None
        or _EXTRACT_STORY.search(text) is not None
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
    for decoded in decoded_views(text):
        contextual = instruction_view(normalize(decoded))
        if any(_CHECKS[name](contextual) for name in _DECISIVE_INSTRUCTIONS):
            return True
        # Deleet and casefold-first stay on text the decoder already yielded.
        # They do not open another codec attempt.
        if any(
            view != contextual and any(_CHECKS[name](view) for name in _DECISIVE_INSTRUCTIONS)
            for view in decoded_decisive_views(decoded)
        ):
            return True
        if _extra_instruction_names(decoded):
            return True
    return False


def _hyphen_phrase(phrase: str) -> bool:
    """True when a hyphen run is an instruction with the hyphens removed."""

    masked = instruction_view(fold_unicode(phrase))
    return any(_CHECKS[name](masked) for name in _DECISIVE_INSTRUCTIONS)


def _extra_instruction_names(text: str) -> set[str]:
    """Run only decisive instruction checks on the masked, transformed views."""

    # A single ASCII word longer than the token cap cannot be segmented by
    # either lexical repair. Its encoded reading is handled separately.
    if len(text) > TOKEN_CHARS and _LONG_WORD.fullmatch(text):
        return set()
    found: set[str] = set()
    sources = [text]
    # Fragment joins always run. A run of whole words is spaced only when that
    # run is already a decisive phrase, so a benign compound stays hyphenated.
    # Reversal views do not include the forward reading, so the repaired text
    # is checked directly as well as through those views.
    repaired = dehyphen(text, phrase_match=_hyphen_phrase)
    if repaired != text:
        sources.append(repaired)
        direct = (
            instruction_view(normalize(repaired)),
            instruction_view(fold_unicode(repaired)),
        )
        for masked in direct:
            for name in _DECISIVE_INSTRUCTIONS:
                if name not in found and _CHECKS[name](masked):
                    found.add(name)
    for source in sources:
        for readings in (instruction_views, composed_instruction_views):
            for reading in readings(source, mask_first=True):
                for name in _DECISIVE_INSTRUCTIONS:
                    if name not in found and _CHECKS[name](reading.text):
                        found.add(name)
    return found


_CONTROL_SIGNALS = ("fake_system_turn", "system_fence", "chat_template_token")
# Every injection weight is at least 0.60, so one hit flags at the default
# threshold. PII is excluded: it is not an instruction pattern.
_DECISIVE_INSTRUCTIONS = tuple(name for name in INJECTION_SIGNALS if name != "encoded_payload")
_CHECKS = {
    "instruction_override": _instruction_override,
    "role_hijack": _role_hijack,
    "system_prompt_extraction": _system_prompt_extraction,
    "fake_system_turn": _fake_system_turn,
    "system_fence": _system_fence,
    "chat_template_token": _chat_template_token,
    "encoded_payload": _encoded_payload,
    "urgency_secrecy": _urgency_secrecy,
    "email": _email,
    "phone": _phone,
    "pan": _pan,
    "aadhaar": _aadhaar,
    "credit_card": _credit_card,
    "api_key": _api_key,
    "private_key": _private_key,
}
