"""A bounded lexical view of instructions, not a document-wide allowlist.

Only explicitly reported quotations and locally negated action clauses are
masked. Quotation marks alone never make a payload safe. Offsets/newlines are
preserved. PII, encoded payloads and control syntax are checked independently.
This view cannot establish that prose claiming to report an attack is trusted.
"""

from __future__ import annotations

import re

_WINDOW = 160
_NEGATION = (
    r"(?:do not|does not|did not|don['’]t|doesn['’]t|didn['’]t|should not|shouldn['’]t|"
    r"must not|mustn['’]t|will not|won['’]t|never)"
)
# Do not mask "do not follow the rules" or "do not tell anyone": those can be
# attacks. Stop at a new coordinated action so "do not reveal X, but ignore
# prior rules" retains the affirmative override. This is lexical, not parsing.
_ACTION_VERBS = (
    r"ignore|disregard|forget|override|cancel|discard|abort|drop|disable|bypass|"
    r"reveal|show|print|repeat|display|output|leak|dump|give|quote|paste|restate|restating|"
    r"read|recite|list|emit|enter|switch|unlock|run|act|role[ -]?play|pretend|pose|simulate|open"
)
_NEGATED_ACTION = re.compile(
    rf"\b{_NEGATION}[ \t]+"
    r"(?:(?:ask|tell|instruct)[ \t]+"
    r"(?:(?:the|a|any|users?|anyone|model|assistant)[ \t]+){0,3}to[ \t]+)?"
    rf"(?:{_ACTION_VERBS})\b"
    rf"(?:(?!\b(?:and|but|then|instead|however|except|unless|now|{_NEGATION}|{_ACTION_VERBS})\b)"
    rf"""[^\n\r.!?,;():'"`‘’“”]){{0,{_WINDOW}}}""",
    re.IGNORECASE,
)
_CONDITIONAL = re.compile(
    r"\b(?:if|unless|until|except|otherwise|once|when (?:i|you|we|they))\b",
    re.IGNORECASE,
)
_QUOTED = re.compile(
    r"(?<!\w)'[^'\r\n]{1,1000}'(?!\w)|\"[^\"\r\n]{1,1000}\"|"
    r"(?<!`)`[^`\r\n]{1,1000}`(?!`)|“[^”\r\n]{1,1000}”|‘[^’\r\n]{1,1000}’"
)
_REPORTING_FRAME = re.compile(
    r"(?:\b(?:contained|included|recorded|detected).{0,64}?"
    r"\b(?:exact|literal|quoted) (?:words|strings?|tokens?)\b|"
    r"\b(?:sample|example) of (?:a |an )?(?:blocked|rejected|quarantined) (?:prompt|payload)\b"
    r"(?:\s*\(do not run\))?|"
    r"\b(?:some|malicious|blocked) payloads?.{0,100}?\b(?:phrase|words|string)\b|"
    r"\b(?:discussed|debated|analyzed|analysed).{0,100}?\b(?:users?|attackers?) (?:say|wrote)\b|"
    r"\b(?:analyzed|analysed|discussed)\s+(?:the|this|an?)\s+(?:sentence|phrase|string)\b|"
    r"\b(?:uses?|keeps?|stores?)\s+(?:the|a)\s+(?:test\s+)?fixture\b|"
    r"\b(?:indirect\s+)?injection\s+(?:may|can|could)\s+(?:hide|appear)\b"
    r".{0,80}?\b(?:says?|contains?)\b)\s*[:=]?\s*\Z",
    re.IGNORECASE,
)
_REPORTING_SUFFIX = re.compile(
    r"^\s+(?:is|was)\s+(?:an?\s+)?(?:attack phrase|literal string|"
    r"often used in (?:tutorials|documentation))\b",
    re.IGNORECASE,
)
_ACTIVATION = re.compile(
    r"\b(?:follow(?:ed)?|obey(?:ed)?|execut(?:e|ed)|appl(?:y|ied)|run|perform(?:ed)?|"
    r"carry out|comply with|act on|honou?r|"
    r"(?:treat|use|interpret).{0,32}?as\s+(?:(?:the|your|a|an|new|updated)\s+){0,3}"
    r"(?:instructions?|commands?|policy|system|authoritative)|"
    r"takes? (?:priority|precedence)|authoritative|mandatory|"
    r"(?:your|new|updated) (?:instructions?|policy|system))\b",
    re.IGNORECASE,
)
_NEGATED_ACTIVATION = re.compile(
    rf"\b{_NEGATION}\s+"
    r"(?:follow|obey|execute|apply|run|perform|carry out|act on)\b|"
    r"\bnot (?:a |an )?(?:request|instruction|command) to\s+"
    r"(?:follow|obey|execute|apply|run|perform|carry out|act on)\b",
    re.IGNORECASE,
)
_DOCUMENT_TASK = re.compile(
    r"\b(?:summari[sz]e|classify|translate|review|process|transcribe|condense|read|analy[sz]e)\b"
    r"[^\n.!?;]{0,48}?\b(?:this|the|following|attached|below)\s+"
    r"(?:(?:quoted|forwarded|attached|following|document)\s+){0,2}"
    r"(?:e-?mail|tickets?|webpages?|documents?|messages?|attachments?|excerpts?|text|snippets?)\b",
    re.IGNORECASE,
)
_MODEL_ADDRESS = re.compile(
    r"\b(?:when|if|once) you (?:read|receive|see|process|encounter)\b|"
    r"\b(?:note|instructions?) (?:to|for) (?:the )?(?:model|assistant)\b|"
    r"\b(?:model|assistant)\s*[:,]",
    re.IGNORECASE,
)
_SENTENCE_BREAK = re.compile(r"[\r\n.!?;]")


def instruction_view(text: str) -> str:
    """Mask non-operative spans without trusting a caller's document label.

    Call with normalized text. A reporting frame must border its quote in the
    same sentence. Nearby execution cues and document-processing requests
    veto quote masking, as does language addressing the model inside the quote.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    spans = []
    for match in _NEGATED_ACTION.finditer(text):
        start, end = match.span()
        context = text[max(0, start - _WINDOW) : end + _WINDOW]
        if not _CONDITIONAL.search(context):
            spans.append((start, end))
    for match in _QUOTED.finditer(text):
        start, end = match.span()
        # Inspect only a bounded neighborhood; a long document must not make
        # matching quadratic, nor let a reporting cue clear a later sentence.
        prefix = text[max(0, start - _WINDOW) : start]
        suffix = text[end : end + _WINDOW]
        before = prefix
        breaks = list(_SENTENCE_BREAK.finditer(before))
        if breaks:
            before = before[breaks[-1].end() :]
        after = suffix
        boundary = _SENTENCE_BREAK.search(after)
        if boundary:
            after = after[: boundary.start()]
        reported = _REPORTING_FRAME.search(before) or _REPORTING_SUFFIX.search(after)
        if not reported:
            continue
        outside = _NEGATED_ACTIVATION.sub(" ", prefix + " " + suffix)
        if not (
            _ACTIVATION.search(outside)
            or _CONDITIONAL.search(outside)
            or _DOCUMENT_TASK.search(outside)
            or _MODEL_ADDRESS.search(match[0])
        ):
            spans.append((start, end))
    return _mask(text, spans)


def _mask(text: str, spans: list[tuple[int, int]]) -> str:
    if not spans:
        return text
    chars = list(text)
    for start, end in spans:
        for index in range(start, end):
            if chars[index] not in "\r\n":
                chars[index] = " "
    return "".join(chars)
