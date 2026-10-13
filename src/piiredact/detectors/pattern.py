"""Regex-based detector with validation, scoring and context words."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator, Sequence

from ..types import Span

# Placeholders written by a previous redaction pass. They are blanked before
# looking for context words, otherwise "[PHONE]" would count as the word
# "phone" and a second pass would redact more than the first.
_PLACEHOLDER = re.compile(
    r"\[[A-Z][A-Z0-9_]*(?::[^\]\s]{1,64})?\]"  # whole placeholder
    r"|\A[A-Z0-9_]*(?::[^\]\s]{0,64})?\]"  # cut off by the start of the window
    r"|\[[A-Z][A-Z0-9_]*(?::[^\]\s]{0,64})?\Z"  # cut off by the end of the window
)

CONTEXT_BEFORE = 48
CONTEXT_AFTER = 24
CONTEXT_BOOST = 0.35


class PatternDetector:
    """Find candidates with a regex, then validate, score and check context.

    ``validator``       returns False to discard a candidate.
    ``scorer``          returns the candidate's score; 0 or less discards it.
                        Without a scorer every candidate gets ``score``.
    ``context``         words that raise the score when found near the match.
    ``require_context`` discards candidates with no context word nearby,
                        unless the caller asks for strict mode. Use it for
                        shapes that are too common to trust alone, such as a
                        bare five-digit number.
    ``group``           regex group holding the value to redact.
    ``trim``            returns the part of the match to keep, which must be a
                        prefix of it, or "" to discard the candidate. For
                        shapes whose end a regex cannot decide.
    ``needs_digit``     every match contains a digit.
    ``needs``           substrings every match contains.

    The last two let the engine skip the detector for text that cannot
    match, which is most of the cost on short strings. They must be true of
    every possible match: a wrong hint silently disables the detector.
    """

    __slots__ = (
        "_context",
        "entity",
        "group",
        "name",
        "needs",
        "needs_digit",
        "pattern",
        "require_context",
        "score",
        "scorer",
        "trim",
        "validator",
    )

    def __init__(
        self,
        entity: str,
        pattern: str,
        *,
        name: str | None = None,
        score: float = 0.85,
        validator: Callable[[str], bool] | None = None,
        scorer: Callable[[str], float] | None = None,
        context: Sequence[str] = (),
        require_context: bool = False,
        group: int | str = 0,
        trim: Callable[[str], str] | None = None,
        flags: int = 0,
        needs_digit: bool = False,
        needs: Sequence[str] = (),
    ) -> None:
        if require_context and not context:
            raise ValueError("require_context needs at least one context word")
        self.entity = entity
        self.name = name or entity.lower()
        self.pattern = re.compile(pattern, flags)
        self.score = score
        self.validator = validator
        self.scorer = scorer
        self.require_context = require_context
        self.group = group
        self.trim = trim
        self.needs_digit = needs_digit
        self.needs = tuple(needs)
        self._context = (
            re.compile(
                r"(?<![^\W_])(?:" + "|".join(re.escape(word) for word in context) + r")(?![^\W_])",
                re.IGNORECASE,
            )
            if context
            else None
        )

    def __repr__(self) -> str:
        return f"PatternDetector({self.name!r}, entity={self.entity!r})"

    def _has_context(self, text: str, start: int, end: int) -> bool:
        if self._context is None:
            return False
        before = text[max(0, start - CONTEXT_BEFORE) : start]
        after = text[end : end + CONTEXT_AFTER]
        return any(
            self._context.search(_PLACEHOLDER.sub(" ", part)) is not None
            for part in (before, after)
        )

    def detect(self, text: str, *, strict: bool = False) -> Iterator[Span]:
        for match in self.pattern.finditer(text):
            start, end = match.span(self.group)
            if start < 0:
                continue
            value = text[start:end]
            if self.trim is not None:
                value = self.trim(value)
                end = start + len(value)
            if not value:
                continue
            if self.validator is not None and not self.validator(value):
                continue
            score = self.scorer(value) if self.scorer is not None else self.score
            if score <= 0:
                continue
            if self._has_context(text, start, end):
                score = min(1.0, score + CONTEXT_BOOST)
            elif self.require_context and not strict:
                continue
            yield Span(start, end, self.entity, value, score, self.name)
