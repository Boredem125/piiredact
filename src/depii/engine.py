"""The redaction pipeline: normalise, detect, resolve overlaps, apply operators."""

from __future__ import annotations

import warnings
from bisect import bisect_right
from collections.abc import Iterable, Mapping
from typing import Any

from . import registry
from .detectors.base import Detector
from .normalize import normalize, to_original
from .operators import Keep, Operator, Replace
from .types import Result, Span

DEFAULT_MIN_SCORE = 0.5
STRICT_MIN_SCORE = 0.3

_DIGITS = "0123456789"


def _has_digit(text: str) -> bool:
    # Ten substring searches beat one regex scan: each runs at memchr speed.
    # Non-ASCII digits were folded to ASCII by normalize().
    return any(digit in text for digit in _DIGITS)


class Redactor:
    """Find and redact PII.

    A Redactor is immutable after construction and safe to share between
    threads. Build it once and reuse it; construction is the expensive part.

    ``locales``          country packs to load, e.g. ``["us", "in"]``.
                         ``None`` loads every installed pack.
    ``entities``         only detect these entity types. ``None`` means all.
    ``exclude_entities`` entity types to leave alone.
    ``policy``           entity type -> operator. Unlisted types use
                         ``default_operator``.
    ``default_operator`` defaults to ``Replace()``, which writes ``[ENTITY]``.
    ``min_score``        detections scoring below this are ignored.
    ``strict``           prefer over-redaction: lower the score threshold and
                         keep candidates that normally need a context word.
    ``detectors``        extra detectors, e.g. ``SpacyDetector()``.
    ``allow``            exact values never to redact (case-insensitive),
                         such as your own support address.
    """

    def __init__(
        self,
        *,
        locales: Iterable[str] | None = None,
        entities: Iterable[str] | None = None,
        exclude_entities: Iterable[str] | None = None,
        policy: Mapping[str, Operator] | None = None,
        default_operator: Operator | None = None,
        min_score: float = DEFAULT_MIN_SCORE,
        strict: bool = False,
        detectors: Iterable[Detector] = (),
        allow: Iterable[str] = (),
    ) -> None:
        if not 0.0 <= min_score <= 1.0:
            raise ValueError("min_score must be between 0 and 1")
        self._entities = None if entities is None else frozenset(entities)
        self._excluded = frozenset(exclude_entities or ())
        self._detectors = registry.build(locales, self._entities, self._excluded, detectors)
        # (order, detector, needs a digit, substrings it needs)
        self._plan = tuple(
            (
                order,
                detector,
                bool(getattr(detector, "needs_digit", False)),
                tuple(getattr(detector, "needs", ())),
            )
            for order, detector in enumerate(self._detectors)
        )
        self._policy: dict[str, Operator] = dict(policy or {})
        self._default: Operator = default_operator if default_operator is not None else Replace()
        self.strict = strict
        self.min_score = min(min_score, STRICT_MIN_SCORE) if strict else min_score
        self._allow = frozenset(value.casefold() for value in allow)

        for name, operator in [*self._policy.items(), ("default_operator", self._default)]:
            if not isinstance(operator, Operator):
                raise TypeError(f"{name}: {operator!r} has no apply(value, entity) method")
        self._warn_unknown_entities()

    def _warn_unknown_entities(self) -> None:
        if any(detector.entity == "*" for detector in self._detectors):
            return  # open-ended detectors can emit anything
        known = set(registry.supported_entities()) | {d.entity for d in self._detectors}
        # Imported here: structured imports this module.
        from .structured import HINT_ENTITIES

        known |= HINT_ENTITIES
        named = {*self._policy, *(self._entities or ()), *self._excluded}
        unknown = sorted(named - known)
        if unknown:
            warnings.warn(
                f"unknown entity type(s): {', '.join(unknown)}. "
                "Check spelling; see depii.supported_entities().",
                stacklevel=3,
            )

    @property
    def detectors(self) -> tuple[Detector, ...]:
        return self._detectors

    def operator_for(self, entity: str) -> Operator:
        return self._policy.get(entity, self._default)

    def _wanted(self, entity: str) -> bool:
        return (self._entities is None or entity in self._entities) and (
            entity not in self._excluded
        )

    def scan(self, text: str) -> list[Span]:
        """Return the PII found in ``text``, ordered by position, without overlaps."""
        if not isinstance(text, str):
            raise TypeError(f"text must be str, not {type(text).__name__}")
        if not text:
            return []
        normalised, offsets = normalize(text)

        has_digit = _has_digit(normalised)
        candidates: list[tuple[float, int, int, int, Span]] = []
        for order, detector, needs_digit, needs in self._plan:
            if needs_digit and not has_digit:
                continue
            if needs and not all(part in normalised for part in needs):
                continue
            open_ended = detector.entity == "*"
            for found in detector.detect(normalised, strict=self.strict):
                if found.score < self.min_score or found.end <= found.start:
                    continue
                if open_ended and not self._wanted(found.entity):
                    continue
                start, end = to_original(found.start, found.end, offsets)
                value = text[start:end]
                if self._allow and value.casefold() in self._allow:
                    continue
                span = Span(start, end, found.entity, value, found.score, found.detector)
                candidates.append((-span.score, start - end, order, start, span))

        # Best score first, then longest, then detector order, then position.
        candidates.sort(key=lambda item: item[:4])
        starts: list[int] = []
        chosen: list[Span] = []
        for *_, span in candidates:
            index = bisect_right(starts, span.start)
            if index > 0 and chosen[index - 1].end > span.start:
                continue
            if index < len(chosen) and chosen[index].start < span.end:
                continue
            starts.insert(index, span.start)
            chosen.insert(index, span)
        return chosen

    def redact(self, text: str) -> Result:
        """Return ``text`` with every detected value replaced by its operator's output."""
        pieces: list[str] = []
        applied: list[Span] = []
        position = 0
        for span in self.scan(text):
            operator = self.operator_for(span.entity)
            if isinstance(operator, Keep):
                continue
            pieces.append(text[position : span.start])
            pieces.append(operator.apply(span.text, span.entity))
            position = span.end
            applied.append(span)
        if not applied:
            return Result(text)
        pieces.append(text[position:])
        return Result("".join(pieces), tuple(applied))

    def redact_obj(self, obj: Any, **options: Any) -> Any:
        """Redact every string inside nested dicts, lists, tuples and sets.

        See :func:`depii.structured.redact_obj` for the options.
        """
        from .structured import redact_obj

        return redact_obj(obj, self, **options)
