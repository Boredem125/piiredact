"""Detector interface."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol, runtime_checkable

from ..types import Span


@runtime_checkable
class Detector(Protocol):
    """Anything that can find PII spans in text.

    ``entity`` is the entity type the detector emits, used to filter detectors
    by the caller's ``entities`` setting. A detector that emits several types
    (the NER detector, for example) sets ``entity`` to ``"*"``.

    ``strict`` asks the detector to prefer recall: emit candidates it would
    normally hold back for lack of supporting context.

    A detector may also define ``needs_digit`` (bool) and ``needs`` (a tuple
    of substrings). The engine then skips it for text with no digit, or
    without all of those substrings. Both must hold for every possible match.
    """

    name: str
    entity: str

    def detect(self, text: str, *, strict: bool = False) -> Iterable[Span]: ...
