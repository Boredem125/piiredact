"""Sweden identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_CONTEXT = ("personnummer", "personnr", "samordningsnummer", "person number")

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "SE_PERSONNUMMER",
        _L + r"(?:\d{2})?\d{6}[-+]\d{4}" + _R,
        score=0.85,
        validator=v.se_personnummer,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "SE_PERSONNUMMER",
        _L + r"(?:\d{2})?\d{10}" + _R,
        name="se_personnummer_unformatted",
        score=0.5,
        validator=v.se_personnummer,
        context=_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
)
