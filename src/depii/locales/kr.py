"""South Korea identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_CONTEXT = ("rrn", "resident registration", "주민등록번호", "주민번호")

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "KR_RRN",
        _L + r"\d{6}-[1-8]\d{6}" + _R,
        score=0.8,
        validator=v.kr_rrn,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "KR_RRN",
        _L + r"\d{6}[1-8]\d{6}" + _R,
        name="kr_rrn_unformatted",
        score=0.5,
        validator=v.kr_rrn,
        context=_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
)
