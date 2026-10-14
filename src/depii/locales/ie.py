"""Ireland identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "IE_PPSN",
        r"(?<![A-Za-z0-9])\d{7}[A-W][A-IW]?(?![A-Za-z0-9])",
        score=0.7,
        validator=v.ie_ppsn,
        context=("ppsn", "pps", "pps number", "personal public service"),
        needs_digit=True,
    ),
)
