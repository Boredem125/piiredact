"""Singapore identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "SG_NRIC",
        r"(?<![A-Za-z0-9])[STFGM]\d{7}[A-Z](?![A-Za-z0-9])",
        score=0.85,
        validator=v.sg_nric,
        context=("nric", "fin", "ic", "ic number", "identity card"),
        needs_digit=True,
    ),
)
