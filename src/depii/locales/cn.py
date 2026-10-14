"""China identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "CN_RESIDENT_ID",
        r"(?<![A-Za-z0-9])[1-9]\d{5}(?:18|19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
        r"\d{3}[\dXx](?![A-Za-z0-9])",
        score=0.95,
        validator=v.cn_resident_id,
        context=("身份证", "身份证号", "身份证号码", "resident id", "id card"),
        needs_digit=True,
    ),
)
