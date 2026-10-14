"""United Arab Emirates identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "AE_EMIRATES_ID",
        r"(?<!\w)(?<!\w[.-])784(-?)\d{4}\1\d{7}\1\d(?!\w)(?!-\w)",
        score=0.95,
        validator=v.ae_emirates_id,
        context=("emirates id", "eid", "id card", "الهوية", "رقم الهوية"),
        needs_digit=True,
    ),
)
