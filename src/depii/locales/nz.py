"""New Zealand identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "NZ_IRD",
        r"(?<!\w)(?<!\w[.-])\d{2,3}([ -]?)\d{3}\1\d{3}(?!\w)(?!-\w)",
        score=0.5,
        validator=v.nz_ird,
        context=("ird", "ird number", "ird no", "inland revenue", "gst number"),
        require_context=True,
        needs_digit=True,
    ),
    # Three letters and four digits is also the shape of many codes and plates.
    PatternDetector(
        "NZ_NHI",
        r"(?<![A-Za-z0-9])[A-HJ-NP-Z]{3}\d{4}(?![A-Za-z0-9])",
        score=0.5,
        validator=v.nz_nhi,
        context=("nhi", "nhi number", "national health index"),
        require_context=True,
        needs_digit=True,
    ),
)
