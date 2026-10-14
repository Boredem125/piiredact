"""Portugal identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    # One nine-digit number in eleven passes the check, so context is required.
    PatternDetector(
        "PT_NIF",
        r"(?<!\w)(?<!\w[.-])\d{3}( ?)\d{3}\1\d{3}(?!\w)(?!-\w)",
        score=0.5,
        validator=v.pt_nif,
        context=("nif", "contribuinte", "número de contribuinte", "numero de contribuinte"),
        require_context=True,
        needs_digit=True,
    ),
)
