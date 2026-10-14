"""South Africa identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "ZA_ID",
        r"(?<!\w)(?<!\w[.-])\d{6}( ?)\d{4}\1\d{3}(?!\w)(?!-\w)",
        # Above CREDIT_CARD: every ID passes Luhn, and many start like a Maestro card.
        score=0.96,
        validator=v.za_id,
        context=("id number", "identity number", "sa id", "rsa id", "id no"),
        needs_digit=True,
    ),
)
