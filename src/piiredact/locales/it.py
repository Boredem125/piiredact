"""Italy identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "IT_FISCAL_CODE",
        r"(?<![A-Za-z0-9])[A-Z]{6}\d{2}[A-EHLMPR-T]\d{2}[A-Z]\d{3}[A-Z](?![A-Za-z0-9])",
        score=0.95,
        validator=v.it_fiscal_code,
        context=("codice fiscale", "cf", "c.f.", "fiscal code"),
        needs_digit=True,
    ),
)
