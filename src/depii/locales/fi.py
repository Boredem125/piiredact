"""Finland identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "FI_HETU",
        r"(?<![A-Za-z0-9])\d{6}[-+A-FU-Y]\d{3}[0-9A-FHJ-NPR-Y](?![A-Za-z0-9])",
        # A Danish CPR number with a context word ties with this and wins on order.
        score=0.9,
        validator=v.fi_hetu,
        context=("hetu", "henkilötunnus", "henkilotunnus", "personbeteckning"),
        needs_digit=True,
    ),
)
