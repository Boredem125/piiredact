"""Netherlands identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "NL_BSN",
        r"(?<!\w)(?<!\w[.-])\d{9}(?!\w)(?!-\w)",
        score=0.55,
        validator=v.nl_bsn,
        context=("bsn", "burgerservicenummer", "sofinummer", "sofi", "sofi-nummer"),
        require_context=True,
    ),
)
