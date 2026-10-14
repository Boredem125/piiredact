"""Switzerland identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "CH_AHV",
        r"(?<!\w)(?<!\w[.-])756(\.?)\d{4}\1\d{4}\1\d{2}(?!\w)(?!-\w)",
        score=0.95,
        validator=v.ch_ahv,
        context=("ahv", "avs", "avs/ahv", "ahv-nummer", "numéro avs", "sozialversicherungsnummer"),
        needs_digit=True,
    ),
)
