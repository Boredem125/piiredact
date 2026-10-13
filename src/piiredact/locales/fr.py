"""France identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "FR_NIR",
        r"(?<!\w)(?<!\w[.-])[12] ?\d{2} ?(?:0[1-9]|1[0-2]|[2-9]\d) ?(?:\d{2}|2[AB]) ?\d{3} ?\d{3} ?\d{2}"
        r"(?!\w)(?!-\w)",
        # Above CREDIT_CARD: a 15-digit NIR can also pass the Luhn check, and
        # the mod-97 key plus the date fields are the stronger evidence.
        score=0.97,
        validator=v.fr_nir,
        context=("nir", "sécurité sociale", "securite sociale", "insee", "numéro de sécu"),
    ),
)
