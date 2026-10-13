"""United Kingdom identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<![A-Za-z0-9])"
_R = r"(?![A-Za-z0-9])"

_NHS_CONTEXT = ("nhs", "nhs no", "nhs number", "national health")

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "GB_NINO",
        _L + r"[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]" + _R,
        score=0.85,
        validator=v.gb_nino,
        context=("nino", "national insurance", "ni number", "ni no", "insurance number"),
    ),
    PatternDetector(
        "GB_NHS_NUMBER",
        r"(?<!\w)(?<!\w[.-])\d{3}([ -])\d{3}\1\d{4}(?!\w)(?!-\w)",
        score=0.55,
        validator=v.gb_nhs,
        context=_NHS_CONTEXT,
    ),
    # One bare ten-digit number in eleven passes the check digit by chance.
    PatternDetector(
        "GB_NHS_NUMBER",
        r"(?<!\w)(?<!\w[.-])\d{10}(?!\w)(?!-\w)",
        name="gb_nhs_number_unformatted",
        score=0.55,
        validator=v.gb_nhs,
        context=_NHS_CONTEXT,
        require_context=True,
    ),
    PatternDetector(
        "GB_POSTCODE",
        _L
        + r"(?:GIR ?0AA|[A-PR-UWYZ][A-HK-Y]?\d[A-HJKPS-UW\d]? ?\d[ABD-HJLNP-UW-Z]{2})"
        + _R,
        score=0.6,
        context=("postcode", "post code", "address"),
    ),
    PatternDetector(
        "GB_DRIVING_LICENCE",
        _L + r"[A-Z9]{5}\d[0156]\d[0-3]\d{2}[A-Z9]{2}\d[A-Z]{2}" + _R,
        score=0.8,
        context=("driving licence", "driver licence", "licence number", "dvla"),
    ),
)
