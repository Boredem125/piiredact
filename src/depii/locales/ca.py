"""Canada identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_SIN_CONTEXT = (
    "sin", "sin#", "social insurance", "social insurance number",
    "nas", "assurance sociale", "numéro d'assurance sociale",
)  # fmt: skip

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "CA_SIN",
        _L + r"\d{3}([ -])\d{3}\1\d{3}" + _R,
        score=0.55,
        validator=v.ca_sin,
        context=_SIN_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "CA_SIN",
        _L + r"\d{9}" + _R,
        name="ca_sin_unformatted",
        score=0.5,
        validator=v.ca_sin,
        context=_SIN_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
    PatternDetector(
        "CA_POSTAL_CODE",
        r"(?<![A-Za-z0-9])[ABCEGHJ-NPRSTVXY]\d[ABCEGHJ-NPRSTV-Z] ?\d[ABCEGHJ-NPRSTV-Z]\d"
        r"(?![A-Za-z0-9])",
        score=0.6,
        context=("postal code", "code postal", "address", "adresse"),
        needs_digit=True,
    ),
)
