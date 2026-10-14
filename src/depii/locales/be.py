"""Belgium identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_CONTEXT = (
    "rijksregisternummer", "rijksregister", "numéro national", "numero national",
    "national number", "registre national", "insz", "niss",
)  # fmt: skip

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "BE_NATIONAL_NUMBER",
        _L + r"\d{2}\.\d{2}\.\d{2}-\d{3}\.\d{2}" + _R,
        score=0.85,
        validator=v.be_national_number,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "BE_NATIONAL_NUMBER",
        _L + r"\d{11}" + _R,
        name="be_national_number_unformatted",
        score=0.5,
        validator=v.be_national_number,
        context=_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
)
