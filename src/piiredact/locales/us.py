"""United States identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_SSN_CONTEXT = ("ssn", "ssn#", "social security", "social security number", "soc sec", "ss#")

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "US_SSN",
        _L + r"\d{3}([- ])\d{2}\1\d{4}" + _R,
        score=0.85,
        validator=v.us_ssn,
        context=_SSN_CONTEXT,
    ),
    PatternDetector(
        "US_SSN",
        _L + r"\d{9}" + _R,
        name="us_ssn_unformatted",
        score=0.5,
        validator=v.us_ssn,
        context=_SSN_CONTEXT,
        require_context=True,
    ),
    PatternDetector(
        "US_ITIN",
        _L + r"9\d{2}([- ])(?:5\d|6[0-5]|7\d|8[0-8]|9[0-24-9])\1\d{4}" + _R,
        score=0.85,
        context=("itin", "taxpayer identification", "tax id"),
    ),
    PatternDetector(
        "US_EIN",
        _L + r"\d{2}-\d{7}" + _R,
        score=0.5,
        context=("ein", "fein", "employer identification", "employer id", "tax id", "tin"),
        require_context=True,
    ),
    PatternDetector(
        "US_PASSPORT",
        _L + r"(?:[A-Z]\d{8}|\d{9})" + _R,
        score=0.5,
        context=("passport", "passport no", "passport number", "passport#"),
        require_context=True,
    ),
    PatternDetector(
        "US_ROUTING_NUMBER",
        _L + r"\d{9}" + _R,
        score=0.55,
        validator=v.aba_routing,
        context=("routing", "routing number", "aba", "rtn", "ach"),
        require_context=True,
    ),
    PatternDetector(
        "US_ZIP",
        _L + r"\d{5}(?:-\d{4})?" + _R,
        score=0.4,
        context=("zip", "zipcode", "zip code", "postal code"),
        require_context=True,
    ),
)
