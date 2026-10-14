"""Norway identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_CONTEXT = ("fødselsnummer", "fodselsnummer", "personnummer", "d-nummer", "fnr")

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "NO_FNR",
        _L + r"\d{6} \d{5}" + _R,
        # Above phone_in_mobile, which matches the same shape for some dates.
        score=0.75,
        validator=v.no_fnr,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "NO_FNR",
        _L + r"\d{11}" + _R,
        name="no_fnr_unformatted",
        score=0.5,
        validator=v.no_fnr,
        context=_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
)
