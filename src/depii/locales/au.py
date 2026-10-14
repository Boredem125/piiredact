"""Australia identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_ABN_CONTEXT = ("abn", "australian business number")

DETECTORS: tuple[Any, ...] = (
    # One number in eleven passes the TFN check, so it always needs context.
    PatternDetector(
        "AU_TFN",
        _L + r"\d{3}([ -]?)\d{3}\1\d{2,3}" + _R,
        score=0.5,
        validator=v.au_tfn,
        context=("tfn", "tax file number", "tax file no"),
        require_context=True,
        needs_digit=True,
    ),
    PatternDetector(
        "AU_ABN",
        _L + r"\d{2} \d{3} \d{3} \d{3}" + _R,
        # Above the phone detectors, which would otherwise take the last nine digits.
        score=0.7,
        validator=v.au_abn,
        context=_ABN_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "AU_ABN",
        _L + r"\d{11}" + _R,
        name="au_abn_unformatted",
        score=0.5,
        validator=v.au_abn,
        context=_ABN_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
    PatternDetector(
        "AU_MEDICARE",
        _L + r"[2-6]\d{3}([ -]?)\d{5}\1\d(?:[ /-]?[1-9])?" + _R,
        score=0.5,
        validator=v.au_medicare,
        context=("medicare", "medicare card", "medicare number", "medicare no"),
        require_context=True,
        needs_digit=True,
    ),
)
