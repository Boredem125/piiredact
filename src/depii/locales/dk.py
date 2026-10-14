"""Denmark identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_CONTEXT = ("cpr", "cpr-nr", "cpr-nummer", "cpr nummer", "personnummer")

DETECTORS: tuple[Any, ...] = (
    # Only the date can be checked, so the shape alone scores just above the
    # threshold. With a context word it outranks a Swedish personnummer.
    PatternDetector(
        "DK_CPR",
        _L + r"\d{6}-\d{4}" + _R,
        score=0.55,
        validator=v.dk_cpr,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "DK_CPR",
        _L + r"\d{10}" + _R,
        name="dk_cpr_unformatted",
        score=0.5,
        validator=v.dk_cpr,
        context=_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
)
