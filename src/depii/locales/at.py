"""Austria identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_CONTEXT = (
    "svnr", "sv-nr", "sv-nummer", "sozialversicherungsnummer", "versicherungsnummer",
)  # fmt: skip

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "AT_SVNR",
        _L + r"[1-9]\d{3} \d{6}" + _R,
        score=0.55,
        validator=v.at_svnr,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "AT_SVNR",
        _L + r"[1-9]\d{9}" + _R,
        name="at_svnr_unformatted",
        score=0.5,
        validator=v.at_svnr,
        context=_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
)
