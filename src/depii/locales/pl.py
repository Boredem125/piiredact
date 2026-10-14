"""Poland identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_NIP_CONTEXT = ("nip", "numer identyfikacji podatkowej", "vat")

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "PL_PESEL",
        _L + r"\d{11}" + _R,
        score=0.5,
        validator=v.pl_pesel,
        context=("pesel", "numer pesel"),
        require_context=True,
        needs_digit=True,
    ),
    PatternDetector(
        "PL_NIP",
        _L + r"(?:\d{3}-\d{3}-\d{2}-\d{2}|\d{3}-\d{2}-\d{2}-\d{3})" + _R,
        score=0.6,
        validator=v.pl_nip,
        context=_NIP_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "PL_NIP",
        _L + r"\d{10}" + _R,
        name="pl_nip_unformatted",
        score=0.5,
        validator=v.pl_nip,
        context=_NIP_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
    PatternDetector(
        "PL_ID_CARD",
        r"(?<![A-Za-z0-9])[A-Z]{3} ?\d{6}(?![A-Za-z0-9])",
        score=0.5,
        validator=lambda value: v.pl_id_card(value.replace(" ", "")),
        context=("dowód", "dowod", "dowód osobisty", "dowodu", "seria i numer", "id card"),
        require_context=True,
        needs_digit=True,
    ),
)
