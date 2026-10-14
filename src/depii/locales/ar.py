"""Argentina identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_CONTEXT = ("cuit", "cuil", "cdi", "clave única de identificación tributaria")

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "AR_CUIT",
        _L + r"\d{2}-\d{8}-\d" + _R,
        score=0.85,
        validator=v.ar_cuit,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "AR_CUIT",
        _L + r"\d{11}" + _R,
        name="ar_cuit_unformatted",
        score=0.5,
        validator=v.ar_cuit,
        context=_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
)
