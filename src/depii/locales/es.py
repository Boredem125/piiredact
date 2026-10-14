"""Spain identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

# Not after "1." either, so "1.38435736E+12" is not read as a DNI.
_L = r"(?<![A-Za-z0-9])(?<![A-Za-z0-9][-.])"
_R = r"(?![A-Za-z0-9])(?!-[A-Za-z0-9])"

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "ES_DNI",
        _L + r"\d{8}-?[A-Z]" + _R,
        score=0.85,
        validator=v.es_dni,
        context=("dni", "nif", "documento nacional de identidad"),
        needs_digit=True,
    ),
    PatternDetector(
        "ES_NIE",
        _L + r"[XYZ]-?\d{7}-?[A-Z]" + _R,
        score=0.9,
        validator=v.es_nie,
        context=("nie", "número de identidad de extranjero", "extranjero"),
        needs_digit=True,
    ),
)
