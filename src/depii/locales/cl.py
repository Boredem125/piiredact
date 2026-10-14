"""Chile identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_CONTEXT = ("rut", "run", "rol único tributario", "rol unico tributario", "cédula", "cedula")

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "CL_RUT",
        r"(?<!\w)(?<!\w[.-])\d{1,2}\.\d{3}\.\d{3}-[\dkK](?!\w)(?!-\w)",
        score=0.85,
        validator=v.cl_rut,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "CL_RUT",
        r"(?<!\w)(?<!\w[.-])\d{7,8}-[\dkK](?!\w)(?!-\w)",
        name="cl_rut_no_dots",
        score=0.6,
        validator=v.cl_rut,
        context=_CONTEXT,
        needs_digit=True,
    ),
)
