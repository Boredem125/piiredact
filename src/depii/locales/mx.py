"""Mexico identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_STATES = "AS|B[CS]|C[CLMSH]|D[FG]|G[TR]|HG|JC|M[CNS]|N[ETL]|OC|PL|Q[TR]|S[PLR]|T[CSL]|VZ|YN|ZS"

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "MX_CURP",
        r"(?<![A-Za-z0-9])[A-Z][AEIOUX][A-Z]{2}\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])"
        rf"[HMX](?:{_STATES})[B-DF-HJ-NP-TV-Z]{{3}}[A-Z\d]\d(?![A-Za-z0-9])",
        score=0.95,
        validator=v.mx_curp,
        context=("curp", "clave única de registro de población"),
        needs_digit=True,
    ),
    PatternDetector(
        "MX_RFC",
        r"(?<![A-Za-z0-9&])[A-ZÑ&]{3,4}\d{6}[A-Z\d]{3}(?![A-Za-z0-9])",
        score=0.6,
        validator=v.mx_rfc,
        context=("rfc", "registro federal de contribuyentes"),
        needs_digit=True,
    ),
)
