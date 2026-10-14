"""Turkey identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "TR_TCKN",
        r"(?<!\w)(?<!\w[.-])[1-9]\d{10}(?!\w)(?!-\w)",
        score=0.5,
        validator=v.tr_tckn,
        context=("tckn", "tc kimlik", "t.c. kimlik", "kimlik no", "kimlik numarası", "tc no"),
        require_context=True,
        needs_digit=True,
    ),
)
