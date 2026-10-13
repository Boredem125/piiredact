"""Germany identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "DE_TAX_ID",
        r"(?<!\w)(?<!\w[.-])[1-9]\d ?\d{3} ?\d{3} ?\d{3}(?!\w)(?!-\w)",
        score=0.55,
        validator=v.de_tax_id,
        context=(
            "steuer",
            "steuer-id",
            "steuerid",
            "steuer-idnr",
            "idnr",
            "steuernummer",
            "identifikationsnummer",
            "steueridentifikationsnummer",
            "tin",
            "tax id",
        ),
        needs_digit=True,
    ),
    PatternDetector(
        "DE_ID_CARD",
        r"(?<![A-Za-z0-9])[CFGHJKLMNPRTVWXYZ][CFGHJKLMNPRTVWXYZ0-9]{8}\d?(?![A-Za-z0-9])",
        score=0.5,
        context=("personalausweis", "ausweis", "ausweisnummer", "id card", "identity card"),
        require_context=True,
    ),
)
