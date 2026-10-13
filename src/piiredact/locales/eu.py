"""Identifiers shared across the European Union."""

from __future__ import annotations

from typing import Any

from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "EU_VAT",
        r"(?<![A-Za-z0-9])(?:"
        r"ATU\d{8}|BE[01]\d{9}|DE\d{9}|DK\d{8}|ES[A-Z0-9]\d{7}[A-Z0-9]|FI\d{8}"
        r"|FR[A-HJ-NP-Z0-9]{2}\d{9}|IE\d[A-Z0-9+*]\d{5}[A-Z]{1,2}|IT\d{11}|LU\d{8}"
        r"|NL\d{9}B\d{2}|PL\d{10}|PT\d{9}|SE\d{12}"
        r")(?![A-Za-z0-9])",
        score=0.6,
        context=(
            "vat", "vat no", "vat number", "vat id", "ust-id", "ust-idnr", "ustid",
            "umsatzsteuer", "tva", "iva", "btw", "partita iva", "nif",
        ),  # fmt: skip
    ),
)
