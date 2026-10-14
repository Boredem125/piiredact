"""Brazil identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

_L = r"(?<!\w)(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"

_CPF_CONTEXT = ("cpf", "cadastro de pessoas físicas", "cadastro de pessoas fisicas")
_CNPJ_CONTEXT = ("cnpj", "cadastro nacional da pessoa jurídica")

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        "BR_CPF",
        _L + r"\d{3}\.\d{3}\.\d{3}-\d{2}" + _R,
        score=0.9,
        validator=v.br_cpf,
        context=_CPF_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "BR_CPF",
        _L + r"\d{11}" + _R,
        name="br_cpf_unformatted",
        score=0.5,
        validator=v.br_cpf,
        context=_CPF_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
    # From July 2026 the first twelve characters may be letters as well as digits.
    PatternDetector(
        "BR_CNPJ",
        r"(?<![A-Za-z0-9])[0-9A-Z]{2}\.[0-9A-Z]{3}\.[0-9A-Z]{3}/[0-9A-Z]{4}-\d{2}(?![A-Za-z0-9])",
        score=0.9,
        validator=v.br_cnpj,
        context=_CNPJ_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        "BR_CNPJ",
        r"(?<![A-Za-z0-9])[0-9A-Z]{12}\d{2}(?![A-Za-z0-9])",
        name="br_cnpj_unformatted",
        score=0.5,
        validator=v.br_cnpj,
        context=_CNPJ_CONTEXT,
        require_context=True,
        needs_digit=True,
    ),
)
