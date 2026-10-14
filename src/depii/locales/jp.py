"""Japan identifiers."""

from __future__ import annotations

from typing import Any

from .. import validators as v
from ..detectors.pattern import PatternDetector

DETECTORS: tuple[Any, ...] = (
    # Twelve digits in groups of four is also the Aadhaar shape; one number in
    # eleven passes this check, so context is required.
    PatternDetector(
        "JP_MY_NUMBER",
        r"(?<!\w)(?<!\w[.-])\d{4}([ -]?)\d{4}\1\d{4}(?!\w)(?!-\w)",
        score=0.5,
        validator=v.jp_my_number,
        context=("my number", "mynumber", "individual number", "マイナンバー", "個人番号"),
        require_context=True,
        needs_digit=True,
    ),
)
