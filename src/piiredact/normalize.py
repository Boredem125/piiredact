"""Text normalisation that keeps a map back to original offsets.

Detection runs on the normalised text so that full-width digits, non-ASCII
digits, exotic dashes and zero-width characters cannot hide an identifier.
Redaction is applied to the original text using the offset map.
"""

from __future__ import annotations

import unicodedata

# Invisible characters that can be inserted to split an identifier.
_ZERO_WIDTH = frozenset("​‌‍⁠﻿­᠎")

# Dash look-alikes folded to ASCII hyphen-minus. NFKC does not fold these.
_DASHES = dict.fromkeys(map(ord, "‐‑‒–—―−﹘﹣－"), "-")


def normalize(text: str) -> tuple[str, list[int] | None]:
    """Return ``(normalised, offsets)``.

    ``offsets[i]`` is the index in ``text`` of the character that produced
    ``normalised[i]``. ``offsets`` is ``None`` when the text is unchanged,
    which is the fast path for ASCII input.
    """
    if text.isascii():
        return text, None

    out: list[str] = []
    offsets: list[int] = []
    for index, char in enumerate(text):
        if char in _ZERO_WIDTH:
            continue
        if char.isascii():
            out.append(char)
            offsets.append(index)
            continue
        if char.isdecimal():
            folded = str(unicodedata.decimal(char))
        else:
            folded = unicodedata.normalize("NFKC", char).translate(_DASHES)
        for piece in folded:
            out.append(piece)
            offsets.append(index)
    normalised = "".join(out)
    if normalised == text:
        return text, None
    return normalised, offsets


def to_original(start: int, end: int, offsets: list[int] | None) -> tuple[int, int]:
    """Map a ``[start, end)`` range in normalised text back to the original text."""
    if offsets is None:
        return start, end
    return offsets[start], offsets[end - 1] + 1
