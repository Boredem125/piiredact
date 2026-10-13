"""Redaction of large inputs without loading them into memory."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Iterator
from typing import TYPE_CHECKING, TextIO

from .types import Result

if TYPE_CHECKING:
    from .engine import Redactor

DEFAULT_CHUNK = 64 * 1024
_KEY_BEGIN = "PRIVATE KEY-----"
_KEY_END = "-----END"


def chunks(lines: Iterable[str], size: int = DEFAULT_CHUNK) -> Iterator[str]:
    """Group lines into chunks of about ``size`` characters, split at line ends.

    A chunk is held open while a PEM private key block is unfinished, up to
    four times ``size``, so a key is not cut in half and missed.
    """
    buffer: list[str] = []
    length = 0
    open_key = False
    for line in lines:
        buffer.append(line)
        length += len(line)
        if _KEY_BEGIN in line:
            open_key = _KEY_END not in line
        if length >= size and (not open_key or length >= 4 * size):
            yield "".join(buffer)
            buffer, length, open_key = [], 0, False
    if buffer:
        yield "".join(buffer)


def redact_lines(
    lines: Iterable[str], redactor: Redactor, *, chunk_size: int = DEFAULT_CHUNK
) -> Iterator[Result]:
    """Redact an iterable of lines chunk by chunk, yielding one ``Result`` per chunk.

    Context words are only seen within a chunk. A value at the very start of
    a chunk whose context word ended the previous chunk can be missed, which
    matters only for identifiers that need context, such as a bare ZIP code.
    """
    for chunk in chunks(lines, chunk_size):
        yield redactor.redact(chunk)


def redact_stream(
    source: TextIO, sink: TextIO, redactor: Redactor, *, chunk_size: int = DEFAULT_CHUNK
) -> dict[str, int]:
    """Copy ``source`` to ``sink`` with PII redacted. Return counts per entity type."""
    totals: Counter[str] = Counter()
    for result in redact_lines(source, redactor, chunk_size=chunk_size):
        sink.write(result.text)
        totals.update(span.entity for span in result.spans)
    return dict(totals)
