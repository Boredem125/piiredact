"""Passes that use what was found elsewhere in the same text.

Detectors look at one place at a time. These passes look at the whole text
after detection:

* **Propagation.** A value found once, perhaps thanks to a label or a
  context word, is redacted wherever else it appears: "SSN 078-05-1120 ...
  confirmed 078-05-1120".
* **Person linking.** The parts of a detected name are redacted where they
  appear alone, and linked to the full name: "Jane Doe ... Ms Doe ... Jane"
  all refer to "Jane Doe", so ``Tokenize`` gives them one token.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Iterable
from dataclasses import replace

from .types import PERSON, URL, Span

PROPAGATED = "propagated"

# Values this short, or this generic, are not worth chasing across the text.
_MIN_LENGTH = 4
_MIN_NAME_PART = 3
_NO_PROPAGATION = frozenset({URL})
# More distinct values than this would make the search pattern too large to
# be worth it; the first ones found are propagated, the rest are not.
_MAX_VALUES = 2000
_NAME_PART = re.compile(r"[^\W\d_]+(?:['’-](?![sS](?![^\W\d_]))[^\W\d_]+)*")


def _name_parts(name: str) -> list[str]:
    # Imported here: names loads its word lists lazily and imports this package.
    from .detectors.names import _NOT_NAMES, ambiguous

    common = ambiguous()
    return [
        part
        for part in _NAME_PART.findall(name)
        if len(part) >= _MIN_NAME_PART
        and part[0].isupper()
        and part.lower() not in _NOT_NAMES
        and part.lower() not in common
    ]


def _distinctive(value: str) -> bool:
    """Whether finding ``value`` elsewhere in the text is good evidence.

    "078051120", "jane@example.com" and "Priya Sharma" are. A plain lowercase
    word such as "value" or "address" is not, even when a label once made it
    look like data.
    """
    if value.lower() in ("none", "null", "true", "false"):
        return False
    return any(ch.isdigit() or ch == "@" or ch.isupper() or not ch.isascii() for ch in value)


def _targets(spans: Iterable[Span]) -> dict[str, tuple[str, float, str]]:
    """value -> (entity, score, link) for every value worth looking for."""
    spans = [span for span in spans if span.entity not in _NO_PROPAGATION]
    # First the parts of every multi-word name, and whose name each belongs to.
    part_owner: dict[str, set[str]] = {}
    for span in spans:
        value = span.text.strip()
        if span.entity == PERSON and " " in value:
            for part in _name_parts(value):
                part_owner.setdefault(part, set()).add(span.link or value)
    targets: dict[str, tuple[str, float, str]] = {}
    for part, owners in part_owner.items():
        # A surname shared by two people stays redacted but is not linked
        # to either of them.
        link = next(iter(owners)) if len(owners) == 1 else ""
        targets[part] = (PERSON, 0.8, link)
    # Then every value found. A part that was also found on its own keeps
    # the link to its full name.
    for span in spans:
        value = span.text.strip()
        if len(value) < _MIN_LENGTH or not _distinctive(value):
            continue
        if value in targets and span.entity == PERSON:
            entity, _, link = targets[value]
            targets[value] = (entity, max(span.score, 0.8), link)
        elif value not in targets:
            targets[value] = (span.entity, span.score, span.link)
    return targets


def propagate(text: str, spans: list[Span]) -> list[Span]:
    """Return ``spans`` plus every further occurrence of their values in ``text``.

    ``spans`` must be sorted by start and must not overlap; so is the result.
    """
    if not spans:
        return spans
    targets = _targets(spans)
    if not targets:
        return spans
    values = sorted(targets, key=len, reverse=True)[:_MAX_VALUES]
    pattern = re.compile(
        # Not inside a longer token: "0.0.0.0" is not in "1.0.0.0.0.8.b".
        r"(?<!\w)(?<!\w\.)(?:" + "|".join(re.escape(value) for value in values) + r")(?!\w)(?!\.\w)"
    )
    # Spans that a detector found on its own ("Jane", "Doe") still refer to the
    # full name when that name is the only one they are part of.
    result = [
        replace(span, link=targets[span.text][2])
        if span.entity == PERSON
        and not span.link
        and span.text in targets
        and targets[span.text][2]
        and targets[span.text][2] != span.text
        else span
        for span in spans
    ]
    starts = [span.start for span in result]
    for match in pattern.finditer(text):
        start, end = match.span()
        index = bisect_right(starts, start)
        if index > 0 and result[index - 1].end > start:
            continue
        if index < len(result) and result[index].start < end:
            continue
        value = match.group()
        entity, score, link = targets[value]
        span = Span(start, end, entity, value, score, PROPAGATED, link)
        starts.insert(index, start)
        result.insert(index, span)
    return result
