"""Quasi-identifiers: details that identify a person only in combination.

"42", "woman", "nurse", "Pune" and "Apollo Hospital" are not personal data
on their own. Together, in one sentence about one person, they can point to
a single individual. This pass finds such details and redacts them only
when enough different kinds appear close together.

Kinds counted: age, gender (next to an age or after a label), occupation,
employer, city, and the postcodes, birth dates and addresses that the main
detectors already redact.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections.abc import Callable, Iterator
from functools import cache
from importlib import resources

from .types import DATE_OF_BIRTH, LOCATION, ORGANIZATION, Span

AGE = "AGE"
GENDER = "GENDER"
OCCUPATION = "OCCUPATION"
CITY = "CITY"
QUASI_ENTITIES = frozenset({AGE, GENDER, OCCUPATION, CITY, ORGANIZATION})

QUASI = "quasi"
SCORE = 0.7
DEFAULT_THRESHOLD = 3
_WINDOW = 300  # characters: roughly two or three sentences about one subject

# Already-redacted entity types that count as one kind each.
_ANCHOR_KINDS = {
    DATE_OF_BIRTH: "DOB",
    LOCATION: "ADDRESS",
    "US_ZIP": "POSTCODE",
    "IN_PIN_CODE": "POSTCODE",
    "GB_POSTCODE": "POSTCODE",
    "CA_POSTAL_CODE": "POSTCODE",
}

_AGE = re.compile(
    r"\b(?:(?P<n1>\d{1,3})[- ](?:years?|yrs?)[- ]old"
    r"|aged?[ :]{1,3}(?P<n2>\d{1,3})"
    r"|(?P<n3>\d{1,3})\s?(?:y/?o|yrs?\.? old))\b",
    re.IGNORECASE,
)
_GENDER = re.compile(
    r"\b(?:male|female|man|woman|boy|girl|transgender|non-binary|nonbinary)\b", re.IGNORECASE
)
_ORG_SUFFIX = (
    r"Ltd|Limited|Inc|LLC|LLP|PLC|GmbH|AG|S\.?A|SAS|SARL|BV|NV|Pvt\.? Ltd|Private Limited"
    r"|Corp|Corporation|Company|Co|Group|Holdings|Bank|University|Hospital|Hospitals|Clinic"
    r"|School|College|Institute|Foundation|Trust"
)
_ORGANISATION = re.compile(
    rf"\b(?:[A-Z][\w&'.-]{{0,30}}\s){{1,4}}(?:{_ORG_SUFFIX})\b"
    r"|\b(?:University|Bank|Institute|College) of (?:[A-Z][\w'-]{1,30}\s?){1,3}"
)
# "Age: 42", "Gender = F", "City: Pune": a label, a separator, a short value.
# "works at" and "works as" introduce a value without a separator.
_QUASI_LABEL = re.compile(
    r"\b(?:(?P<label>age|gender|sex|occupation|profession|designation|job title|"
    r"city|town|place of birth|employer)\s{0,3}[:=]|(?P<phrase>works at|works as))"
    r"\s{0,3}(?:an?\s|the\s)?(?P<value>[^\n,;|.]{1,40})",
    re.IGNORECASE,
)
_GENDER_VALUES = frozenset(
    {"m", "f", "x", "male", "female", "man", "woman", "other", "non-binary", "nonbinary",
     "transgender", "trans"}
)  # fmt: skip
_LABEL_KIND = {
    "age": AGE,
    "gender": GENDER,
    "sex": GENDER,
    "occupation": OCCUPATION,
    "profession": OCCUPATION,
    "designation": OCCUPATION,
    "job title": OCCUPATION,
    "job": OCCUPATION,
    "works as": OCCUPATION,
    "city": CITY,
    "town": CITY,
    "place of birth": CITY,
    "employer": ORGANIZATION,
    "works at": ORGANIZATION,
}
_WORD = re.compile(r"[^\W\d_]+(?:[-'][^\W\d_]+)*")


@cache
def _phrases(name: str) -> frozenset[str]:
    text = resources.files("depii.data").joinpath(f"{name}.txt").read_text(encoding="utf-8")
    return frozenset(
        line.strip().lower() for line in text.splitlines() if line.strip() and line[0] != "#"
    )


def _lookup(text: str, start: int, end: int, phrases: frozenset[str], kind: str) -> Iterator[Span]:
    """Phrases of up to three words from ``phrases`` within ``text[start:end]``."""
    words = list(_WORD.finditer(text, start, end))
    index = 0
    while index < len(words):
        for size in (3, 2, 1):
            if index + size > len(words):
                continue
            first, last = words[index], words[index + size - 1]
            phrase = " ".join(w.group().lower() for w in words[index : index + size])
            # Words of a phrase must be separated by single spaces.
            if size > 1 and text[first.start() : last.end()].lower() != phrase:
                continue
            if phrase in phrases:
                value = text[first.start() : last.end()]
                # A city is a proper noun; "nice" in prose is not Nice.
                if kind == CITY and not value[0].isupper():
                    continue
                yield Span(first.start(), last.end(), kind, value, SCORE, QUASI)
                index += size - 1
                break
        index += 1


def _windows(text: str) -> list[tuple[int, int]]:
    """Split ``text`` into windows of about ``_WINDOW`` characters at sentence ends."""
    windows: list[tuple[int, int]] = []
    start = 0
    for match in re.finditer(r"\n|[.!?](?=\s)", text):
        end = match.end()
        if text[match.start()] == "\n" or end - start >= _WINDOW:
            windows.append((start, end))
            start = end
    if start < len(text):
        windows.append((start, len(text)))
    return windows


def _anchors(text: str) -> list[Span]:
    spans: list[Span] = []
    for match in _AGE.finditer(text):
        number = match.group("n1") or match.group("n2") or match.group("n3")
        if number is None or not 0 < int(number) <= 120:
            continue
        # "aged 42" and "Age: 42" keep the word visible; "42-year-old" goes whole.
        start, end = match.span("n2") if match.group("n2") else match.span()
        spans.append(Span(start, end, AGE, text[start:end], SCORE, QUASI))
    for match in _ORGANISATION.finditer(text):
        spans.append(Span(*match.span(), ORGANIZATION, match.group(), SCORE, QUASI))
    for match in _QUASI_LABEL.finditer(text):
        label = match.group("label") or match.group("phrase")
        kind = _LABEL_KIND[re.sub(r"\s+", " ", label.lower())]
        # "works as a nurse at Apollo Hospital": the occupation ends at "at".
        value = _CLAUSE_BREAK.split(match.group("value"), maxsplit=1)[0].strip()
        if not _plausible(kind, value):
            continue
        start = match.start("value") + match.group("value").find(value)
        spans.append(Span(start, start + len(value), kind, value, SCORE, QUASI))
    return spans


_CLAUSE_BREAK = re.compile(r"\s(?:at|in|for|with|from|since|as|and|who|which)\s", re.IGNORECASE)


def _plausible(kind: str, value: str) -> bool:
    if not value or not any(ch.isalnum() for ch in value):
        return False
    if kind == AGE:
        return value.isdigit() and 0 < int(value) <= 120
    if kind == GENDER:
        return value.lower() in _GENDER_VALUES
    if kind in (CITY, ORGANIZATION):
        return value[0].isupper()
    return len(value.split()) <= 4


def combine(
    text: str,
    chosen: list[Span],
    threshold: int = DEFAULT_THRESHOLD,
    wanted: Callable[[str], bool] = lambda entity: True,
) -> list[Span]:
    """Add the quasi-identifiers of every window that holds at least ``threshold`` kinds.

    ``chosen`` must be sorted and free of overlaps; so is the result. Only
    entity types for which ``wanted`` is true are added, though all count.
    """
    anchors = _anchors(text)
    anchored = [span for span in chosen if span.entity in _ANCHOR_KINDS]
    if not anchors and not anchored:
        return chosen
    cities, jobs = _phrases("cities"), _phrases("occupations")
    result = list(chosen)
    starts = [span.start for span in result]

    def free(span: Span) -> bool:
        index = bisect_right(starts, span.start)
        if index > 0 and result[index - 1].end > span.start:
            return False
        return not (index < len(result) and result[index].start < span.end)

    for start, end in _windows(text):
        local = [s for s in anchors if start <= s.start < end]
        kinds = {_ANCHOR_KINDS[s.entity] for s in anchored if start <= s.start < end}
        if not local and not kinds:
            continue
        local += list(_lookup(text, start, end, cities, CITY))
        local += list(_lookup(text, start, end, jobs, OCCUPATION))
        ages = [s for s in local if s.entity == AGE]
        for match in _GENDER.finditer(text, start, end):
            # "woman" counts next to an age ("a 42-year-old woman"), not anywhere.
            if any(
                abs(match.start() - age.end) <= 20 or abs(age.start - match.end()) <= 20
                for age in ages
            ):
                local.append(Span(*match.span(), GENDER, match.group(), SCORE, QUASI))
        kinds |= {s.entity for s in local}
        if len(kinds) < threshold:
            continue
        for span in sorted(local, key=lambda s: (s.start, -(s.end - s.start))):
            if wanted(span.entity) and free(span):
                index = bisect_right(starts, span.start)
                starts.insert(index, span.start)
                result.insert(index, span)
    return result
