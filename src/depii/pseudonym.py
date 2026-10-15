"""Reversible pseudonyms for sending text to an AI and mapping the answer back.

    >>> import depii
    >>> p = depii.Pseudonymizer()
    >>> p.mask("Aryan asked Ravan to email aryan@example.com")
    'Person A asked Person B to email Email A'
    >>> p.unmask("Person A should wait for Person B's reply.")
    "Aryan should wait for Ravan's reply."

The table that links "Person A" to "Aryan" stays with the caller. Never send
it to the AI: it holds the real values, and sending it undoes the masking.
"""

from __future__ import annotations

import json
import re
import threading
from bisect import bisect_right
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any

from . import types as t
from .engine import Redactor
from .structured import entity_for_key

# The word each entity type is called by in a label: "Person A", "Email B".
_NOUNS: dict[str, str] = {
    t.PERSON: "Person",
    t.EMAIL: "Email",
    t.PHONE: "Phone",
    t.LOCATION: "Address",
    t.ORGANIZATION: "Company",
    t.CREDIT_CARD: "Card",
    t.IBAN: "Bank account",
    "BANK_ACCOUNT": "Bank account",
    t.BIC: "Bank code",
    t.IP_ADDRESS: "IP address",
    t.MAC_ADDRESS: "Device address",
    t.URL: "Link",
    t.IMEI: "Device",
    t.VIN: "Vehicle",
    t.GEO_COORDINATES: "Coordinates",
    t.CRYPTO_WALLET: "Wallet",
    t.DATE_OF_BIRTH: "Date of birth",
    t.SECRET: "Secret",
    t.PASSPORT: "Passport",
    t.USERNAME: "Username",
    "AGE": "Age",
    "GENDER": "Gender",
    "OCCUPATION": "Occupation",
    "CITY": "City",
    "NATIONAL_ID": "ID number",
    "TAX_ID": "Tax ID",
    "DRIVING_LICENCE": "Licence",
}

_LOCALE_PREFIX = re.compile(r"^[A-Z]{2}_")


def noun_for(entity: str) -> str:
    """The label word for an entity type: "PERSON" -> "Person", "BR_CPF" -> "CPF"."""
    if entity in _NOUNS:
        return _NOUNS[entity]
    words = _LOCALE_PREFIX.sub("", entity).split("_")
    # Short words are acronyms ("CPF", "NHS", "UPI"); longer ones are words.
    shown = [w if len(w) <= 4 else w.lower() for w in words]
    shown[0] = shown[0][0].upper() + shown[0][1:]
    return " ".join(shown)


def _suffix(number: int) -> str:
    """0 -> "A", 25 -> "Z", 26 -> "AA", 27 -> "AB"."""
    letters = ""
    number += 1
    while number:
        number, remainder = divmod(number - 1, 26)
        letters = chr(65 + remainder) + letters
    return letters


def _canonical(value: str) -> str:
    """The form under which equal values share a label.

    "Aryan" and "ARYAN " match; so do "98765 43210" and "98765-43210".
    """
    folded = " ".join(value.split()).casefold()
    digits = "".join(ch for ch in folded if ch.isdigit())
    if len(digits) >= 5 and not any(ch.isalpha() for ch in folded):
        return digits
    return folded


# Describes the labels without quoting real ones, so that the instructions
# themselves never contain a label that could collide with the table.
INSTRUCTIONS = (
    "Some private details in this text have been replaced with placeholders: a "
    'word such as "Person", "Email", "Phone" or "Address" followed by a space and '
    "one to three capital letters. Keep every placeholder exactly as written, "
    "letters included, and write each one out in full every time you use it, "
    "even when you refer to several together. Do not guess or invent the real "
    "values behind them."
)


class Pseudonymizer:
    """Mask personal data with readable labels and map them back afterwards.

    Use one per conversation, so the same person keeps the same label in
    every message. Safe to share between threads.

    ``redactor`` decides what counts as personal data; the default is a
    ``Redactor()`` with every country pack and contextual detection.
    """

    instructions = INSTRUCTIONS

    def __init__(self, redactor: Redactor | None = None) -> None:
        self.redactor = redactor if redactor is not None else Redactor()
        self._lock = threading.Lock()
        self._by_key: dict[str, str] = {}  # canonical value -> label
        self._by_label: dict[str, tuple[str, str]] = {}  # label -> (entity, value)
        self._next: dict[str, int] = {}  # noun -> next suffix number
        self._reserved: set[str] = set()  # labels found in input text
        self._pattern: re.Pattern[str] | None = None  # labels in the table
        self._shape: re.Pattern[str] | None = None  # any label-shaped text

    # ------------------------------------------------------------- the table

    @property
    def table(self) -> dict[str, str]:
        """A copy of the table: label -> original value."""
        with self._lock:
            return {label: value for label, (_, value) in self._by_label.items()}

    def __len__(self) -> int:
        return len(self._by_label)

    def __repr__(self) -> str:
        return f"Pseudonymizer({len(self)} values)"

    def label_for(self, value: str, entity: str) -> str:
        """The label for ``value``, creating one if it is new."""
        key = _canonical(value)
        with self._lock:
            label = self._by_key.get(key)
            if label is None:
                noun = noun_for(entity)
                while True:
                    number = self._next.get(noun, 0)
                    self._next[noun] = number + 1
                    label = f"{noun} {_suffix(number)}"
                    # Never reuse a label that already appears in the user's text.
                    if label not in self._reserved and label not in self._by_label:
                        break
                self._by_key[key] = label
                self._by_label[label] = (entity, value)
                self._pattern = self._shape = None
            return label

    # --------------------------------------------------------------- masking

    def mask(self, text: str) -> str:
        """Replace the personal data in ``text`` with labels.

        Values already in the table are masked wherever they appear, in any
        case, even where the detectors alone would miss them: once "Aryan" is
        Person A, so is a later "ARYAN", and "Jane" after "Jane Doe".
        """
        self._reserve_labels_in(text)
        shape = self._shapes()
        known = self._known_values()
        found: list[tuple[int, int, str]] = []  # (start, end, label)
        # Labels already in the text (an earlier reply sent back, say) are left
        # alone, and so is anything a detector found inside or across one.
        labelled = [match.span() for match in shape.finditer(text)]
        for span in self.redactor.scan(text):
            if any(span.start < end and start < span.end for start, end in labelled):
                continue
            value = span.link or span.text
            label = known.get(_canonical(value)) or known.get(_canonical(span.text))
            found.append((span.start, span.end, label or self.label_for(value, span.entity)))
        found = self._add_known_mentions(text, found, known)
        pieces: list[str] = []
        position = 0
        for start, end, label in found:
            pieces.append(text[position:start])
            pieces.append(label)
            position = end
        pieces.append(text[position:])
        return "".join(pieces)

    def _known_values(self) -> dict[str, str]:
        """canonical value -> label, including the parts of known full names."""
        # Imported here: the name lists load lazily and import this package.
        from .context import _name_parts

        with self._lock:
            entries = list(self._by_label.items())
        known: dict[str, str] = {}
        owners: dict[str, set[str]] = {}
        for label, (entity, value) in entries:
            known.setdefault(_canonical(value), label)
            if entity == t.PERSON and " " in value.strip():
                for part in _name_parts(value):
                    owners.setdefault(_canonical(part), set()).add(label)
        for part, labels in owners.items():
            # A surname shared by two people is not linked to either.
            if part not in known and len(labels) == 1:
                known[part] = next(iter(labels))
        return known

    def _add_known_mentions(
        self, text: str, found: list[tuple[int, int, str]], known: dict[str, str]
    ) -> list[tuple[int, int, str]]:
        """Add every further mention of a known value that no detector found."""
        words = [value for value in known if len(value) >= 3 and not value.isdigit()]
        if not words:
            return found
        pattern = re.compile(
            r"(?<!\w)(?:"
            + "|".join(
                r"\s+".join(map(re.escape, v.split())) for v in sorted(words, key=len, reverse=True)
            )
            + r")(?!\w)",
            re.IGNORECASE,
        )
        result = sorted(found)
        starts = [start for start, _, _ in result]
        for match in pattern.finditer(text):
            start, end = match.span()
            index = bisect_right(starts, start)
            if index > 0 and result[index - 1][1] > start:
                continue
            if index < len(result) and result[index][0] < end:
                continue
            label = known.get(_canonical(match.group()))
            if label is not None:
                starts.insert(index, start)
                result.insert(index, (start, end, label))
        return result

    def mask_obj(self, obj: Any) -> Any:
        """Mask every string in nested dicts, lists and tuples; returns a copy.

        A field whose name says what it holds ("phone", "userEmail") is masked
        whole, numbers included.
        """
        return self._walk(obj, hint=None)

    def mask_messages(self, messages: Iterable[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Mask a list of chat messages; returns new messages.

        Handles string content, lists of content blocks (``text``), tool-use
        inputs, tool results and JSON tool-call arguments. Roles, types, ids
        and tool names are left as they are.
        """
        return [self._message(message) for message in messages]

    def _message(self, message: Mapping[str, Any]) -> dict[str, Any]:
        out = dict(message)
        if "content" in out:
            out["content"] = self._content(out["content"])
        if isinstance(out.get("tool_calls"), list):
            out["tool_calls"] = [self._tool_call(call) for call in out["tool_calls"]]
        return out

    def _content(self, content: Any) -> Any:
        if isinstance(content, str):
            return self.mask(content)
        if isinstance(content, list):
            return [self._block(block) for block in content]
        return content

    def _block(self, block: Any) -> Any:
        if isinstance(block, str):
            return self.mask(block)
        if not isinstance(block, Mapping):
            return block
        out = dict(block)
        if isinstance(out.get("text"), str):
            out["text"] = self.mask(out["text"])
        if "input" in out:
            out["input"] = self.mask_obj(out["input"])
        if "content" in out:
            out["content"] = self._content(out["content"])
        return out

    def _tool_call(self, call: Any) -> Any:
        if not isinstance(call, Mapping):
            return call
        out = dict(call)
        function = out.get("function")
        if isinstance(function, Mapping) and isinstance(function.get("arguments"), str):
            out["function"] = {**function, "arguments": self.mask(function["arguments"])}
        return out

    def _walk(self, value: Any, hint: str | None) -> Any:
        if isinstance(value, Mapping):
            return {
                name: self._walk(item, entity_for_key(name) or hint) for name, item in value.items()
            }
        if isinstance(value, list):
            return [self._walk(item, hint) for item in value]
        if isinstance(value, tuple):
            return tuple(self._walk(item, hint) for item in value)
        if isinstance(value, bool) or value is None:
            return value
        if hint is not None and isinstance(value, (str, int, float)) and str(value).strip():
            text = str(value)
            if isinstance(value, str) and self._shapes().fullmatch(text):
                return value
            return self.label_for(text, hint)
        if isinstance(value, str):
            return self.mask(value)
        return value

    def _reserve_labels_in(self, text: str) -> None:
        found = {self._normalise(match) for match in self._shapes().finditer(text)}
        new = found - self._reserved - set(self._by_label)
        if new:
            with self._lock:
                self._reserved |= new

    # ------------------------------------------------------------- unmasking

    def unmask(self, text: str) -> str:
        """Put the original values back in place of their labels."""
        return self._label_pattern().sub(self._restore, text)

    def unmask_obj(self, obj: Any) -> Any:
        """Unmask every string, keys included, in nested dicts, lists and tuples."""
        if isinstance(obj, Mapping):
            return {self.unmask_obj(k): self.unmask_obj(v) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self.unmask_obj(item) for item in obj]
        if isinstance(obj, tuple):
            return tuple(self.unmask_obj(item) for item in obj)
        if isinstance(obj, str):
            return self.unmask(obj)
        return obj

    def unmask_stream(self, chunks: Iterable[str]) -> Iterator[str]:
        """Unmask a reply that arrives in pieces, as from a streaming API.

        Text is held back only while it could still be part of a label, so a
        label split across pieces ("Pers" + "on A") is restored whole.
        """
        hold = self._longest_label() + 8
        buffer = ""
        for chunk in chunks:
            buffer += chunk
            cut = len(buffer) - hold
            if cut <= 0:
                continue
            for match in self._shapes().finditer(buffer, max(0, cut - hold)):
                if match.start() < cut < match.end():
                    cut = match.start()
                    break
            if cut > 0:
                yield self.unmask(buffer[:cut])
                buffer = buffer[cut:]
        if buffer:
            yield self.unmask(buffer)

    def unknown_labels(self, text: str) -> list[str]:
        """Labels in ``text`` that are not in the table, e.g. ones the AI invented."""
        with self._lock:
            known = set(self._by_label)
        seen: list[str] = []
        for match in self._shapes().finditer(text):
            label = self._normalise(match)
            if label not in known and label not in seen:
                seen.append(label)
        return seen

    def _restore(self, match: re.Match[str]) -> str:
        label = self._normalise(match)
        entry = self._by_label.get(label)
        if entry is None:
            return match.group()
        value = entry[1]
        opening, closing = match.group("open") or "", match.group("close") or ""
        # Brackets the AI put around the label go; a lone one stays.
        if opening and closing and _PAIRS.get(opening) == closing:
            return value
        return opening + value + closing

    def _label_pattern(self) -> re.Pattern[str]:
        with self._lock:
            if self._pattern is None:
                nouns = self._nouns()
                self._pattern = _compile(nouns) if nouns else re.compile(r"(?!x)x")
            return self._pattern

    def _nouns(self) -> set[str]:
        return {label.rsplit(" ", 1)[0] for label in self._by_label}

    def _shapes(self) -> re.Pattern[str]:
        with self._lock:
            if self._shape is None:
                self._shape = _compile({*_NOUNS.values(), *self._nouns()})
            return self._shape

    def _normalise(self, match: re.Match[str]) -> str:
        """The canonical label for a match: "PERSON-A" -> "Person A"."""
        noun_text = re.sub(r"[ _-]", " ", match.group("noun")).lower()
        suffix = match.group("suffix")
        for noun in (*self._nouns(), *_NOUNS.values()):
            if noun.lower() == noun_text:
                return f"{noun} {suffix}"
        return f"{noun_text.capitalize()} {suffix}"

    def _longest_label(self) -> int:
        with self._lock:
            return max((len(label) for label in self._by_label), default=12)

    # ---------------------------------------------------------------- saving

    def to_json(self) -> str:
        """The table as JSON. It holds the real values: store it like the original data."""
        with self._lock:
            data = {
                "version": 1,
                "entries": [
                    {"label": label, "entity": entity, "value": value}
                    for label, (entity, value) in self._by_label.items()
                ],
                "next": dict(self._next),
                "reserved": sorted(self._reserved),
            }
        return json.dumps(data, ensure_ascii=False, indent=2)

    @classmethod
    def from_json(cls, data: str, redactor: Redactor | None = None) -> Pseudonymizer:
        """Rebuild a pseudonymizer from :meth:`to_json` output."""
        loaded = json.loads(data)
        if loaded.get("version") != 1:
            raise ValueError(f"unsupported table version: {loaded.get('version')!r}")
        pseudonymizer = cls(redactor)
        for entry in loaded["entries"]:
            label, entity, value = entry["label"], entry["entity"], entry["value"]
            pseudonymizer._by_label[label] = (entity, value)
            pseudonymizer._by_key.setdefault(_canonical(value), label)
        pseudonymizer._next = {str(k): int(v) for k, v in loaded.get("next", {}).items()}
        pseudonymizer._reserved = set(loaded.get("reserved", ()))
        return pseudonymizer

    def save(self, path: str | Path) -> None:
        """Write the table to ``path`` as JSON. The file holds the real values."""
        Path(path).write_text(self.to_json(), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path, redactor: Redactor | None = None) -> Pseudonymizer:
        """Read a table written by :meth:`save`."""
        return cls.from_json(Path(path).read_text(encoding="utf-8"), redactor)


# ------------------------------------------------------------ label matching

_PAIRS = {"[": "]", "{": "}"}


def _noun_pattern(noun: str) -> str:
    """A noun with flexible joins: "IP address" also matches "IP-address", "IP_ADDRESS"."""
    return r"[ _-]".join(re.escape(word) for word in noun.split(" "))


def _compile(nouns: Iterable[str]) -> re.Pattern[str]:
    alternatives = "|".join(_noun_pattern(n) for n in sorted(nouns, key=len, reverse=True))
    # "[Person A]" and "{Person A}" are decoration the AI added around a label
    # and go. "**Person A**" (bold) and "(Person A)" are the AI's own
    # formatting and punctuation, so they stay: "**Aryan**".
    return re.compile(
        r"(?P<open>[\[{])?"
        rf"(?<![A-Za-z0-9])(?P<noun>(?i:{alternatives}))[ _-](?P<suffix>[A-Z]{{1,3}})"
        r"(?![A-Za-z0-9])(?P<close>[\]}])?"
    )
