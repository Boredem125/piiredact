"""Operators decide what a detected value is replaced with."""

from __future__ import annotations

import hashlib
import hmac
import re
import threading
from typing import Protocol, runtime_checkable


@runtime_checkable
class Operator(Protocol):
    def apply(self, value: str, entity: str) -> str: ...


class Replace:
    """Replace the value with a label. The default operator."""

    def __init__(self, template: str = "[{entity}]") -> None:
        self.template = template

    def apply(self, value: str, entity: str) -> str:
        return self.template.format(entity=entity)


class Mask:
    """Mask letters and digits, keeping separators so the shape stays readable.

    ``Mask(keep_last=4)`` turns ``4111 1111 1111 1111`` into ``**** **** **** 1111``.
    """

    def __init__(self, char: str = "*", keep_first: int = 0, keep_last: int = 0) -> None:
        if len(char) != 1:
            raise ValueError("char must be a single character")
        if keep_first < 0 or keep_last < 0:
            raise ValueError("keep_first and keep_last must not be negative")
        self.char = char
        self.keep_first = keep_first
        self.keep_last = keep_last

    def apply(self, value: str, entity: str) -> str:
        total = sum(ch.isalnum() for ch in value)
        # Never reveal more than half of the value, whatever the settings say.
        budget = total // 2
        first = min(self.keep_first, budget)
        last = min(self.keep_last, budget - first)
        out: list[str] = []
        seen = 0
        for ch in value:
            if not ch.isalnum():
                out.append(ch)
                continue
            seen += 1
            out.append(ch if seen <= first or seen > total - last else self.char)
        return "".join(out)


class Hash:
    """Replace the value with a keyed hash, so equal values stay linkable.

    The key is mandatory. An unkeyed hash of a phone number or national ID is
    reversible by enumerating every possible value, so it is not offered.
    Keep the key secret and out of the redacted data set.
    """

    def __init__(
        self,
        key: str | bytes,
        *,
        length: int = 16,
        template: str = "[{entity}:{digest}]",
        canonicalize: bool = True,
    ) -> None:
        raw = key.encode() if isinstance(key, str) else bytes(key)
        if len(raw) < 16:
            raise ValueError("key must be at least 16 bytes")
        if not 8 <= length <= 64:
            raise ValueError("length must be between 8 and 64 hex characters")
        self._key = raw
        self.length = length
        self.template = template
        self.canonicalize = canonicalize

    def apply(self, value: str, entity: str) -> str:
        if self.canonicalize:
            # "Jane@Example.com" and "jane@example.com " should link.
            value = "".join(value.split()).casefold()
        message = f"{entity}\x00{value}".encode()
        digest = hmac.new(self._key, message, hashlib.sha256).hexdigest()[: self.length]
        return self.template.format(entity=entity, digest=digest)


class Vault:
    """Two-way map between tokens and original values, used by ``Tokenize``.

    The vault holds raw PII. Treat it like the original data: do not log it,
    and store it only where the unredacted data would be allowed to live.
    """

    _TOKEN = re.compile(r"\[[A-Z][A-Z0-9_]*_\d+\]")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._by_value: dict[tuple[str, str], str] = {}
        self._by_token: dict[str, str] = {}
        self._counters: dict[str, int] = {}

    def token_for(self, value: str, entity: str) -> str:
        with self._lock:
            token = self._by_value.get((entity, value))
            if token is None:
                number = self._counters.get(entity, 0) + 1
                self._counters[entity] = number
                token = f"[{entity}_{number}]"
                self._by_value[(entity, value)] = token
                self._by_token[token] = value
            return token

    def restore(self, text: str) -> str:
        """Put original values back in place of their tokens."""
        with self._lock:
            mapping = dict(self._by_token)
        return self._TOKEN.sub(lambda match: mapping.get(match.group(), match.group()), text)

    def __len__(self) -> int:
        return len(self._by_token)

    def __repr__(self) -> str:
        return f"Vault({len(self)} values)"


class Tokenize:
    """Replace each distinct value with a numbered token that a vault can reverse."""

    def __init__(self, vault: Vault | None = None) -> None:
        self.vault = vault if vault is not None else Vault()

    def apply(self, value: str, entity: str) -> str:
        return self.vault.token_for(value, entity)


class Drop:
    """Remove the value entirely."""

    def apply(self, value: str, entity: str) -> str:
        return ""


class Keep:
    """Leave the value untouched. Use in a policy to exempt one entity type."""

    def apply(self, value: str, entity: str) -> str:
        return value
