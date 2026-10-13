"""Core data types and entity names.

Entity names are part of the public contract: user policies are keyed by them,
so they must not be renamed once released.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

# Global entities
EMAIL = "EMAIL"
PHONE = "PHONE"
CREDIT_CARD = "CREDIT_CARD"
IBAN = "IBAN"
BIC = "BIC"
IP_ADDRESS = "IP_ADDRESS"
MAC_ADDRESS = "MAC_ADDRESS"
URL = "URL"
IMEI = "IMEI"
VIN = "VIN"
GEO_COORDINATES = "GEO_COORDINATES"
CRYPTO_WALLET = "CRYPTO_WALLET"
DATE_OF_BIRTH = "DATE_OF_BIRTH"
SECRET = "SECRET"  # noqa: S105
PASSPORT = "PASSPORT"

# Produced by the optional NER detector
PERSON = "PERSON"
LOCATION = "LOCATION"
ORGANIZATION = "ORGANIZATION"


@dataclass(frozen=True, slots=True)
class Span:
    """One detected piece of PII. Offsets refer to the original input text."""

    start: int
    end: int
    entity: str
    # Raw PII. Kept out of repr so spans can be logged without leaking it.
    text: str = field(repr=False)
    score: float
    detector: str = ""

    def overlaps(self, other: Span) -> bool:
        return self.start < other.end and other.start < self.end


@dataclass(frozen=True, slots=True)
class Result:
    """Outcome of a redaction: the redacted text and what was found."""

    text: str
    spans: tuple[Span, ...] = ()

    @property
    def stats(self) -> dict[str, int]:
        """Number of redactions per entity type."""
        return dict(Counter(span.entity for span in self.spans))

    def __bool__(self) -> bool:
        return bool(self.spans)
