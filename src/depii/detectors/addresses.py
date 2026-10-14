"""Street addresses and post boxes.

A house number next to a street word ("221B Baker Street", "42 MG Road",
"Hauptstraße 5", "Calle Mayor 3", "12 rue de Rivoli") is specific enough
to redact on its own. Following city names after commas are included;
postcodes are left to their own detectors, which run alongside.
"""

from __future__ import annotations

import re
from typing import Any

from ..types import LOCATION
from .pattern import PatternDetector

# Street words that follow the street name, as in "Baker Street", "MG Road".
_SUFFIX_WORDS = (
    "Street St Road Rd Avenue Ave Lane Ln Drive Dr Boulevard Blvd Court Ct Place Pl Way "
    "Terrace Close Crescent Cres Square Sq Highway Hwy Parkway Pkwy Circle Cir Row Mews "
    "Gardens Grove Walk Alley Expressway Freeway Pike Trail Plaza "
    # South Asia
    "Marg Nagar Path Gali Chowk Colony Layout Cross Main Sector Enclave Vihar Bagh Ganj "
    "Peth Puram Palya Halli Salai Veedhi"
).split()
_SUFFIX = "|".join(_SUFFIX_WORDS)
# Suffixes that are also everyday words ("Step 2 Click Close"). An address
# ending in one needs a context word or a following town to count.
_AMBIGUOUS_SUFFIXES = frozenset(
    "Close Way Row Walk Cross Main Path Place Pl Circle Square Grove Gardens Trail Plaza "
    "Court Ct Sector Layout Pike".split()
)
# Words that start an instruction or a heading rather than a street name.
_NOT_STREET = frozenset(
    "Click Press Select Choose Open Step Use Add Remove Go Tap Enter Type Run Page "
    "Chapter Section Figure Table Version Item Option Level Phase Part".split()
)
# Street words that come first, as in "Rue de Rivoli", "Calle Mayor", "Via Roma".
_PREFIX = (
    r"Rue|Avenue|Boulevard|Bd|Allée|Chemin|Impasse|Quai|Calle|Avenida|Av\.|Paseo|Plaza"
    r"|Camino|Carrera|Rua|Travessa|Alameda|Via|Viale|Piazza|Corso|Largo|Strada|Ulica|ul\."
)
# Words that end a street name in Germanic and Nordic languages.
_COMPOUND = (
    r"straße|strasse|str\.|weg|platz|allee|gasse|ring|damm|ufer|straat|laan|plein|gracht"
    r"|kade|gatan|vägen|vej|gade|veien|gata|katu|tie"
)

_NUMBER = r"(?:#\s?|No\.?\s?)?\d{1,5}[A-Za-z]?(?:[/-]\d{1,5}[A-Za-z]?)?"
_UNIT = (
    r"(?:(?:Flat|Apt|Apartment|Unit|Suite|House|H\.?\s?No\.?|Plot|Door|Room)"
    r"\s*(?:No\.?\s*)?[\w/-]{1,8},?\s+)?"
)
_NAME_WORD = r"[A-Z0-9][\w'.-]{0,30}"
# Further comma-separated places: ", Leeds", ", Bandra West, Mumbai", ", 10115 Berlin".
_TAIL = r"(?:,\s{0,2}(?:\d{4,6}\s)?[A-Z][a-z'-]{1,30}(?:\s[A-Z][a-z'-]{1,30}){0,2}){0,3}"


def _address_score(value: str) -> float:
    words = value.replace(",", " ").split()
    if any(word in _NOT_STREET for word in words[1:3]):
        return 0.0
    suffix = next((w.rstrip(".") for w in words if w.rstrip(".") in _SUFFIX_WORDS), "")
    if suffix in _AMBIGUOUS_SUFFIXES and "," not in value:
        return 0.45  # needs a context word to reach the threshold
    return 0.85


_START = r"(?<![\w#/-])"
_END = r"(?![\w-])"

_CONTEXT = ("address", "addr", "lives", "resides", "located", "deliver", "ship to", "send to")

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        LOCATION,
        _START
        + _UNIT
        + _NUMBER
        + rf",?\s{{1,2}}(?:{_NAME_WORD}\s){{1,4}}(?:{_SUFFIX})\b\.?"
        + _TAIL,
        name="address_number_first",
        scorer=_address_score,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        LOCATION,
        _START
        + rf"(?:(?:{_PREFIX})\s(?:(?:de|del|de la|du|des|da|do|dos|di|della)\s)?"
        + r"[A-Z][\w'-]{1,30}(?:\s[A-Z][\w'-]{1,30}){0,3}"
        + rf"|[A-ZÄÖÜÅØÆ][\w-]{{1,40}}(?:{_COMPOUND}))\s{{1,2}}\d{{1,5}}[a-zA-Z]?"
        + _END
        + _TAIL,
        name="address_street_first",
        score=0.85,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        LOCATION,
        _START
        + r"\d{1,5}(?:\s?(?:bis|ter))?,?\s(?:rue|avenue|boulevard|bd|allée|chemin|impasse|quai)"
        + r"\s(?:(?:de|du|des|de la|d')\s?)?[A-Z][\w'-]{1,30}(?:\s[A-Z][\w'-]{1,30}){0,3}"
        + _TAIL,
        name="address_french",
        score=0.85,
        flags=re.UNICODE,
        context=_CONTEXT,
        needs_digit=True,
    ),
    PatternDetector(
        LOCATION,
        r"(?<!\w)(?:P\.?\s?O\.?\s?Box|Post\s+Office\s+Box|Postfach|Apartado|Caixa\s+Postal)"
        r"\s{1,2}\d{1,6}(?!\d)",
        name="po_box",
        score=0.9,
        flags=re.IGNORECASE,
        needs_digit=True,
    ),
)
