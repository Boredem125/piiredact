"""Detectors for identifiers that are not tied to one country.

Patterns follow two rules:

* Every quantifier is bounded and no quantified group can match the same
  text in more than a handful of ways, so matching time is linear in input
  length.
* A pattern matches one fixed shape. A greedy "digits and separators"
  pattern would swallow a neighbouring number, fail validation and lose
  both, so each shape gets its own detector and overlaps are resolved later.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from typing import Any

from .. import types as t
from .. import validators as v
from ..types import Span
from .pattern import PatternDetector

# Not preceded / followed by something that makes the match part of a longer token.
_L = r"(?<![\w+])(?<!\w[.-])"
_R = r"(?!\w)(?!-\w)"


def _load_phonenumbers() -> Any:
    try:
        import phonenumbers
    except ImportError:
        return None
    return phonenumbers


_phonenumbers: Any = _load_phonenumbers()

_PHONE_CONTEXT = (
    "phone", "phones", "tel", "tel.", "telephone", "mobile", "mob", "cell", "cellphone",
    "call", "fax", "whatsapp", "contact", "ph", "sms", "dial", "helpline",
    "telefon", "téléphone", "teléfono", "telefono", "móvil", "handy", "फोन", "फ़ोन", "मोबाइल",
)  # fmt: skip

_DATE_LIKE = re.compile(r"\d{1,4}[-./ ]\d{1,2}[-./ ]\d{1,4}\Z")


def _digit_count(low: int, high: int) -> Callable[[str], bool]:
    def check(value: str) -> bool:
        return low <= len(v.digits_of(value)) <= high

    return check


def _trim_international(value: str) -> str:
    """Drop trailing digit groups until the number fits E.164's 15 digits.

    The pattern allows long groups, so it can run on into a neighbouring
    number. Cutting back keeps the phone number instead of losing both.
    """
    while len(v.digits_of(value)) > 15:
        cut = max(value.rfind(" "), value.rfind("."), value.rfind("-"))
        if cut <= 0:
            return ""
        value = value[:cut]
    return value


def _trim_url(value: str) -> str:
    return value.rstrip(".,;:!?)")


def _phone_international(value: str) -> bool:
    if not 8 <= len(v.digits_of(value)) <= 15:
        return False
    if _phonenumbers is None:
        return True
    try:
        return bool(_phonenumbers.is_possible_number(_phonenumbers.parse(value, None)))
    except _phonenumbers.NumberParseException:
        return False


def _phone_nanp(value: str) -> bool:
    digits = v.digits_of(value)[-10:]
    # Area code and exchange never start with 0 or 1.
    return digits[0] not in "01" and digits[3] not in "01"


def _phone_generic(value: str) -> bool:
    return 8 <= len(v.digits_of(value)) <= 13 and not _DATE_LIKE.match(value)


def _url_score(value: str) -> float:
    rest = value.split("://", 1)[-1]
    authority = rest.split("/", 1)[0]
    if "@" in authority:
        # Embedded credentials. Scored above EMAIL, which would otherwise claim
        # "password@host" and leave the user name behind.
        return 0.99
    if "?" in rest:
        return 0.6  # query strings routinely carry identifiers and tokens
    return 0.3  # a plain link; only redacted in strict mode


def _vin_score(value: str) -> float:
    if value.isdigit() or value.isalpha():
        return 0.0
    return 0.85 if v.vin_check_digit(value) else 0.4


class IbanDetector:
    """IBAN detector that reads exactly as many characters as the country uses.

    A regex alone cannot know where the IBAN ends: ``CZ65 0800 ... 5399 PAID``
    would swallow the next word, fail the checksum and be missed.
    """

    name = "iban"
    entity = t.IBAN
    _start = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?=[ ]?[A-Z0-9])")

    def detect(self, text: str, *, strict: bool = False) -> Iterator[Span]:
        for match in self._start.finditer(text):
            needed = v._IBAN_LENGTHS.get(match.group()[:2])
            if needed is None:
                continue
            pos = match.end()
            count = 4
            limit = len(text)
            while count < needed and pos < limit:
                char = text[pos]
                if char == " " and pos + 1 < limit and text[pos + 1] != " ":
                    pos += 1
                    char = text[pos]
                if not (char.isascii() and (char.isdigit() or char.isupper())):
                    break
                count += 1
                pos += 1
            if count != needed or (pos < limit and text[pos].isalnum()):
                continue
            value = text[match.start() : pos]
            if v.iban(value):
                yield Span(match.start(), pos, t.IBAN, value, 0.95, self.name)


_MONTH = (
    r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
    r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
)
_DATE = (
    r"(?<!\w)(?:"
    r"\d{4}[-/.]\d{1,2}[-/.]\d{1,2}"
    r"|\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}"
    rf"|\d{{1,2}}(?:st|nd|rd|th)? {_MONTH},? \d{{4}}"
    rf"|{_MONTH} \d{{1,2}}(?:st|nd|rd|th)?,? \d{{4}}"
    r")(?!\w)"
)

_OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        t.EMAIL,
        r"(?<!\w)(?<!\w[.+%-])[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@"
        r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.){1,8}[A-Za-z]{2,24}(?!\w)(?!-\w)",
        score=0.95,
    ),
    # ---------------------------------------------------------------- phone
    PatternDetector(
        t.PHONE,
        r"(?<![\w+])(?<!\w[.-])\+\d{1,3}[ .-]?(?:\(\d{1,5}\)[ .-]?)?\d{1,14}(?:[ .-]\d{1,12}){0,5}" + _R,
        name="phone_international",
        score=0.85,
        trim=_trim_international,
        validator=_phone_international,
        context=_PHONE_CONTEXT,
    ),
    PatternDetector(
        t.PHONE,
        _L + r"(?:1[ .-])?(?:\(\d{3}\) ?|\d{3}[ .-])\d{3}[ .-]\d{4}" + _R,
        name="phone_nanp",
        score=0.75,
        validator=_phone_nanp,
        context=_PHONE_CONTEXT,
    ),
    PatternDetector(
        t.PHONE,
        _L + r"0?[6-9]\d{4}[ -]\d{5}" + _R,
        name="phone_in_mobile",
        score=0.7,
        context=_PHONE_CONTEXT,
    ),
    PatternDetector(
        t.PHONE,
        _L + r"0\d{1,4}(?:[ .-]\d{2,5}){1,4}" + _R,
        name="phone_trunk",
        score=0.65,
        validator=_digit_count(9, 11),
        context=_PHONE_CONTEXT,
    ),
    PatternDetector(
        t.PHONE,
        _L + r"\(\d{2,5}\)[ .-]?\d{3,5}(?:[ .-]\d{2,5}){0,2}" + _R,
        name="phone_parenthesised",
        score=0.7,
        validator=_digit_count(7, 13),
        context=_PHONE_CONTEXT,
    ),
    PatternDetector(
        t.PHONE,
        _L + r"(?:\d{2,5}(?:[ -]\d{2,5}){1,3}|\d{8,13})" + _R,
        name="phone_generic",
        score=0.45,
        validator=_phone_generic,
        context=_PHONE_CONTEXT,
        require_context=True,
    ),
    # -------------------------------------------------------------- finance
    PatternDetector(
        t.CREDIT_CARD,
        _L + r"\d{4}([ -]?)\d{4}\1\d{4}\1\d{1,7}" + _R,
        score=0.95,
        validator=v.credit_card,
    ),
    PatternDetector(
        t.CREDIT_CARD,
        _L + r"\d{4}([ -])\d{6}\1\d{4,5}" + _R,
        name="credit_card_4_6_5",
        score=0.95,
        validator=v.credit_card,
    ),
    PatternDetector(
        t.CREDIT_CARD,
        _L + r"\d{4}([ -])\d{4}\1\d{4}\1\d{4}\1\d{3}" + _R,
        name="credit_card_19",
        score=0.95,
        validator=v.credit_card,
    ),
    IbanDetector(),
    PatternDetector(
        t.BIC,
        r"(?<![A-Za-z0-9])[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?(?![A-Za-z0-9])",
        score=0.5,
        validator=v.bic,
        context=("swift", "bic", "swift code", "bic code", "swift/bic"),
        require_context=True,
    ),
    PatternDetector(
        t.CRYPTO_WALLET,
        r"(?<![A-Za-z0-9])[13][1-9A-HJ-NP-Za-km-z]{25,34}(?![A-Za-z0-9])",
        name="bitcoin_base58",
        score=0.9,
        validator=v.base58check,
    ),
    PatternDetector(
        t.CRYPTO_WALLET,
        r"(?<![A-Za-z0-9])bc1[02-9ac-hj-np-z]{11,71}(?![A-Za-z0-9])",
        name="bitcoin_bech32",
        score=0.9,
        validator=v.bech32,
    ),
    PatternDetector(
        t.CRYPTO_WALLET,
        r"(?<![A-Za-z0-9])0x[0-9A-Fa-f]{40}(?![A-Za-z0-9])",
        name="ethereum",
        score=0.8,
    ),
    # -------------------------------------------------------------- network
    PatternDetector(
        t.IP_ADDRESS,
        rf"(?<![\w.]){_OCTET}(?:\.{_OCTET}){{3}}(?!\w|\.\d)",
        name="ipv4",
        score=0.8,
    ),
    PatternDetector(
        t.IP_ADDRESS,
        r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}"
        rf"(?:{_OCTET}(?:\.{_OCTET}){{3}}|[0-9A-Fa-f]{{0,4}})(?!\w)(?!:[\w:])",
        name="ipv6",
        score=0.8,
        validator=v.ipv6,
    ),
    PatternDetector(
        t.MAC_ADDRESS,
        r"(?<!\w)(?<!\w[:-])[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\1[0-9A-Fa-f]{2}){4}(?!\w)(?![:-]\w)",
        score=0.85,
    ),
    PatternDetector(
        t.URL,
        r"(?<!\w)(?:https?|ftp)://[^\s<>\"'`\[\]{}|\\^]{1,2048}",
        score=0.6,
        scorer=_url_score,
        trim=_trim_url,
    ),
    # -------------------------------------------------------------- devices
    PatternDetector(
        t.IMEI,
        _L + r"\d{2}([ -]?)\d{6}\1\d{6}\1\d" + _R,
        score=0.5,
        validator=v.luhn,
        context=("imei", "imei1", "imei2", "handset", "device id"),
        require_context=True,
    ),
    PatternDetector(
        t.VIN,
        r"(?<![A-Za-z0-9])[A-HJ-NPR-Z0-9]{17}(?![A-Za-z0-9])",
        scorer=_vin_score,
        context=("vin", "vehicle identification", "chassis", "chassis no", "vehicle"),
    ),
    # ------------------------------------------------------------- location
    PatternDetector(
        t.GEO_COORDINATES,
        r"(?<![\w.])[-+]?\d{1,2}\.\d{4,8}, ?[-+]?\d{1,3}\.\d{4,8}(?![\w.])",
        score=0.7,
        validator=v.geo_coordinates,
        context=("lat", "latitude", "lon", "lng", "longitude", "gps", "coordinates", "location"),
    ),
    # ----------------------------------------------------------------- date
    PatternDetector(
        t.DATE_OF_BIRTH,
        _DATE,
        score=0.5,
        flags=re.IGNORECASE,
        context=(
            "born", "dob", "d.o.b", "d.o.b.", "date of birth", "birth date", "birthdate",
            "birthday", "birth", "geboren", "geburtsdatum", "né le", "née le",
            "date de naissance", "fecha de nacimiento", "data di nascita", "geboortedatum",
            "जन्म तिथि", "जन्मतिथि",
        ),  # fmt: skip
        require_context=True,
    ),
)
