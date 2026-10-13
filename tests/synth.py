"""Synthetic PII for tests and benchmarks.

Every value is generated: correct shape and check digits, but not issued to
anyone. No real personal data belongs in this repository.
"""

from __future__ import annotations

import random
import string
from collections.abc import Callable
from dataclasses import dataclass

from depii import validators as v

UPPER = string.ascii_uppercase
DIGITS = string.digits


def _digits(rng: random.Random, count: int) -> str:
    return "".join(rng.choice(DIGITS) for _ in range(count))


def _letters(rng: random.Random, count: int, alphabet: str = UPPER) -> str:
    return "".join(rng.choice(alphabet) for _ in range(count))


def _with_check(body: str, valid: Callable[[str], bool], alphabet: str = DIGITS) -> str:
    """Append whichever check character makes ``body`` valid."""
    for char in alphabet:
        if valid(body + char):
            return body + char
    raise ValueError(f"no check character fits {body!r}")


def _retry(make: Callable[[], str]) -> str:
    """Some bodies have no valid check digit (NHS remainder 10); draw again."""
    while True:
        try:
            return make()
        except ValueError:
            continue


def _group(value: str, size: int, sep: str) -> str:
    return sep.join(value[i : i + size] for i in range(0, len(value), size))


# ---------------------------------------------------------------- generators


def email(rng: random.Random) -> str:
    user = rng.choice(["jane", "raj.kumar", "a_b", "info", "maria-g", "x1"]) + str(
        rng.randint(1, 999)
    )
    return f"{user}@{rng.choice(['example.com', 'example.org', 'mail.example.net'])}"


def phone(rng: random.Random) -> str:
    last = _digits(rng, 2)
    return rng.choice(
        [
            f"+1 415 555 01{last}",
            f"+1-212-555-01{last}",
            f"(415) 555-01{last}",
            f"415-555-01{last}",
            f"+44 20 7946 0{_digits(rng, 3)}",
            f"020 7946 0{_digits(rng, 3)}",
            f"+91 98765 4{_digits(rng, 4)}",
            f"+91-9{_digits(rng, 9)}",
            f"98765 4{_digits(rng, 4)}",
            f"+49 30 5550{_digits(rng, 4)}",
            f"+33 1 55 55 {_digits(rng, 2)} {last}",
        ]
    )


def credit_card(rng: random.Random) -> str:
    prefix = rng.choice(["4", "51", "55", "2221", "6011"])
    number = _with_check(prefix + _digits(rng, 15 - len(prefix)), v.luhn)
    return rng.choice([number, _group(number, 4, " "), _group(number, 4, "-")])


def amex(rng: random.Random) -> str:
    number = _with_check(rng.choice(["34", "37"]) + _digits(rng, 12), v.luhn)
    return rng.choice([number, f"{number[:4]} {number[4:10]} {number[10:]}"])


def iban(rng: random.Random) -> str:
    country, length = rng.choice([("DE", 22), ("GB", 22), ("FR", 27), ("NL", 18), ("ES", 24)])
    bban = _digits(rng, length - 4)
    if country == "GB":
        bban = _letters(rng, 4) + bban[4:]
    if country == "NL":
        bban = _letters(rng, 4) + bban[4:]
    numeric = "".join(str(int(ch, 36)) for ch in bban + country + "00")
    value = f"{country}{98 - int(numeric) % 97:02d}{bban}"
    return rng.choice([value, _group(value, 4, " ")])


def ipv4(rng: random.Random) -> str:
    return f"{rng.choice(['203.0.113', '198.51.100', '192.0.2'])}.{rng.randint(1, 254)}"


def ipv6(rng: random.Random) -> str:
    return "2001:db8:" + ":".join(f"{rng.randint(0, 65535):x}" for _ in range(6))


def mac(rng: random.Random) -> str:
    sep = rng.choice(":-")
    return sep.join(f"{rng.randint(0, 255):02X}" for _ in range(6))


def us_ssn(rng: random.Random) -> str:
    area = rng.choice([n for n in range(1, 900) if n != 666])
    return f"{area:03d}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"


def in_aadhaar(rng: random.Random) -> str:
    number = _with_check(rng.choice("23456789") + _digits(rng, 10), v.verhoeff)
    return rng.choice([number, _group(number, 4, " "), _group(number, 4, "-")])


def in_pan(rng: random.Random) -> str:
    return (
        _letters(rng, 3)
        + rng.choice("PCHFAT")
        + _letters(rng, 1)
        + _digits(rng, 4)
        + _letters(rng, 1)
    )


def in_gstin(rng: random.Random) -> str:
    body = f"{rng.randint(1, 37):02d}{in_pan(rng)}{rng.choice('123456789')}Z"
    return _with_check(body, v.in_gstin, DIGITS + UPPER)


def gb_nino(rng: random.Random) -> str:
    while True:
        prefix = _letters(rng, 1, "ABCEGHJKLMNOPRSTWXYZ") + _letters(rng, 1, "ABCEGHJKLMNPRSTWXYZ")
        if v.gb_nino(prefix):
            break
    number = prefix + _digits(rng, 6) + rng.choice("ABCD")
    return rng.choice(
        [number, f"{number[:2]} {number[2:4]} {number[4:6]} {number[6:8]} {number[8]}"]
    )


def gb_nhs(rng: random.Random) -> str:
    number = _retry(lambda: _with_check(_digits(rng, 9), v.gb_nhs))
    return rng.choice([number, f"{number[:3]} {number[3:6]} {number[6:]}"])


def de_tax_id(rng: random.Random) -> str:
    def make() -> str:
        first = rng.choice("123456789")
        rest = rng.sample([d for d in DIGITS if d != first], 8)
        body = [first, *rest]
        body.insert(rng.randint(1, len(body)), rng.choice(body))
        return _with_check("".join(body), v.de_tax_id)

    return _retry(make)


def fr_nir(rng: random.Random) -> str:
    dept = rng.choice([n for n in range(1, 96) if n != 20])
    body = (
        f"{rng.choice('12')}{rng.randint(0, 99):02d}{rng.randint(1, 12):02d}"
        f"{dept:02d}{rng.randint(1, 999):03d}{rng.randint(1, 999):03d}"
    )
    value = f"{body}{97 - int(body) % 97:02d}"
    spaced = f"{value[0]} {value[1:3]} {value[3:5]} {value[5:7]} {value[7:10]} {value[10:13]} {value[13:]}"
    return rng.choice([value, spaced])


def es_dni(rng: random.Random) -> str:
    return _with_check(_digits(rng, 8), v.es_dni, UPPER)


def es_nie(rng: random.Random) -> str:
    return _with_check(rng.choice("XYZ") + _digits(rng, 7), v.es_nie, UPPER)


def it_fiscal_code(rng: random.Random) -> str:
    body = (
        _letters(rng, 6) + _digits(rng, 2) + rng.choice("ABCDEHLMPRST")
        + f"{rng.randint(1, 31):02d}" + _letters(rng, 1) + _digits(rng, 3)
    )  # fmt: skip
    return _with_check(body, v.it_fiscal_code, UPPER)


def nl_bsn(rng: random.Random) -> str:
    return _retry(lambda: _with_check(_digits(rng, 8), v.nl_bsn))


def secret(rng: random.Random) -> str:
    alnum = string.ascii_letters + DIGITS
    # Assembled from parts so secret scanners do not flag this file.
    return rng.choice(
        [
            "AK" + "IA" + _letters(rng, 16, UPPER + DIGITS),
            "gh" + "p_" + _letters(rng, 36, alnum),
            "xox" + "b-" + _digits(rng, 12) + "-" + _letters(rng, 24, alnum),
            "sk" + "_live_" + _letters(rng, 24, alnum),
        ]
    )


@dataclass(frozen=True)
class Kind:
    entity: str
    make: Callable[[random.Random], str]
    # Sentences with one {} slot. Identifiers that need a context word get one here.
    templates: tuple[str, ...]


_PLAIN = (
    "Please update the record to {} before Friday.",
    "{} was given by the customer during the call.",
    "Ticket notes: user confirmed {}, nothing else changed.",
    "value={}",
)

KINDS: tuple[Kind, ...] = (
    Kind("EMAIL", email, _PLAIN),
    Kind("PHONE", phone, (*_PLAIN, "Call me on {} after six.", "Tel: {}")),
    Kind("CREDIT_CARD", credit_card, (*_PLAIN, "Paid with card {} exp 12/29.")),
    Kind("CREDIT_CARD", amex, _PLAIN),
    Kind("IBAN", iban, (*_PLAIN, "Transfer to {} TODAY")),
    Kind("IP_ADDRESS", ipv4, (*_PLAIN, "Failed login from {}.")),
    Kind("IP_ADDRESS", ipv6, _PLAIN),
    Kind("MAC_ADDRESS", mac, _PLAIN),
    Kind("SECRET", secret, _PLAIN),
    Kind("US_SSN", us_ssn, (*_PLAIN, "SSN {} on file.")),
    Kind("IN_AADHAAR", in_aadhaar, (*_PLAIN, "Aadhaar no. {} verified.")),
    Kind("IN_PAN", in_pan, (*_PLAIN, "PAN {} linked.")),
    Kind("IN_GSTIN", in_gstin, _PLAIN),
    Kind("GB_NINO", gb_nino, (*_PLAIN, "NI number {}.")),
    Kind("GB_NHS_NUMBER", gb_nhs, ("NHS number {} checked.", "Patient NHS no: {}")),
    Kind("DE_TAX_ID", de_tax_id, (*_PLAIN, "Steuer-ID: {}")),
    Kind("FR_NIR", fr_nir, _PLAIN),
    Kind("ES_DNI", es_dni, (*_PLAIN, "DNI {}.")),
    Kind("ES_NIE", es_nie, _PLAIN),
    Kind("IT_FISCAL_CODE", it_fiscal_code, _PLAIN),
    Kind("NL_BSN", nl_bsn, ("BSN {} is geregistreerd.", "burgerservicenummer: {}")),
)

# Text that looks numeric or token-like but holds no PII.
NEGATIVES: tuple[str, ...] = (
    "Order 1234567890 shipped on 2024-03-15 at 14:32:07.",
    "Upgrade from version 10.0.26200.1 to 11.2.0.",
    "Request id 550e8400-e29b-41d4-a716-446655440000 took 1532 ms.",
    "commit 9fceb02d0ae598e95dc970b74767f19372d61af8 merged into main",
    "Total: 1,299.00 USD for 3 items, invoice 000482913.",
    "The meeting moved from 10:30 to 11:45 in room 4021.",
    "ISBN 978-3-16-148410-0, 2nd edition, 412 pages.",
    "Tracking number 1Z999AA10123456784 delivered.",
    "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "Server responded 404 after 3 retries; error code 0x80070005.",
    "See section 3.14.15 and figure 12-4 on page 220.",
    "Batch 20240315-0042 processed 18446744073709551615 rows.",
    "Temperature 21.5 C, pressure 1013.25 hPa, humidity 45 %.",
    "The quick brown fox jumps over the lazy dog 13 times.",
    "Released under the Apache-2.0 licence in 2026.",
    "user_id=48213 session_len=3600 status=OK",
    "Part no. AB-4471-X, lot 77120, qty 250.",
    "Flight BA2490 departs gate B32 at 06:15.",
)


@dataclass(frozen=True)
class Sample:
    text: str
    # (start, end, entity) of each planted value; empty for negatives
    gold: tuple[tuple[int, int, str], ...]


def corpus(seed: int = 7, per_kind: int = 40) -> list[Sample]:
    """A labelled corpus: ``per_kind`` positives per generator plus all negatives."""
    rng = random.Random(seed)
    samples: list[Sample] = []
    for kind in KINDS:
        for _ in range(per_kind):
            value = kind.make(rng)
            template = rng.choice(kind.templates)
            start = template.index("{}")
            samples.append(
                Sample(template.format(value), ((start, start + len(value), kind.entity),))
            )
    samples.extend(Sample(text, ()) for text in NEGATIVES)
    return samples


@dataclass
class Score:
    planted: int = 0  # values planted for this entity
    found: int = 0  # planted values covered by a span with the right label
    covered: int = 0  # planted values covered by a span with any label
    predicted: int = 0  # spans emitted with this label
    correct: int = 0  # emitted spans that overlap a planted value of this label

    @property
    def recall(self) -> float:
        return self.found / self.planted if self.planted else 1.0

    @property
    def coverage(self) -> float:
        """Share of planted values that were redacted, whatever the label."""
        return self.covered / self.planted if self.planted else 1.0

    @property
    def precision(self) -> float:
        return self.correct / self.predicted if self.predicted else 1.0


def evaluate(scan: Callable[[str], list], samples: list[Sample]) -> dict[str, Score]:
    """Score ``scan`` against a labelled corpus. Returns a Score per entity type."""
    scores: dict[str, Score] = {}

    def score(entity: str) -> Score:
        return scores.setdefault(entity, Score())

    for sample in samples:
        spans = scan(sample.text)
        for start, end, entity in sample.gold:
            entry = score(entity)
            entry.planted += 1
            covering = [s for s in spans if s.start <= start and s.end >= end]
            entry.covered += bool(covering)
            entry.found += any(s.entity == entity for s in covering)
        for span in spans:
            entry = score(span.entity)
            entry.predicted += 1
            entry.correct += any(
                entity == span.entity and span.start < end and start < span.end
                for start, end, entity in sample.gold
            )
    return scores
