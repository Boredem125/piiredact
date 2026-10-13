"""Redaction of nested Python data: dicts, lists, tuples, sets."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from . import types as t

if TYPE_CHECKING:
    from .engine import Redactor

# Entity types that only key hints can produce. There is no detector for
# them: the value is redacted because of the name of the field it sits in.
BANK_ACCOUNT = "BANK_ACCOUNT"
NATIONAL_ID = "NATIONAL_ID"
TAX_ID = "TAX_ID"
DRIVING_LICENCE = "DRIVING_LICENCE"

_HINTS: dict[str, tuple[str, ...]] = {
    t.SECRET: (
        "password", "passwd", "pwd", "passphrase", "secret", "client_secret", "api_key",
        "apikey", "access_key", "secret_key", "private_key", "access_token", "auth_token",
        "refresh_token", "id_token", "token", "authorization", "credentials", "cookie",
        "set_cookie", "cvv", "cvc", "otp",
    ),
    t.EMAIL: ("email", "e_mail", "email_address", "emailaddress"),
    t.PHONE: (
        "phone", "phone_number", "phonenumber", "mobile", "mobile_number", "telephone", "tel",
        "cell", "fax", "msisdn", "whatsapp", "contact_number",
    ),
    t.PERSON: (
        "first_name", "last_name", "full_name", "surname", "given_name", "family_name",
        "middle_name", "maiden_name", "firstname", "lastname", "fullname", "father_name",
        "mother_name", "spouse_name", "customer_name", "patient_name", "user_name_full",
    ),
    t.LOCATION: (
        "address", "street", "street_address", "address1", "address2", "address_line1",
        "address_line2", "address_line_1", "address_line_2", "addr",
    ),
    t.DATE_OF_BIRTH: ("dob", "date_of_birth", "birth_date", "birthdate", "birthday"),
    t.CREDIT_CARD: (
        "credit_card", "card_number", "cardnumber", "cc_number", "credit_card_number",
        "debit_card",
    ),
    t.IBAN: ("iban",),
    t.IP_ADDRESS: ("ip", "ip_address", "ipaddress", "remote_addr", "ipv4", "ipv6"),
    t.PASSPORT: ("passport", "passport_number", "passport_no"),
    "US_SSN": ("ssn", "social_security", "social_security_number"),
    "IN_AADHAAR": ("aadhaar", "aadhar", "aadhaar_number", "aadhar_number", "aadhaar_no"),
    "IN_PAN": ("pan_number", "pan_no", "pan_card"),
    BANK_ACCOUNT: ("account_number", "bank_account", "bank_account_number", "acct_number"),
    NATIONAL_ID: ("national_id", "national_id_number", "nin", "id_number"),
    TAX_ID: ("tax_id", "tin", "tax_number", "vat_number"),
    DRIVING_LICENCE: (
        "driver_license", "drivers_license", "driving_licence", "driving_license",
        "license_number", "licence_number",
    ),
}  # fmt: skip

_KEY_TO_ENTITY: dict[str, str] = {key: entity for entity, keys in _HINTS.items() for key in keys}
HINT_ENTITIES: frozenset[str] = frozenset(_HINTS)

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def entity_for_key(key: object) -> str | None:
    """Entity type implied by a field name, or None.

    ``userEmail``, ``USER-EMAIL`` and ``user_email`` all map to ``EMAIL``:
    names are compared in snake case, and a hint also matches as a suffix.
    """
    if not isinstance(key, str) or not key or len(key) > 64:
        return None
    name = _NON_ALNUM.sub("_", _CAMEL.sub("_", key).lower()).strip("_")
    entity = _KEY_TO_ENTITY.get(name)
    if entity is not None:
        return entity
    parts = name.split("_")
    for cut in range(1, len(parts)):
        entity = _KEY_TO_ENTITY.get("_".join(parts[cut:]))
        if entity is not None:
            return entity
    return None


def redact_obj(
    obj: Any,
    redactor: Redactor,
    *,
    key_hints: bool = True,
    redact_keys: bool = False,
    scan_numbers: bool = False,
    max_depth: int = 100,
) -> Any:
    """Return a copy of ``obj`` with PII redacted. The input is not modified.

    ``key_hints``    redact the whole value of fields whose name says what
                     they hold (``password``, ``ssn``, ``userEmail``), even if
                     the value itself does not look like PII.
    ``redact_keys``  also redact PII found in dictionary keys.
    ``scan_numbers`` also scan ints and floats. A number that contains PII
                     comes back as a redacted string.
    ``max_depth``    nesting deeper than this raises ``ValueError`` rather
                     than returning partly redacted data.

    Dicts, lists, tuples, sets, strings and UTF-8 bytes are handled. Other
    objects are returned unchanged, so convert custom classes to plain data
    first.
    """
    memo: dict[tuple[int, str | None], Any] = {}

    def scalar(value: Any, hint: str | None) -> Any:
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, str):
            if hint is not None and value:
                return redactor.operator_for(hint).apply(value, hint)
            return redactor.redact(value).text
        if isinstance(value, (bytes, bytearray)):
            try:
                decoded = bytes(value).decode("utf-8")
            except UnicodeDecodeError:
                return value
            return type(value)(scalar(decoded, hint).encode("utf-8"))
        if isinstance(value, (int, float)):
            if hint is not None:
                return redactor.operator_for(hint).apply(str(value), hint)
            if scan_numbers:
                result = redactor.redact(str(value))
                return result.text if result.spans else value
        return value

    def walk(value: Any, hint: str | None, depth: int) -> Any:
        if depth > max_depth:
            raise ValueError(f"object nested deeper than max_depth={max_depth}")
        if isinstance(value, Mapping):
            key = (id(value), hint)
            if key in memo:
                return memo[key]
            out: dict[Any, Any] = {}
            memo[key] = out
            for name, item in value.items():
                # A field's own name wins; otherwise the parent's hint carries down,
                # so {"address": {"line1": ...}} is redacted as a whole.
                child_hint = (entity_for_key(name) if key_hints else None) or hint
                new_name = name
                if redact_keys and isinstance(name, str):
                    new_name = redactor.redact(name).text
                out[new_name] = walk(item, child_hint, depth + 1)
            return out
        if isinstance(value, list):
            key = (id(value), hint)
            if key in memo:
                return memo[key]
            items: list[Any] = []
            memo[key] = items
            items.extend(walk(item, hint, depth + 1) for item in value)
            return items
        if isinstance(value, tuple):
            walked = [walk(item, hint, depth + 1) for item in value]
            if hasattr(value, "_fields"):  # namedtuple
                return type(value)(*walked)
            return tuple(walked)
        if isinstance(value, (set, frozenset)):
            return type(value)(walk(item, hint, depth + 1) for item in value)
        return scalar(value, hint)

    return walk(obj, None, 0)
