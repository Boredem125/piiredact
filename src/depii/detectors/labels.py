"""Values identified by the label in front of them, in prose and in tables.

``Email: jane at example dot com`` is an email address because of its label,
whatever the value looks like. The same holds for a cell in a table column
headed ``Email``. This detector finds such labels and redacts the value.

Labels are found from the separator backwards: every ``:``, ``=`` or ``is``
is a candidate, and the words just before it are looked up in a table of
known labels. That keeps the cost independent of how many labels exist.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from .. import types as t
from ..structured import _KEY_TO_ENTITY, HINT_ENTITIES, entity_for_key
from ..types import Span

USERNAME = t.USERNAME

# Label phrase (lowercase words separated by single spaces) -> entity type.
# None marks phrases that contain a label word but are not personal data,
# such as "file name", so the shorter label inside them is not used.
_LABELS: dict[str, str | None] = {}


def _add(entity: str | None, *phrases: str) -> None:
    for phrase in phrases:
        _LABELS[_normalise(phrase)] = entity


_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_WORDS = re.compile(r"[^\W\d_]+", re.UNICODE)


def _normalise(label: str) -> str:
    """ "Date_of-Birth", "dateOfBirth" and "date of birth" all become "date of birth"."""
    return " ".join(_WORDS.findall(_CAMEL.sub(" ", label).lower()))


_add(t.PERSON, "name", "full name", "first name", "last name", "surname", "given name",
     "family name", "middle name", "maiden name", "patient", "patient name", "customer",
     "customer name", "client",
     "client name", "contact name", "contact person", "father name", "father's name",
     "mother name", "mother's name", "spouse", "spouse name", "husband name", "wife name",
     "guardian", "guardian name", "nominee", "nominee name", "applicant", "applicant name",
     "employee name", "account holder", "account holder name", "cardholder", "card holder",
     "cardholder name", "beneficiary", "beneficiary name", "candidate name", "student name",
     "attn", "attention", "recipient", "sender name", "signed by", "naam", "nombre",
     "nom", "nom complet", "vorname", "nachname", "nome", "cognome", "imie",
     "nazwisko")  # fmt: skip
_add(t.ORGANIZATION, "company", "company name", "employer", "employer name", "organisation",
     "organization", "organisation name", "organization name", "firm", "business name")  # fmt: skip
_add(t.LOCATION, "address", "home address", "residential address", "permanent address",
     "current address", "postal address", "mailing address", "billing address",
     "shipping address", "delivery address", "correspondence address", "street",
     "street address", "residence", "domicile", "dirección", "direccion", "adresse",
     "anschrift", "wohnort", "indirizzo", "endereço", "endereco", "pata", "adres")  # fmt: skip
_add(t.EMAIL, "email", "e mail", "email address", "e mail address", "email id", "mail id",
     "e mail id", "mail", "correo", "correo electrónico", "courriel")  # fmt: skip
_add(t.PHONE, "phone", "phone no", "phone number", "phone num", "ph", "ph no", "mobile",
     "mobile no", "mobile number", "mob", "mob no", "cell", "cell no", "cell number",
     "telephone", "telephone number", "tel", "tel no", "landline", "whatsapp",
     "whatsapp no", "whatsapp number", "fax", "fax no", "contact no", "contact number",
     "teléfono", "telefono", "telefon", "telefonnummer", "handy", "téléphone", "portable",
     "celular")  # fmt: skip
_add(t.DATE_OF_BIRTH, "dob", "d o b", "date of birth", "birth date", "birthdate", "birthday",
     "born", "born on", "fecha de nacimiento", "geburtsdatum", "date de naissance",
     "data di nascita", "data de nascimento")  # fmt: skip
_add(t.SECRET, "password", "passwd", "pwd", "passcode", "passphrase", "secret", "api key",
     "access key", "secret key", "access token", "auth token", "token", "otp", "cvv", "cvc",
     "security code", "pin number", "atm pin")  # fmt: skip
# Numeric user and login IDs are left alone: they are kept in logs on purpose.
_add(USERNAME, "username", "user name", "login", "handle")
_add(None, "user id", "userid", "login id")
_add(t.PASSPORT, "passport", "passport no", "passport number")
_add(t.CREDIT_CARD, "card number", "card no", "credit card", "credit card number",
     "debit card", "debit card number")  # fmt: skip
_add("BANK_ACCOUNT", "account number", "account no", "acct no", "bank account",
     "bank account number", "a c no")  # fmt: skip
_add("NATIONAL_ID", "national id", "id number", "identity number", "id card number",
     "national insurance number")  # fmt: skip
_add("TAX_ID", "tax id", "tax number", "tin")
_add("DRIVING_LICENCE", "driving licence", "driving license", "driver's license",
     "drivers license", "licence number", "license number", "dl no")  # fmt: skip
_add("US_SSN", "ssn", "social security number")
_add("IN_AADHAAR", "aadhaar", "aadhar", "aadhaar no", "aadhaar number", "uid")
_add("IN_PAN", "pan", "pan no", "pan number", "pan card")
# Look like labels above but are not about a person.
_add(None, "file name", "filename", "host name", "hostname", "domain name", "server name",
     "table name", "column name", "field name", "class name", "function name",
     "method name", "variable name", "package name", "module name", "project name",
     "product name", "brand name", "app name", "service name", "branch name", "tag name",
     "bucket name", "queue name", "topic name", "display mode", "ip address", "mac address",
     "web address", "memory address", "wallet address", "bitcoin address", "contract address",
     "mail server", "email template", "email subject", "email body", "phone model",
     "token count", "token type", "token limit", "pin code", "pincode", "street light")  # fmt: skip

# The words a label can end with, for the quick check in _label_before. Field
# names such as "billing_address" are matched on their last part as well.
_LAST_WORDS = frozenset(
    {phrase.rsplit(" ", 1)[-1] for phrase in _LABELS}
    | {key.rsplit("_", 1)[-1] for key in _KEY_TO_ENTITY}
)

# Labels whose value is a single identifier rather than free text.
_IDENTIFIER_ENTITIES = frozenset(
    {
        t.PASSPORT, t.CREDIT_CARD, "BANK_ACCOUNT", "NATIONAL_ID", "TAX_ID", "DRIVING_LICENCE",
        "US_SSN", "IN_AADHAAR", "IN_PAN", USERNAME, t.SECRET,
    }
)  # fmt: skip

_PHONE_CHARS = re.compile(r"[ \"']*[+(]?[0-9][0-9 ().+/-]*")
LABEL_SCORE = 0.97
LABEL_SCORE_WEAK = 0.85

# "I live at ...", "she resides in ...": a place without a "label: value" shape.
_LIVES_AT = re.compile(
    r"(?:live|lives|living|reside|resides|residing|stay|stays|staying)"
    r"(?<![^\W\d_]live)(?<![^\W\d_]lives)(?<![^\W\d_]living)"  # not "outlive", "delivering"
    r"\s+(?:at|in|on)\s+",
    re.IGNORECASE,
)

# Each alternative starts with the separator itself, not with the spaces
# around it, so the regex engine can skip straight to candidate characters.
_SEPARATOR = re.compile(
    r"(?P<strong>[:=：])"
    r"|(?P<dash>[-–—](?<=\s[-–—])-?>?)(?=\s)"
    r"|(?P<weak>[iIwW](?<=\s[iIwW])(?:[sS]|[aA][sS]))(?=\s)"
)
# Spacing, and after "is" an article, between a separator and its value.
_GAP = re.compile(r"[ \t]{0,3}(?:(?<=\s)(?:an?|An?)[ \t]+)?")
_NULLISH = frozenset(
    {"", "-", "--", "n/a", "na", "none", "null", "nil", "unknown", "not provided",
     "not available", "tbd", "redacted", "xxx", "***", "?", "same as above", "nan"}
)  # fmt: skip
_PLACEHOLDER = re.compile(r"\[[A-Z][A-Z0-9_]*(?::[^\]\s]{1,64})?\]")
_MONTHS = ("jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec")
_STOP_ALWAYS = "\n\r|;\t"
_MAX_LENGTH = {t.LOCATION: 150, t.PERSON: 60, t.ORGANIZATION: 80}
_NOT_A_NAME = frozenset(
    {"required", "optional", "missing", "invalid", "empty", "unknown", "test", "string",
     "admin", "user", "default", "anonymous", "guest", "true", "false", "yes", "no", "same"}
)  # fmt: skip


def entity_for_label(label: str) -> str | None:
    """Entity type implied by a label or column header, or None."""
    phrase = _normalise(label)
    if phrase in _LABELS:
        return _LABELS[phrase]
    return entity_for_key(label)


_TRAILING = " \"'`*"


_KEY_TOKEN = re.compile(r"[A-Za-z0-9_.\-]+$")


def _last_word(head: str) -> str:
    """The last word of ``head``, lowercased; for "userEmail" that is "email"."""
    end = len(head)
    while end and head[end - 1] in _TRAILING:
        end -= 1
    start = end
    while start and head[start - 1].isalpha():
        start -= 1
    word = head[start:end]
    for index in range(len(word) - 1, 0, -1):
        if word[index].isupper() and word[index - 1].islower():
            return word[index:].lower()
    return word.lower()


def _label_before(text: str, end: int) -> tuple[str | None, bool]:
    """Find a known label ending at ``end``. Returns (entity, found)."""
    head = text[max(0, end - 48) : end]
    # Cheap rejection first: most separators do not follow a label word.
    if _last_word(head) not in _LAST_WORDS:
        return None, False
    head = head.rstrip(_TRAILING)
    # A label is the last few words of the head. Words are compared in the
    # same form as the label table: lowercase letters, "'s" dropped.
    words = _WORDS.findall(head.lower().replace("'s", "").replace("’s", ""))[-5:]
    for size in range(len(words), 0, -1):
        phrase = " ".join(words[-size:])
        if phrase in _LABELS:
            return _LABELS[phrase], True
    # The last token might be a key such as "userEmail" or "billing_address".
    last_token = _KEY_TOKEN.search(head, max(0, len(head) - 40))
    if last_token is not None:
        entity = entity_for_key(last_token.group())
        if entity is not None:
            return entity, True
    return None, False


# A full stop after these does not end a sentence.
_ABBREVIATIONS = frozenset(
    {"dr", "mr", "mrs", "ms", "prof", "st", "sr", "jr", "rd", "no", "apt", "ave", "blvd",
     "ln", "nr", "opp", "flat", "bldg", "co", "ltd", "inc", "pvt", "smt", "shri"}
)  # fmt: skip
_NAME_PARTICLES = frozenset(
    {"de", "da", "das", "dos", "del", "della", "di", "du", "van", "von", "der", "den", "la",
     "le", "bin", "binti", "bint", "ibn", "al", "el", "ben", "ter", "ten", "mac", "o"}
)  # fmt: skip
# In prose, a place ends where the sentence goes on to something else.
_CLAUSE = re.compile(r"\s(?:and|but|where|which|who|since|for|with|from)\s", re.IGNORECASE)


def _sentence_ends(text: str, dot: int) -> bool:
    """Whether the full stop at ``dot`` ends a sentence rather than an abbreviation."""
    if dot + 1 < len(text) and not text[dot + 1].isspace():
        return False
    word = re.search(r"[^\W\d_]+$", text[max(0, dot - 12) : dot])
    if word is None:
        return True
    letters = word.group()
    # A single capital is an initial, as in "J. Smith".
    return not (len(letters) == 1 and letters.isupper()) and letters.lower() not in _ABBREVIATIONS


def _name_run(value: str, *, require_capital: bool) -> int:
    """Length of the leading run of name-like words in ``value``.

    A name written in lowercase is accepted when ``require_capital`` is off,
    but only if it starts lowercase: "R. Iyer from Chennai" stops at "from".
    """
    end = 0
    for count, match in enumerate(re.finditer(r"\S+", value)):
        word = match.group().rstrip(',;"`)]}')
        possessive = word[-2:] in ("'s", "’s")
        if possessive:
            word = word[:-2]  # "Iyer's team": the name is "Iyer"
        core = word.strip(".'’-")
        if not core or not all(ch.isalpha() or ch in ".'’-" for ch in word):
            break
        if count == 0 and core[0].isupper():
            require_capital = True
        particle = count > 0 and core.lower() in _NAME_PARTICLES
        capital = core[0].isupper() or not core[0].isascii()
        if not (particle or capital or not require_capital):
            break
        if not particle:
            end = match.start() + len(word)
        if count == 4 or possessive:
            break
    return end


def _identifier(raw: str, *, single_token: bool) -> str:
    """The identifier at the start of ``raw``: "078051120 on file" -> "078051120".

    Groups are kept together when every group holds a digit or is a short
    capital code, as in "1234 5678 9012" or "AB 12 34 56 C".
    """
    end = 0
    for count, match in enumerate(re.finditer(r"\S+", raw)):
        group = match.group().rstrip(",;")
        if count and (single_token or not (any(ch.isdigit() for ch in group)
                                           or (len(group) <= 2 and group.isupper()))):  # fmt: skip
            break
        end = match.start() + len(group)
    return raw[:end]


def _value_after(text: str, start: int, entity: str, *, weak: bool) -> tuple[int, int]:
    """The extent of the value that follows a separator."""
    limit = min(len(text), start + _MAX_LENGTH.get(entity, 64))
    stops = _STOP_ALWAYS if entity == t.LOCATION else _STOP_ALWAYS + ","
    end = start
    while end < limit and text[end] not in stops:
        # Two or more spaces usually separate fields in aligned text.
        if text[end] == " " and end + 1 < limit and text[end + 1] == " ":
            break
        if text[end] == "." and _sentence_ends(text, end):
            break
        end += 1
    # A following "key: value" pair starts a new field.
    for match in _SEPARATOR.finditer(text, start, end):
        if match.group("strong") and _label_before(text, match.start())[1]:
            cut = text.rfind(" ", start, match.start())
            end = cut if cut > start else match.start()
            break
    raw = text[start:end]
    if _PLACEHOLDER.search(raw):
        return start, start  # already redacted
    if entity == t.PERSON:
        leading = len(raw) - len(raw.lstrip(" \"'`"))
        raw = raw[: leading + _name_run(raw[leading:], require_capital=weak)]
    elif entity == t.PHONE:
        # "98765-43210 (after 6pm)": the number ends where phone characters do.
        number = _PHONE_CHARS.match(raw)
        raw = number.group().rstrip(" (") if number else ""
    elif entity in _IDENTIFIER_ENTITIES:
        raw = _identifier(raw, single_token=entity in (t.SECRET, USERNAME))
    elif entity == t.LOCATION and weak:
        clause = _CLAUSE.search(raw)
        if clause is not None:
            raw = raw[: clause.start()]
    stripped = raw.strip().strip("\"'`").rstrip(".,)]}*").strip().strip("\"'`")
    if not stripped:
        return start, start
    offset = raw.find(stripped)
    return start + offset, start + offset + len(stripped)


_IP_LIKE = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f]{0,4}:")

# Variable names that a username label is often assigned from in code.
_VARIABLE_NAMES = frozenset({"name", "user", "username", "user_name", "login", "handle", "value"})

_UNIT_WORDS = frozenset(
    {"flat", "apt", "apartment", "unit", "suite", "house", "h.no", "plot", "door", "#", "no",
     "room", "block", "building", "bldg", "p.o", "po", "c/o"}
)  # fmt: skip


# Names of secrets: "pwd=pwd" passes a variable along rather than a password.
_SECRET_WORDS = frozenset(
    {"pwd", "password", "passwd", "pass", "passphrase", "secret", "token", "key", "apikey",
     "api_key", "otp", "cvv", "cvc", "credentials", "auth"}
)  # fmt: skip


def plausible_secret(value: str) -> bool:
    """Whether a value assigned to a secret-looking key could be the secret itself."""
    core = value.rstrip("):,;")
    lowered = core.lower()
    if lowered in _CODE_LITERALS or lowered in _SECRET_WORDS:
        return False
    return not lowered.startswith(_CODE_PREFIXES) and "(" not in core


def _comparison(text: str, index: int) -> bool:
    """Whether the ":" or "=" at ``index`` belongs to "==", "!=", "<=", ":=" or "::"."""
    before = text[index - 1 : index]
    after = text[index + 1 : index + 2]
    return after in ("=", ":") or before in ("=", "!", "<", ">", ":")


def _camel_case(value: str) -> bool:
    """ "IPv4Network" or "MyClass", but not "McDonald", "O'Brien" or "DeSouza"."""
    for word in value.split():
        for index in range(2, len(word)):
            if word[index].isupper() and word[index - 1].islower():
                prefix = word[:index]
                if prefix not in ("Mc", "Mac", "De", "Di", "Le", "La", "Van", "Von"):
                    return True
    return False


def _looks_like_name(value: str, *, require_capital: bool) -> bool:
    words = value.replace(",", " ").split()
    if not 1 <= len(words) <= 5 or value.lower() in _NOT_A_NAME:
        return False
    for word in words:
        core = word.strip(".'’-")
        if not core or not all(ch.isalpha() or ch in ".'’-" for ch in word):
            return False
    if not require_capital:
        return True
    # Scripts without case (Devanagari, CJK, Arabic) cannot be checked for capitals.
    return any(word[0].isupper() or not word[0].isascii() for word in words)


# Values that are program code rather than data: "name = value", "pwd=None",
# "addr = parse(addr)", "ip = IPv4Network".
_CODE_LITERALS = frozenset({"none", "null", "nil", "true", "false", "undefined", "nan", "self"})
_CODE_PREFIXES = ("self.", "this.", "os.", "cls.", "$", "%(", "{{", "${", "<%")
# "@", or an "at" marker followed by a dot or "dot": "jane at example dot com",
# "raj [at] example.in". "accepted for at least" has no dot after the "at".
_OBFUSCATED_EMAIL = re.compile(
    r"@|(?:\bat\b|\[at\]|\(at\)|\{at\}).*?(?:\.\w|\bdot\b|\[dot\]|\(dot\))"
)


def _looks_like_code(value: str, following: str) -> bool:
    lowered = value.lower()
    if lowered in _CODE_LITERALS or lowered.startswith(_CODE_PREFIXES):
        return True
    if following[:1] in ("(", "[") or (" " not in value and any(ch in value for ch in "()[]{}")):
        return True  # a call or an index: "parse(addr)", "addr[0]"
    # A bare lower_snake identifier with no digit is a variable, not a value.
    return bool(re.fullmatch(r"[a-z_][a-z_]*(?:\.[a-z_]+)*", value))


def _accept(entity: str, value: str, weak: bool, following: str = "") -> bool:
    lowered = value.lower()
    if lowered in _NULLISH or _PLACEHOLDER.search(value):
        return False
    if not any(ch.isalnum() for ch in value):
        return False
    if entity == USERNAME:
        # Usernames look like identifiers; only rule out obvious variables.
        if lowered in _CODE_LITERALS or lowered in _VARIABLE_NAMES or following[:1] in ("(", "["):
            return False
    elif _looks_like_code(value, following) and entity != t.SECRET:
        return False
    digits = sum(ch.isdigit() for ch in value)
    if entity == t.PERSON:
        # Names are written with capitals (in scripts that have them), and are
        # not CamelCase identifiers such as "IPv4Network".
        # A lone lowercase word was already ruled out as a variable above, so a
        # lowercase name is only accepted with a space in it: "john smith".
        return _looks_like_name(value, require_capital=weak) and not _camel_case(value)
    if entity == t.ORGANIZATION:
        return value[0].isupper() or not value[0].isascii() or value[0].isdigit()
    if entity == t.LOCATION:
        # An address starts with a house or flat number, or lists its parts
        # with commas: "12 High St", "Flat 4, ...", "Hauptstraße 5, Berlin".
        # "address: An integer representation of an IPv4 address" does neither.
        if digits == 0 or not any(ch.isalpha() for ch in value) or "=" in value:
            return False
        first = value.split()[0].rstrip(",.").lower()
        if first in _CODE_LITERALS:
            return False
        starts_like_address = first[0].isdigit() or first in _UNIT_WORDS
        # After "is", only a value that starts like an address will do.
        return starts_like_address or ("," in value and not weak)
    if entity == t.PHONE:
        return digits >= 5
    if entity == t.DATE_OF_BIRTH:
        return digits >= 2 or any(month in lowered for month in _MONTHS)
    if entity == t.EMAIL:
        return _OBFUSCATED_EMAIL.search(lowered) is not None
    if entity == t.IP_ADDRESS:
        return _IP_LIKE.search(value) is not None
    if entity in _IDENTIFIER_ENTITIES:
        token_ok = len(value.split()) <= 4 and len(value) >= 3
        if entity == t.SECRET and lowered.split(" ")[0] in ("bearer", "basic"):
            return False  # the authorization_header detector keeps the scheme visible
        if entity == t.SECRET and not plausible_secret(value):
            return False
        if entity in (t.SECRET, USERNAME):
            return token_ok and not weak
        return token_ok and digits >= 2
    return len(value) >= 2


_TABLE_RULE = re.compile(r"^\s*\|?\s*:?-{2,}:?\s*(?:\|\s*:?-{2,}:?\s*)+\|?\s*$")


def _cells(line: str, start: int, sep: str) -> list[tuple[int, int]]:
    """(start, end) of each cell's stripped content in a table line."""
    cells: list[tuple[int, int]] = []
    position = 0
    parts = line.split(sep)
    if sep == "|":
        # Leading and trailing pipes frame the row rather than separate cells.
        if parts and not parts[0].strip():
            position += len(parts[0]) + 1
            parts = parts[1:]
        if parts and not parts[-1].strip():
            parts = parts[:-1]
    for part in parts:
        stripped = part.strip()
        offset = part.find(stripped) if stripped else 0
        cells.append((start + position + offset, start + position + offset + len(stripped)))
        position += len(part) + 1
    return cells


class LabelDetector:
    """Redact values by their label: ``Name: ...``, ``email = ...``, table columns."""

    name = "labels"
    entity = "*"
    entities = frozenset(e for e in _LABELS.values() if e is not None) | HINT_ENTITIES

    def detect(self, text: str, *, strict: bool = False) -> Iterator[Span]:
        yield from self._prose(text)
        yield from self._tables(text)

    def _prose(self, text: str) -> Iterator[Span]:
        for match in _SEPARATOR.finditer(text):
            if match.group("strong") and _comparison(text, match.start()):
                continue
            entity, found = _label_before(text, match.start())
            if not found or entity is None:
                continue
            weak = match.group("weak") is not None
            gap = _GAP.match(text, match.end())
            start = gap.end() if weak and gap else match.end()
            yield from self._value(text, start, entity, weak)
        for match in _LIVES_AT.finditer(text):
            yield from self._value(text, match.end(), t.LOCATION, weak=True, place=True)

    def _value(
        self, text: str, start: int, entity: str, weak: bool, place: bool = False
    ) -> Iterator[Span]:
        start, end = _value_after(text, start, entity, weak=weak)
        if end <= start:
            return
        value = text[start:end]
        # After "lives in", a capitalised place name is enough: "lives in Leeds".
        named_place = place and value[0].isupper() and not _camel_case(value)
        if named_place or _accept(entity, value, weak, text[end : end + 1]):
            # A labelled value outranks smaller matches inside it, such as the
            # postcode within "Address: 12 High St, Leeds LS1 4AB".
            yield Span(
                start, end, entity, value, LABEL_SCORE_WEAK if weak else LABEL_SCORE, self.name
            )

    def _tables(self, text: str) -> Iterator[Span]:
        lines: list[tuple[int, str]] = []
        position = 0
        for line in text.splitlines(keepends=True):
            lines.append((position, line.rstrip("\r\n")))
            position += len(line)
        index = 0
        while index < len(lines):
            start, line = lines[index]
            sep = "|" if line.count("|") >= 2 else "\t" if line.count("\t") >= 1 else ""
            if not sep:
                index += 1
                continue
            header = _cells(line, start, sep)
            columns = [entity_for_label(text[a:b]) for a, b in header]
            if not any(columns):
                index += 1
                continue
            row = index + 1
            if sep == "|" and row < len(lines) and _TABLE_RULE.match(lines[row][1]):
                row += 1
            while row < len(lines) and lines[row][1].count(sep) >= (2 if sep == "|" else 1):
                row_start, row_line = lines[row]
                for (a, b), entity in zip(_cells(row_line, row_start, sep), columns, strict=False):
                    value = text[a:b]
                    if (
                        entity is not None
                        and b > a
                        and _accept(entity, value, False, text[b : b + 1])
                    ):
                        yield Span(a, b, entity, value, LABEL_SCORE, "labels_table")
                row += 1
            index = row


DETECTORS: tuple[LabelDetector, ...] = (LabelDetector(),)
