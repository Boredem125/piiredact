"""Checksum and structure validators.

Every function takes the matched text (separators allowed) and returns a bool.
They never raise on malformed input: a validator that raises would turn a
detection miss into a crash.
"""

from __future__ import annotations

import hashlib
import ipaddress
from collections import Counter


def digits_of(value: str) -> str:
    return "".join(ch for ch in value if ch.isdigit())


def alnum_of(value: str) -> str:
    return "".join(ch for ch in value if ch.isalnum()).upper()


# --------------------------------------------------------------------- generic


def luhn(value: str) -> bool:
    digits = digits_of(value)
    if len(digits) < 2:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = ord(char) - 48
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


_VERHOEFF_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_VERHOEFF_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)


def verhoeff(value: str) -> bool:
    digits = digits_of(value)
    if not digits:
        return False
    check = 0
    for index, char in enumerate(reversed(digits)):
        check = _VERHOEFF_D[check][_VERHOEFF_P[index % 8][ord(char) - 48]]
    return check == 0


# --------------------------------------------------------------------- finance

# (prefixes, valid lengths) per card scheme. Checking the length as well as
# the prefix keeps other Luhn-valid numbers, such as IMEIs, from matching.
_CARD_SCHEMES: tuple[tuple[tuple[str, ...], frozenset[int]], ...] = (
    (("4",), frozenset({13, 16, 19})),  # Visa
    (("51", "52", "53", "54", "55", "22", "23", "24", "25", "26", "27"), frozenset({16})),  # Mastercard
    (("34", "37"), frozenset({15})),  # American Express
    (("30", "36", "38", "39"), frozenset({14, 16, 19})),  # Diners Club
    (("35",), frozenset({16, 17, 18, 19})),  # JCB
    (("60", "64", "65", "62", "81"), frozenset({16, 17, 18, 19})),  # Discover, UnionPay, RuPay
    (("50", "56", "57", "58", "63", "67", "82"), frozenset(range(13, 20))),  # Maestro, RuPay
)  # fmt: skip


def credit_card(value: str) -> bool:
    digits = digits_of(value)
    if len(set(digits)) <= 1:
        return False
    for prefixes, lengths in _CARD_SCHEMES:
        if digits.startswith(prefixes):
            return len(digits) in lengths and luhn(digits)
    return False


_IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22,
    "BH": 22, "BR": 29, "BY": 28, "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22,
    "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18, "FR": 27,
    "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28,
    "IE": 22, "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20,
    "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MD": 24,
    "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31,
    "SE": 24, "SI": 19, "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24,
    "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}  # fmt: skip


def iban(value: str) -> bool:
    compact = alnum_of(value)
    if _IBAN_LENGTHS.get(compact[:2]) != len(compact):
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        return int("".join(str(int(ch, 36)) for ch in rearranged)) % 97 == 1
    except ValueError:
        return False


_ISO_COUNTRIES = frozenset(
    ["AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT", "AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI", "BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY", "BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN", "CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM", "DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK", "FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL", "GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM", "HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR", "IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN", "KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS", "LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK", "ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW", "MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP", "NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM", "PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW", "SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM", "SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF", "TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW", "TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI", "VN", "VU", "WF", "WS", "XK", "YE", "YT", "ZA", "ZM", "ZW"]
)


def bic(value: str) -> bool:
    return len(value) in (8, 11) and value[4:6] in _ISO_COUNTRIES


def aba_routing(value: str) -> bool:
    digits = digits_of(value)
    if len(digits) != 9 or digits == "000000000":
        return False
    d = [ord(ch) - 48 for ch in digits]
    total = 3 * (d[0] + d[3] + d[6]) + 7 * (d[1] + d[4] + d[7]) + (d[2] + d[5] + d[8])
    return total % 10 == 0


_BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def base58check(value: str) -> bool:
    number = 0
    for char in value:
        index = _BASE58.find(char)
        if index < 0:
            return False
        number = number * 58 + index
    leading = len(value) - len(value.lstrip("1"))
    try:
        raw = b"\x00" * leading + number.to_bytes((number.bit_length() + 7) // 8, "big")
    except OverflowError:
        return False
    if len(raw) != 25:
        return False
    digest = hashlib.sha256(hashlib.sha256(raw[:-4]).digest()).digest()
    return digest[:4] == raw[-4:]


_BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_GEN = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)


def bech32(value: str) -> bool:
    """Accept both bech32 and bech32m checksums."""
    if value != value.lower() and value != value.upper():
        return False
    value = value.lower()
    pos = value.rfind("1")
    if pos < 1 or pos + 7 > len(value):
        return False
    hrp, data = value[:pos], value[pos + 1 :]
    if any(ch not in _BECH32 for ch in data):
        return False
    values = [ord(ch) >> 5 for ch in hrp] + [0] + [ord(ch) & 31 for ch in hrp]
    values += [_BECH32.index(ch) for ch in data]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if (top >> i) & 1:
                chk ^= _BECH32_GEN[i]
    return chk in (1, 0x2BC830A3)


# --------------------------------------------------------------------- network


def ipv6(value: str) -> bool:
    if value.count(":") < 2 or not any(ch.isalnum() for ch in value):
        return False
    try:
        ipaddress.IPv6Address(value)
    except ValueError:
        return False
    return True


def geo_coordinates(value: str) -> bool:
    try:
        lat_text, lon_text = value.split(",")
        lat, lon = float(lat_text), float(lon_text)
    except ValueError:
        return False
    return -90 <= lat <= 90 and -180 <= lon <= 180


# --------------------------------------------------------------------- devices

_VIN_VALUES = dict(zip("ABCDEFGHJKLMNPRSTUVWXYZ", (1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 7, 9,
                                                    2, 3, 4, 5, 6, 7, 8, 9), strict=True))  # fmt: skip
_VIN_WEIGHTS = (8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2)


def vin_check_digit(value: str) -> bool:
    """North American VIN check digit (position 9). Other regions do not use it."""
    if len(value) != 17:
        return False
    total = 0
    for char, weight in zip(value.upper(), _VIN_WEIGHTS, strict=True):
        if char.isdigit():
            total += (ord(char) - 48) * weight
        elif char in _VIN_VALUES:
            total += _VIN_VALUES[char] * weight
        else:
            return False
    remainder = total % 11
    return value[8].upper() == ("X" if remainder == 10 else str(remainder))


# -------------------------------------------------------------------------- US


def us_ssn(value: str) -> bool:
    digits = digits_of(value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in ("000", "666") and area < "900" and group != "00" and serial != "0000"


# ----------------------------------------------------------------------- India

_BASE36 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def in_gstin(value: str) -> bool:
    value = value.upper()
    if len(value) != 15 or any(ch not in _BASE36 for ch in value):
        return False
    total = 0
    factor = 2
    for char in reversed(value[:14]):
        product = factor * _BASE36.index(char)
        total += product // 36 + product % 36
        factor = 1 if factor == 2 else 2
    return _BASE36[(36 - total % 36) % 36] == value[14]


def in_aadhaar(value: str) -> bool:
    digits = digits_of(value)
    return len(digits) == 12 and digits[0] not in "01" and verhoeff(digits)


# -------------------------------------------------------------------------- UK

_NINO_BAD_PREFIXES = frozenset({"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"})


def gb_nino(value: str) -> bool:
    return alnum_of(value)[:2] not in _NINO_BAD_PREFIXES


def gb_nhs(value: str) -> bool:
    digits = digits_of(value)
    if len(digits) != 10 or len(set(digits)) == 1:
        return False
    total = sum((ord(ch) - 48) * weight for ch, weight in zip(digits[:9], range(10, 1, -1), strict=True))
    check = 11 - total % 11
    if check == 11:
        check = 0
    return check != 10 and check == ord(digits[9]) - 48


# -------------------------------------------------------------------------- EU


def de_tax_id(value: str) -> bool:
    """German Steuer-IdNr: ISO 7064 MOD 11,10 plus the digit-repetition rule."""
    digits = digits_of(value)
    if len(digits) != 11 or digits[0] == "0":
        return False
    repeated = [count for count in Counter(digits[:10]).values() if count > 1]
    if len(repeated) != 1 or repeated[0] not in (2, 3):
        return False
    product = 10
    for char in digits[:10]:
        total = (ord(char) - 48 + product) % 10 or 10
        product = (total * 2) % 11
    check = 11 - product
    return (0 if check == 10 else check) == ord(digits[10]) - 48


def fr_nir(value: str) -> bool:
    compact = alnum_of(value)
    if len(compact) != 15:
        return False
    body, key = compact[:13], compact[13:]
    # Corsica uses 2A and 2B as department codes.
    if body[5:7] == "2A":
        body = body[:5] + "19" + body[7:]
    elif body[5:7] == "2B":
        body = body[:5] + "18" + body[7:]
    if not (body.isdigit() and key.isdigit()):
        return False
    return 97 - int(body) % 97 == int(key)


_ES_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"


def es_dni(value: str) -> bool:
    compact = alnum_of(value)
    if len(compact) != 9 or not compact[:8].isdigit():
        return False
    return _ES_LETTERS[int(compact[:8]) % 23] == compact[8]


def es_nie(value: str) -> bool:
    compact = alnum_of(value)
    if len(compact) != 9 or compact[0] not in "XYZ" or not compact[1:8].isdigit():
        return False
    return _ES_LETTERS[int("XYZ".index(compact[0]) * 10_000_000 + int(compact[1:8])) % 23] == compact[8]


_IT_ODD = {
    **dict(zip("0123456789", (1, 0, 5, 7, 9, 13, 15, 17, 19, 21), strict=True)),
    **dict(zip("ABCDEFGHIJKLMNOPQRSTUVWXYZ", (1, 0, 5, 7, 9, 13, 15, 17, 19, 21, 2, 4, 18, 20,
                                             11, 3, 6, 8, 12, 14, 16, 10, 22, 25, 24, 23), strict=True)),
}  # fmt: skip


def it_fiscal_code(value: str) -> bool:
    code = value.upper()
    if len(code) != 16 or not code.isalnum() or not code.isascii():
        return False
    total = 0
    for index, char in enumerate(code[:15]):
        if index % 2 == 0:  # odd position, counting from 1
            total += _IT_ODD[char]
        else:
            total += ord(char) - 48 if char.isdigit() else ord(char) - 65
    return chr(65 + total % 26) == code[15]


def nl_bsn(value: str) -> bool:
    digits = digits_of(value)
    if len(digits) != 9 or digits == "000000000":
        return False
    total = sum((ord(ch) - 48) * weight for ch, weight in zip(digits[:8], range(9, 1, -1), strict=True))
    return (total - (ord(digits[8]) - 48)) % 11 == 0
