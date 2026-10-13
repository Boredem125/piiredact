import pytest

from piiredact import validators as v


@pytest.mark.parametrize(
    ("check", "good", "bad"),
    [
        (v.luhn, "4111 1111 1111 1111", "4111 1111 1111 1112"),
        (v.verhoeff, "2363", "2364"),
        (v.credit_card, "5500-0000-0000-0004", "1234 5678 9012 3456"),
        (v.iban, "DE89 3704 0044 0532 0130 00", "DE89 3704 0044 0532 0130 01"),
        (v.iban, "GB29NWBK60161331926819", "GB29NWBK6016133192681"),
        (v.bic, "DEUTDEFF", "DEUTXXFF"),
        (v.aba_routing, "021000021", "021000022"),
        (v.base58check, "1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "1BoatSLRHtKNngkdXEeobR76b53LETtpyU"),
        (v.bech32, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"),
        (v.ipv6, "2001:db8::8a2e:370:7334", "12:30:45"),
        (v.geo_coordinates, "48.8584,2.2945", "98.8584,2.2945"),
        (v.vin_check_digit, "1HGCM82633A004352", "1HGCM82643A004352"),
        (v.us_ssn, "078-05-1120", "666-05-1120"),
        (v.us_ssn, "123-45-6789", "900-45-6789"),
        (v.in_aadhaar, "2345 6789 0124", "2345 6789 0123"),
        (v.in_gstin, "27AAPFU0939F1ZV", "27AAPFU0939F1ZW"),
        (v.gb_nino, "AB123456C", "GB123456C"),
        (v.gb_nhs, "943 476 5919", "943 476 5918"),
        (v.de_tax_id, "86095742719", "86095742710"),
        (v.es_dni, "12345678Z", "12345678A"),
        (v.es_nie, "X1234567L", "X1234567A"),
        (v.it_fiscal_code, "RSSMRA80A01H501U", "RSSMRA80A01H501A"),
        (v.nl_bsn, "111222333", "111222334"),
    ],
)
def test_check_digits(check, good, bad):
    assert check(good)
    assert not check(bad)


def test_fr_nir_key_and_corsica():
    body = "1850578006084"
    assert v.fr_nir(f"{body}{97 - int(body) % 97:02d}")
    assert not v.fr_nir(f"{body}{(97 - int(body) % 97 + 1) % 100:02d}")
    corsica = "185052A006084"
    key = 97 - int(corsica.replace("2A", "19")) % 97
    assert v.fr_nir(f"{corsica}{key:02d}")


def test_de_tax_id_needs_one_repeated_digit():
    # check digit is right, but no digit repeats in the first ten
    assert not v.de_tax_id("12345678903")


@pytest.mark.parametrize(
    "check",
    [
        v.luhn, v.verhoeff, v.credit_card, v.iban, v.bic, v.aba_routing, v.base58check,
        v.bech32, v.ipv6, v.geo_coordinates, v.vin_check_digit, v.us_ssn, v.in_aadhaar,
        v.in_gstin, v.gb_nino, v.gb_nhs, v.de_tax_id, v.fr_nir, v.es_dni, v.es_nie,
        v.it_fiscal_code, v.nl_bsn,
    ],
)  # fmt: skip
@pytest.mark.parametrize("junk", ["", " ", "x", "0", "-", "é", "1" * 400, "A" * 400, "\x00"])
def test_validators_never_raise(check, junk):
    assert check(junk) in (True, False)
