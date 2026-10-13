import pytest

import piiredact
from piiredact import Redactor, locales, supported_entities


@pytest.mark.parametrize(
    ("text", "entity", "value"),
    [
        # United States
        ("SSN 078-05-1120", "US_SSN", "078-05-1120"),
        ("ssn: 078051120", "US_SSN", "078051120"),
        ("ITIN 912-70-1234", "US_ITIN", "912-70-1234"),
        ("EIN 12-3456789", "US_EIN", "12-3456789"),
        ("passport no A12345678", "US_PASSPORT", "A12345678"),
        ("routing number 021000021", "US_ROUTING_NUMBER", "021000021"),
        ("zip code 94105-1234", "US_ZIP", "94105-1234"),
        # India
        ("Aadhaar 2345 6789 0124", "IN_AADHAAR", "2345 6789 0124"),
        ("2345-6789-0124", "IN_AADHAAR", "2345-6789-0124"),
        ("PAN ABCPE1234F", "IN_PAN", "ABCPE1234F"),
        ("GSTIN 27AAPFU0939F1ZV", "IN_GSTIN", "27AAPFU0939F1ZV"),
        ("voter id ABC1234567", "IN_VOTER_ID", "ABC1234567"),
        ("passport number J8369854", "IN_PASSPORT", "J8369854"),
        ("IFSC HDFC0001234", "IN_IFSC", "HDFC0001234"),
        ("pay raj.kumar@okaxis.", "IN_UPI_ID", "raj.kumar@okaxis"),
        ("UPI id shop99@newbank", "IN_UPI_ID", "shop99@newbank"),
        ("pin code 411001", "IN_PIN_CODE", "411001"),
        # United Kingdom
        ("NINO AB123456C", "GB_NINO", "AB123456C"),
        ("AB 12 34 56 C", "GB_NINO", "AB 12 34 56 C"),
        ("NHS number 943 476 5919", "GB_NHS_NUMBER", "943 476 5919"),
        ("lives at SW1A 1AA", "GB_POSTCODE", "SW1A 1AA"),
        ("licence MORGA657054SM9IJ", "GB_DRIVING_LICENCE", "MORGA657054SM9IJ"),
        # Germany, France, Spain, Italy, Netherlands, EU
        ("Steuer-ID 86095742719", "DE_TAX_ID", "86095742719"),
        ("Personalausweis L01X00T47", "DE_ID_CARD", "L01X00T47"),
        ("NIR 1 85 05 78 006 084 91", "FR_NIR", "1 85 05 78 006 084 91"),
        ("DNI 12345678Z", "ES_DNI", "12345678Z"),
        ("NIE X1234567L", "ES_NIE", "X1234567L"),
        ("CF RSSMRA80A01H501U", "IT_FISCAL_CODE", "RSSMRA80A01H501U"),
        ("BSN 111222333", "NL_BSN", "111222333"),
        ("VAT DE123456789", "EU_VAT", "DE123456789"),
    ],
)
def test_detects(text, entity, value):
    found = {(span.entity, span.text) for span in piiredact.scan(text)}
    assert (entity, value) in found


@pytest.mark.parametrize(
    "text",
    [
        "invoice 078051120",  # nine digits, no context
        "code 94105",  # five digits, no context
        "ref 411001",
        "SSN 666-05-1120",  # area 666 is never issued
        "2345 6789 0123",  # fails Verhoeff
        "GSTIN 27AAPFU0939F1ZW",  # bad check character
        "NINO GB123456C",  # GB is not a valid prefix
        "DNI 12345678A",  # wrong letter
        "root@localhost",
        "jane@example.com",  # an email, not a UPI ID
    ],
)
def test_rejects_as_locale_identifier(text):
    locale_entities = {
        span.entity for span in piiredact.scan(text) if span.entity[:3] in {
            "US_", "IN_", "GB_", "DE_", "FR_", "ES_", "IT_", "NL_", "EU_"}
    }  # fmt: skip
    assert locale_entities == set()


def test_strict_mode_drops_the_context_requirement():
    assert piiredact.scan("invoice 078051120") == []
    assert piiredact.scan("invoice 078051120", strict=True) != []


def test_gstin_is_not_reported_as_the_pan_inside_it():
    assert [s.entity for s in piiredact.scan("27AAPFU0939F1ZV")] == ["IN_GSTIN"]


def test_locale_selection():
    text = "SSN 123-45-6789 and Aadhaar 2345 6789 0124"
    assert Redactor(locales=["us"]).redact(text).text == "SSN [US_SSN] and Aadhaar 2345 6789 0124"
    assert Redactor(locales=["in"]).redact(text).text == "SSN 123-45-6789 and Aadhaar [IN_AADHAAR]"
    assert Redactor(locales=[]).redact(text).text == text


def test_aliases_and_unknown_locale():
    assert locales.load("uk") is locales.load("gb")
    assert locales.load("IN") is locales.load("in")
    with pytest.raises(ValueError, match="unknown locale"):
        Redactor(locales=["zz"])


def test_every_builtin_pack_loads_and_follows_the_naming_rule():
    for code in locales.BUILTIN:
        detectors = locales.load(code)
        assert detectors, code
        for detector in detectors:
            assert detector.entity.startswith(code.upper() + "_"), detector


def test_supported_entities():
    names = supported_entities()
    assert {"EMAIL", "US_SSN", "IN_AADHAAR", "GB_NINO", "SECRET"} <= set(names)
    assert names == sorted(names)
    assert "IN_AADHAAR" not in supported_entities(["us"])
