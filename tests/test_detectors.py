"""Detection of global identifiers and secrets through the public API."""

import pytest

import piiredact
from piiredact import Redactor


def entities(text, **options):
    return [span.entity for span in piiredact.scan(text, **options)]


def values(text, **options):
    return [span.text for span in piiredact.scan(text, **options)]


@pytest.mark.parametrize(
    ("text", "entity", "value"),
    [
        ("Mail jane.doe+tag@mail.example.co.uk now", "EMAIL", "jane.doe+tag@mail.example.co.uk"),
        ("write to <a_b@example.org>.", "EMAIL", "a_b@example.org"),
        ("reach me at +1 415 555 0132.", "PHONE", "+1 415 555 0132"),
        ("(415) 555-0132 is the desk", "PHONE", "(415) 555-0132"),
        ("office 020 7946 0958", "PHONE", "020 7946 0958"),
        ("+91 98765 43210", "PHONE", "+91 98765 43210"),
        ("card 4111 1111 1111 1111 123", "CREDIT_CARD", "4111 1111 1111 1111"),
        ("card 4111-1111-1111-1111", "CREDIT_CARD", "4111-1111-1111-1111"),
        ("amex 3782 822463 10005", "CREDIT_CARD", "3782 822463 10005"),
        ("pay DE89 3704 0044 0532 0130 00 TODAY", "IBAN", "DE89 3704 0044 0532 0130 00"),
        ("pay CZ65 0800 0000 1920 0014 5399 PAID", "IBAN", "CZ65 0800 0000 1920 0014 5399"),
        ("host 203.0.113.42.", "IP_ADDRESS", "203.0.113.42"),
        ("host 2001:db8::8a2e:370:7334 up", "IP_ADDRESS", "2001:db8::8a2e:370:7334"),
        ("nic 00:1A:2B:3C:4D:5E", "MAC_ADDRESS", "00:1A:2B:3C:4D:5E"),
        ("at 48.858400, 2.294500 today", "GEO_COORDINATES", "48.858400, 2.294500"),
        ("VIN 1HGCM82633A004352", "VIN", "1HGCM82633A004352"),
        ("IMEI 490154203237518", "IMEI", "490154203237518"),
        ("SWIFT code DEUTDEFF500", "BIC", "DEUTDEFF500"),
        ("btc 1BoatSLRHtKNngkdXEeobR76b53LETtpyT", "CRYPTO_WALLET", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
        ("eth 0x52908400098527886E0F7030069857D2E4169EE7", "CRYPTO_WALLET",
         "0x52908400098527886E0F7030069857D2E4169EE7"),
        ("DOB: 01/02/1990", "DATE_OF_BIRTH", "01/02/1990"),
        ("born 3 March 1985 in Pune", "DATE_OF_BIRTH", "3 March 1985"),
    ],
)  # fmt: skip
def test_detects(text, entity, value):
    found = {(span.entity, span.text) for span in piiredact.scan(text)}
    assert (entity, value) in found


@pytest.mark.parametrize(
    "text",
    [
        "Order 1234567890 shipped on 2024-03-15 at 14:32:07.",
        "Upgrade from version 10.0.26200.1 to 11.2.0.",
        "Request id 550e8400-e29b-41d4-a716-446655440000 took 1532 ms.",
        "commit 9fceb02d0ae598e95dc970b74767f19372d61af8 merged",
        "meeting at 12:30:45, room 4021",
        "not a card: 1234 5678 9012 3456",
        "The word COMPUTER is eight capitals",
        "see https://example.com/docs for details",
        "user@localhost and git@host are not emails",
        "price 1,299.00 and ratio 3.14159",
    ],
)
def test_ignores(text):
    assert entities(text) == []


def test_url_is_redacted_only_when_it_carries_data():
    assert piiredact.redact("see https://example.com/reset?token_id=abc.") == "see [URL]."
    assert piiredact.redact("see https://example.com/docs") == "see https://example.com/docs"
    assert piiredact.redact("see https://example.com/docs", strict=True) == "see [URL]"


def test_url_credentials_are_not_split_by_the_email_detector():
    assert piiredact.redact("db https://admin:hunter2@db.example.com/x") == "db [URL]"


def test_neighbouring_numbers_are_both_found():
    assert piiredact.redact("415-555-0132 98765 43210") == "[PHONE] [PHONE]"
    assert values("+1 415 555 0132 9876543210 x")[0] == "+1 415 555 0132"


def test_bare_number_needs_context():
    assert entities("ref 4155550132") == []
    assert entities("phone 4155550132") == ["PHONE"]


def test_date_needs_birth_context():
    assert entities("invoice dated 01/02/2024") == []


class TestSecrets:
    # Sample secrets are assembled from parts so scanners do not flag this file.
    @pytest.mark.parametrize(
        "secret",
        [
            "AK" + "IA" + "IOSFODNN7EXAMPLE",
            "gh" + "p_" + "a" * 36,
            "xox" + "b-123456789012-abcdefghijklmnopqrstuvwx",
            "sk" + "_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2",
            "AI" + "za" + "SyA" + "b" * 32,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ],
    )
    def test_token_formats(self, secret):
        assert piiredact.redact(f"key {secret} end") == "key [SECRET] end"

    def test_private_key_block(self):
        block = (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf\n"
            "-----END RSA PRIVATE KEY-----"
        )
        assert piiredact.redact(f"key:\n{block}\ndone") == "key:\n[SECRET]\ndone"

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("password=hunter2secret; next", "password=[SECRET]; next"),
            ('{"api_key": "abcd1234efgh"}', '{"api_key": "[SECRET]"}'),
            ("Authorization: Bearer abcdefghijklmnop1234", "Authorization: Bearer [SECRET]"),
            ("PWD : s3cr3t!", "PWD : [SECRET]"),
        ],
    )
    def test_assignments_keep_the_key_name(self, text, expected):
        assert piiredact.redact(text) == expected


class TestUnicode:
    def test_fullwidth_digits(self):
        assert (
            piiredact.redact("card ４１１１ １１１１ １１１１ １１１１ ok")
            == "card [CREDIT_CARD] ok"
        )

    def test_zero_width_characters_inside_a_value(self):
        text = "mail ja​ne@exam‍ple.com now"
        result = Redactor().redact(text)
        assert result.text == "mail [EMAIL] now"
        assert result.spans[0].text == "ja​ne@exam‍ple.com"

    def test_devanagari_digits_and_exotic_dashes(self):
        assert piiredact.redact("SSN ०७८–०५–११२०") == "SSN [US_SSN]"

    def test_offsets_point_into_the_original_text(self):
        text = "é​— jane@example.com — ４１１１１１１１１１１１１１１１"
        for span in piiredact.scan(text):
            assert text[span.start : span.end] == span.text

    def test_surrounding_text_is_untouched(self):
        text = "naïve café — ７ jane@example.com ☕"
        assert piiredact.redact(text) == "naïve café — ７ [EMAIL] ☕"
