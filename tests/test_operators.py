import threading

import pytest

from piiredact import Drop, Hash, Keep, Mask, Replace, Tokenize, Vault


def test_replace():
    assert Replace().apply("x", "EMAIL") == "[EMAIL]"
    assert Replace("<{entity}>").apply("x", "EMAIL") == "<EMAIL>"
    assert Replace("***").apply("x", "EMAIL") == "***"


class TestMask:
    def test_keeps_separators(self):
        assert Mask().apply("4111 1111-1111", "X") == "**** ****-****"

    def test_keep_first_and_last(self):
        assert Mask(keep_last=4).apply("4111 1111 1111 1111", "X") == "**** **** **** 1111"
        assert Mask(keep_first=2, keep_last=2).apply("ABCDEFGH", "X") == "AB****GH"
        assert Mask(char="#").apply("ab", "X") == "##"

    def test_never_reveals_more_than_half(self):
        assert Mask(keep_last=10).apply("1234", "X") == "**34"
        assert Mask(keep_first=10, keep_last=10).apply("123456", "X") == "123***"
        assert Mask(keep_last=4).apply("7", "X") == "*"

    def test_arguments(self):
        with pytest.raises(ValueError, match="single"):
            Mask(char="**")
        with pytest.raises(ValueError, match="negative"):
            Mask(keep_last=-1)


class TestHash:
    key = "0123456789abcdef0123456789abcdef"

    def test_deterministic_and_keyed(self):
        a = Hash(self.key).apply("jane@example.com", "EMAIL")
        assert a == Hash(self.key).apply("jane@example.com", "EMAIL")
        assert a != Hash("another-key-of-enough-length").apply("jane@example.com", "EMAIL")
        assert a.startswith("[EMAIL:") and len(a) == len("[EMAIL:]") + 16

    def test_entity_separates_equal_values(self):
        op = Hash(self.key)
        assert op.apply("123456789", "US_SSN") != op.apply("123456789", "NL_BSN")

    def test_canonicalisation(self):
        op = Hash(self.key)
        assert op.apply("Jane@Example.com ", "EMAIL") == op.apply("jane@example.com", "EMAIL")
        raw = Hash(self.key, canonicalize=False)
        assert raw.apply("Jane@Example.com", "EMAIL") != raw.apply("jane@example.com", "EMAIL")

    def test_value_is_not_in_the_output(self):
        assert "jane" not in Hash(self.key).apply("jane@example.com", "EMAIL")

    def test_rejects_weak_settings(self):
        with pytest.raises(ValueError, match="16 bytes"):
            Hash("short")
        with pytest.raises(ValueError, match="length"):
            Hash(self.key, length=4)


class TestTokenize:
    def test_consistent_tokens_and_restore(self):
        vault = Vault()
        op = Tokenize(vault)
        assert op.apply("a@example.com", "EMAIL") == "[EMAIL_1]"
        assert op.apply("b@example.com", "EMAIL") == "[EMAIL_2]"
        assert op.apply("a@example.com", "EMAIL") == "[EMAIL_1]"
        assert op.apply("078-05-1120", "US_SSN") == "[US_SSN_1]"
        assert len(vault) == 3
        assert vault.restore("to [EMAIL_2], ssn [US_SSN_1], [EMAIL_9]") == (
            "to b@example.com, ssn 078-05-1120, [EMAIL_9]"
        )

    def test_vault_repr_hides_values(self):
        vault = Vault()
        vault.token_for("a@example.com", "EMAIL")
        assert "example" not in repr(vault)

    def test_concurrent_use_gives_unique_tokens(self):
        vault = Vault()
        values = [f"user{i}@example.com" for i in range(200)]

        def work():
            for value in values:
                vault.token_for(value, "EMAIL")

        threads = [threading.Thread(target=work) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        assert len(vault) == 200
        assert len({vault.token_for(value, "EMAIL") for value in values}) == 200


def test_drop_and_keep():
    assert Drop().apply("x", "EMAIL") == ""
    assert Keep().apply("x", "EMAIL") == "x"
