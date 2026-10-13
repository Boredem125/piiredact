import threading

import pytest

import piiredact
from piiredact import Drop, Hash, Keep, Mask, PatternDetector, Redactor, Replace, Tokenize, Vault


def test_readme_example():
    assert piiredact.redact("Mail jane@example.com") == "Mail [EMAIL]"


def test_result_fields():
    result = Redactor().redact("a@example.com b@example.com 203.0.113.9")
    assert result.text == "[EMAIL] [EMAIL] [IP_ADDRESS]"
    assert result.stats == {"EMAIL": 2, "IP_ADDRESS": 1}
    assert [span.start for span in result.spans] == sorted(span.start for span in result.spans)
    assert bool(result)
    assert not Redactor().redact("nothing here")


def test_span_repr_does_not_leak_the_value():
    (span,) = piiredact.scan("jane@example.com")
    assert "jane" not in repr(span)
    assert span.text == "jane@example.com"


def test_empty_and_non_string_input():
    assert piiredact.redact("") == ""
    assert piiredact.scan("") == []
    with pytest.raises(TypeError):
        piiredact.redact(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        piiredact.redact(b"jane@example.com")  # type: ignore[arg-type]


def test_spans_never_overlap():
    text = "https://u:p@example.com/x?mail=jane@example.com 27AAPFU0939F1ZV 415-555-0132"
    spans = piiredact.scan(text, strict=True)
    for left, right in zip(spans, spans[1:], strict=False):
        assert left.end <= right.start


def test_higher_score_wins_an_overlap():
    low = PatternDetector("LOW", r"\d{4}-\d{4}", score=0.6)
    high = PatternDetector("HIGH", r"\d{4}", score=0.9)
    spans = Redactor(locales=[], detectors=[low, high]).scan("id 1234-5678")
    assert [(s.entity, s.text) for s in spans] == [("HIGH", "1234"), ("HIGH", "5678")]


def test_longer_span_wins_a_tie():
    short = PatternDetector("SHORT", r"\d{4}", score=0.8)
    long = PatternDetector("LONG", r"\d{4}-\d{4}", score=0.8)
    spans = Redactor(locales=[], detectors=[short, long]).scan("id 1234-5678")
    assert [(s.entity, s.text) for s in spans] == [("LONG", "1234-5678")]


class TestPolicy:
    text = "jane@example.com paid with 4111 1111 1111 1111"

    def test_per_entity_operator(self):
        redactor = Redactor(policy={"CREDIT_CARD": Mask(keep_last=4)})
        assert redactor.redact(self.text).text == "[EMAIL] paid with **** **** **** 1111"

    def test_default_operator(self):
        redactor = Redactor(default_operator=Replace("<{entity}>"))
        assert redactor.redact(self.text).text == "<EMAIL> paid with <CREDIT_CARD>"

    def test_keep_leaves_value_and_reports_nothing(self):
        result = Redactor(policy={"EMAIL": Keep()}).redact(self.text)
        assert result.text == "jane@example.com paid with [CREDIT_CARD]"
        assert result.stats == {"CREDIT_CARD": 1}

    def test_drop(self):
        assert Redactor(default_operator=Drop()).redact(self.text).text == " paid with "

    def test_entities_and_exclude(self):
        assert Redactor(entities=["EMAIL"]).redact(self.text).text == (
            "[EMAIL] paid with 4111 1111 1111 1111"
        )
        assert Redactor(exclude_entities=["EMAIL"]).redact(self.text).text == (
            "jane@example.com paid with [CREDIT_CARD]"
        )

    def test_allow_list_is_case_insensitive(self):
        redactor = Redactor(allow=["Support@Example.com"])
        assert redactor.redact("support@example.com or jane@example.com").text == (
            "support@example.com or [EMAIL]"
        )

    def test_unknown_entity_name_warns(self):
        with pytest.warns(UserWarning, match="CREDITCARD"):
            Redactor(policy={"CREDITCARD": Mask()})

    def test_operator_must_have_apply(self):
        with pytest.raises(TypeError):
            Redactor(policy={"EMAIL": "***"})  # type: ignore[dict-item]

    def test_min_score_range(self):
        with pytest.raises(ValueError, match="min_score"):
            Redactor(min_score=1.5)


class TestIdempotence:
    def test_placeholder_is_not_read_as_a_context_word(self):
        # "[PHONE]" contains the word "phone"; it must not make the bare
        # number next to it look like a phone number on a second pass.
        text = "+1 415 555 0132 or 4155550199"
        once = piiredact.redact(text)
        assert once == "[PHONE] or 4155550199"
        assert piiredact.redact(once) == once

    @pytest.mark.parametrize(
        "text",
        [
            "jane@example.com, 4111 1111 1111 1111, SSN 078-05-1120",
            "password=hunter2secret",
            "IMEI 490154203237518 then 490154203237518",
            "phone 4155550132 4155550132",
        ],
    )
    def test_second_pass_changes_nothing(self, text):
        once = piiredact.redact(text)
        assert piiredact.redact(once) == once

    def test_tokens_are_not_context_either(self):
        redactor = Redactor(default_operator=Tokenize(Vault()))
        once = redactor.redact("+1 415 555 0132 or 4155550199").text
        assert once == "[PHONE_1] or 4155550199"
        assert redactor.redact(once).text == once


def test_hash_operator_end_to_end():
    redactor = Redactor(default_operator=Hash("k" * 32))
    out = redactor.redact("Jane@Example.com wrote; jane@example.com replied").text
    first, second = (part.split("]")[0] for part in out.split("[")[1:])
    assert first == second and first.startswith("EMAIL:")


def test_redactor_is_thread_safe():
    redactor = Redactor()
    text = "jane@example.com 4111 1111 1111 1111 078-05-1120 " * 20
    expected = redactor.redact(text).text
    results: list[str] = []

    def work():
        for _ in range(20):
            results.append(redactor.redact(text).text)

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 160 and set(results) == {expected}


def test_custom_detector_with_context_and_trim():
    detector = PatternDetector(
        "EMPLOYEE_ID",
        r"\bE\d{5}\w*",
        score=0.4,
        context=("employee", "staff"),
        require_context=True,
        trim=lambda value: value[:6],
    )
    redactor = Redactor(locales=[], detectors=[detector])
    assert redactor.redact("part E12345X").text == "part E12345X"
    assert redactor.redact("employee E12345X").text == "employee [EMPLOYEE_ID]X"
    with pytest.raises(ValueError, match="context"):
        PatternDetector("X", r"x", require_context=True)
