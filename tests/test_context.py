"""Contextual detection: names, addresses, linking and identifying combinations."""

import pytest

import depii
from depii import Hash, Redactor, Tokenize, Vault


class TestNames:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("Priya Sharma called about the invoice.", "[PERSON] called about the invoice."),
            ("Kavya Sharma joined.", "[PERSON] joined."),  # unknown given name, known surname
            ("Priya Venkataraman joined.", "[PERSON] joined."),  # known given name, unknown surname
            ("José García llamó.", "[PERSON] llamó."),  # accents ignored for lookup
            ("Dr. R. Iyer from Chennai", "Dr. [PERSON] from Chennai"),
            ("Mrs Okafor agreed.", "Mrs [PERSON] agreed."),
            ("Dear Aanu,\nthanks.", "Dear [PERSON],\nthanks."),
            ("Regards,\nOluwadamilare", "Regards,\n[PERSON]"),
            ("Hello Zephyrine!", "Hello [PERSON]!"),
            ("Smith said the deploy failed.", "[PERSON] said the deploy failed."),
            ("Meeting With Priya Sharma About Budget", "Meeting With [PERSON] About Budget"),
            ("iPhone Smith", "iPhone [PERSON]"),
            ("श्री राम प्रसाद ने फॉर्म भरा।", "श्री [PERSON] ने फॉर्म भरा।"),
        ],
    )
    def test_found(self, text, expected):
        assert depii.redact(text) == expected

    @pytest.mark.parametrize(
        "text",
        [
            "Hi Team, Hello World, Hi there.",
            "Will you send the report in May? Mark it done.",
            "Apollo Hospital, New Delhi, Bank of India",
            "Paris and London are cities; Sydney is in Australia.",
            "Best Buy and Thanks Giving",
            "Dear Sir,",
            "the quick brown fox",
        ],
    )
    def test_left_alone(self, text):
        assert depii.redact(text) == text

    def test_can_be_excluded(self):
        assert Redactor(exclude_entities=["PERSON"]).redact("Priya Sharma").text == "Priya Sharma"


class TestAddresses:
    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("Send it to 221B Baker Street, London.", "Send it to [LOCATION]."),
            ("#12, 5th Cross, Indiranagar, Bengaluru", "[LOCATION]"),
            ("Hauptstraße 5, 10115 Berlin", "[LOCATION]"),
            ("Calle Mayor 3, Madrid", "[LOCATION]"),
            ("12 rue de Rivoli, Paris", "[LOCATION]"),
            ("Write to PO Box 1234.", "Write to [LOCATION]."),
            ("We met at 4 Willow Close, Harrogate.", "We met at [LOCATION]."),
        ],
    )
    def test_found(self, text, expected):
        assert depii.redact(text) == expected

    @pytest.mark.parametrize(
        "text",
        ["Step 2 Click Close to finish", "Version 2 Release Notes", "I bought 3 Apple Pies"],
    )
    def test_left_alone(self, text):
        assert depii.redact(text) == text


class TestPropagation:
    def test_value_found_once_is_redacted_everywhere(self):
        # The second number is too far from the word "SSN" to be found on its own.
        text = (
            "SSN: 078051120 on file. The customer called back later in the week and "
            "confirmed 078051120 by letter."
        )
        assert depii.redact(text) == (
            "SSN: [US_SSN] on file. The customer called back later in the week and "
            "confirmed [US_SSN] by letter."
        )
        unpropagated = Redactor(propagate=False).redact(text).text
        assert "078051120 by letter" in unpropagated

    def test_name_parts_share_one_token(self):
        text = (
            "Patient: Jane Doe.\nMs Doe reported pain. Jane will return Friday.\n"
            "Her brother Kwame Mensah called; Mr Mensah left a number. Kwame said hi."
        )
        out = Redactor(default_operator=Tokenize(Vault())).redact(text).text
        assert out == (
            "Patient: [PERSON_1].\nMs [PERSON_1] reported pain. [PERSON_1] will return Friday.\n"
            "Her brother [PERSON_2] called; Mr [PERSON_2] left a number. [PERSON_2] said hi."
        )

    def test_shared_surname_is_not_linked(self):
        out = Redactor(default_operator=Tokenize(Vault())).redact(
            "Jane Doe and John Doe arrived. Doe left."
        )
        tokens = out.text.split()
        assert tokens[0] != tokens[2]  # two different people
        assert "[PERSON_3]" in out.text  # the lone "Doe" is its own token

    def test_hash_links_too(self):
        out = Redactor(default_operator=Hash("k" * 32)).redact("Kwame Mensah. Mr Mensah.").text
        first, second = out.split("[")[1].split("]")[0], out.split("[")[2].split("]")[0]
        assert first == second


class TestQuasiIdentifiers:
    def test_combination_is_redacted(self):
        text = (
            "The patient is a 42-year-old woman from Pune who works as a nurse at Apollo Hospital."
        )
        assert depii.redact(text) == (
            "The patient is a [AGE] [GENDER] from [CITY] who works as a [OCCUPATION] at "
            "[ORGANIZATION]."
        )

    def test_form_fields(self):
        assert depii.redact("Age: 34, Gender: M, City: Leeds, Occupation: Teacher") == (
            "Age: [AGE], Gender: [GENDER], City: [CITY], Occupation: [OCCUPATION]"
        )

    def test_already_redacted_details_count(self):
        text = "Employee aged 51, software engineer, lives at 12 High St, Leeds."
        assert depii.redact(text) == ("Employee aged [AGE], [OCCUPATION], lives at [LOCATION].")

    @pytest.mark.parametrize(
        "text",
        [
            "A 42-year-old woman attended.",
            "She works as a nurse in Pune.",
            "Age: 34",
            "The age of the system is 12 years.",
            "Nice weather today, said the teacher.",
            "Version 1.2 of Acme Corp's tool shipped in London.",
        ],
    )
    def test_too_few_kinds_are_left_alone(self, text):
        assert depii.redact(text) == text

    def test_threshold_and_switch(self):
        text = "A 42-year-old woman attended."
        assert Redactor(quasi_threshold=2).redact(text).text == "A [AGE] [GENDER] attended."
        busy = "The patient is a 42-year-old woman from Pune who works as a nurse."
        assert Redactor(quasi_threshold=None).redact(busy).text == busy
        with pytest.raises(ValueError, match="quasi_threshold"):
            Redactor(quasi_threshold=1)

    def test_entity_filters_apply(self):
        text = "Age: 34, Gender: M, City: Leeds, Occupation: Teacher"
        out = Redactor(exclude_entities=["CITY"]).redact(text).text
        assert "Leeds" in out and "[AGE]" in out

    def test_quasi_entities_are_listed(self):
        assert {"AGE", "GENDER", "OCCUPATION", "CITY"} <= set(depii.supported_entities())


def test_contextual_redaction_is_idempotent():
    text = (
        "Dear Priya,\nYour colleague Kwame Mensah (42-year-old engineer, Pune) moved to "
        "221B Baker Street, London. Mensah's SSN: 078051120; confirm 078051120."
    )
    once = depii.redact(text)
    assert depii.redact(once) == once
