"""Values recognised by their label: "Email: ...", JSON keys, table columns."""

import pytest

import depii
from depii.detectors.labels import entity_for_label


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # the label decides, whatever the value looks like
        ("email: a@gmail.com", "email: [EMAIL]"),
        ("Email: jane at example dot com", "Email: [EMAIL]"),
        ("E-Mail ID: priya at gmail dot com", "E-Mail ID: [EMAIL]"),
        ("Mobile: 98765-43210 (after 6pm)", "Mobile: [PHONE] (after 6pm)"),
        ("Name: john smith, Age: 42", "Name: [PERSON], Age: 42"),
        ("Father's Name: Ram Prasad", "Father's Name: [PERSON]"),
        ("Patient: Ana de la Cruz was admitted", "Patient: [PERSON] was admitted"),
        ("Contact Person: Dr. R. Iyer from Chennai", "Contact Person: [PERSON] from Chennai"),
        ("Name: J. R. Smith. Next line", "Name: [PERSON]. Next line"),
        ("Company Name: Acme Pvt Ltd; ok", "Company Name: [ORGANIZATION]; ok"),
        ("DOB: 3 March 1985", "DOB: [DATE_OF_BIRTH]"),
        (
            "Address: Flat 4, 12 High St, Leeds LS1 4AB, Phone: 0113 496 0000",
            "Address: [LOCATION], Phone: [PHONE]",
        ),
        ("Passport No: Z1234567", "Passport No: [PASSPORT]"),
        ("username: rkumar", "username: [USERNAME]"),
        # natural language
        ("My name is Priya Sharma and I live at 42 MG Road, Pune.",
         "My name is [PERSON] and I live at [LOCATION]."),
        ("She lives in Leeds and works from home.", "She lives in [LOCATION] and works from home."),
        ("my email is raj at example dot in", "my email is [EMAIL]"),
        # keys in data and code
        ('{"email": "x@y.z", "fullName": "Ana Gómez"}', '{"email": "[EMAIL]", "fullName": "[PERSON]"}'),
        ("user_email=rahul.k@corp.in user_name=rkumar", "user_email=[EMAIL] user_name=[USERNAME]"),
        ("billingAddress: 12 High St", "billingAddress: [LOCATION]"),
    ],
)  # fmt: skip
def test_labelled_values(text, expected):
    assert depii.redact(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "The file name: report.pdf and host name: db01.",
        "Name is required. Address is invalid.",
        "He lives in fear of the dark.",
        "Time: 10:30, Status: OK, Note: call back tomorrow",
        "user_id=48213 session_len=3600 status=OK",
        "email: N/A, phone: none, name: -",
        "Tel-Aviv is a city; name-brand goods",
        "see https://example.com/docs: the guide",
        "ip address: is configured by DHCP",
    ],
)
def test_labels_that_are_not_personal(text):
    assert depii.redact(text) == text


def test_markdown_table_columns():
    table = (
        "| Name | Email | City |\n"
        "|------|-------|------|\n"
        "| Ravi Kumar | ravi@example.in | Pune |\n"
        "| A. Lee | lee at example dot com | Leeds |\n"
    )
    assert depii.redact(table) == (
        "| Name | Email | City |\n"
        "|------|-------|------|\n"
        "| [PERSON] | [EMAIL] | Pune |\n"
        "| [PERSON] | [EMAIL] | Leeds |\n"
    )


def test_tab_separated_columns():
    table = "id\tname\temail\n1\tJane Doe\tjane@example.com\n2\tRaj\traj [at] example.in\n"
    assert depii.redact(table) == "id\tname\temail\n1\t[PERSON]\t[EMAIL]\n2\t[PERSON]\t[EMAIL]\n"


def test_table_without_known_columns_is_left_alone():
    table = "| step | result |\n|---|---|\n| build | ok |\n"
    assert depii.redact(table) == table


def test_shell_pipes_are_not_tables():
    text = "cat users.txt | grep Smith | sort\n"
    assert depii.redact(text) == text


def test_label_redaction_is_idempotent():
    text = "Name: Jane Doe\nEmail: jane at example dot com\n| Name | Phone |\n|--|--|\n| Raj | 98765 43210 |"
    once = depii.redact(text)
    assert depii.redact(once) == once


def test_specific_detector_keeps_its_label():
    (span,) = depii.scan("Phone: 415-555-0132")
    assert span.entity == "PHONE" and span.detector == "phone_nanp"
    (span,) = depii.scan("lives at SW1A 1AA")
    assert span.entity == "GB_POSTCODE"


def test_bearer_scheme_stays_visible():
    assert depii.redact("Authorization: Bearer abcdefghijklmnop1234") == (
        "Authorization: Bearer [SECRET]"
    )


@pytest.mark.parametrize(
    ("label", "entity"),
    [
        ("E-mail", "EMAIL"),
        ("Date_of_Birth", "DATE_OF_BIRTH"),
        ("phoneNumber", "PHONE"),
        ("file name", None),
        ("Status", None),
    ],
)
def test_entity_for_label(label, entity):
    assert entity_for_label(label) == entity


def test_label_entities_are_listed_and_policies_still_checked():
    assert {"PERSON", "LOCATION", "USERNAME"} <= set(depii.supported_entities())
    with pytest.warns(UserWarning, match="CREDITCARD"):
        depii.Redactor(policy={"CREDITCARD": depii.Mask()})
