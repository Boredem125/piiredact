from collections import namedtuple

import pytest

import depii
from depii import Mask, Redactor
from depii.structured import entity_for_key, redact_obj


@pytest.mark.parametrize(
    ("key", "entity"),
    [
        ("email", "EMAIL"),
        ("userEmail", "EMAIL"),
        ("USER-EMAIL", "EMAIL"),
        ("customer.phone_number", "PHONE"),
        ("password", "SECRET"),
        ("dbPassword", "SECRET"),
        ("X-Api-Key", "SECRET"),
        ("ssn", "US_SSN"),
        ("first_name", "PERSON"),
        ("billingAddress", "LOCATION"),
        ("ip_address", "IP_ADDRESS"),
        ("clientIp", "IP_ADDRESS"),
        ("name", None),
        ("zip", None),
        ("token_count", None),
        ("is_email_verified", None),
        ("description", None),
        (42, None),
        ("", None),
    ],
)
def test_entity_for_key(key, entity):
    assert entity_for_key(key) == entity


def test_nested_structure():
    data = {
        "id": 7,
        "note": "call jane@example.com",
        "user": {"firstName": "Jane", "password": "hunter2", "age": 41, "active": True},
        "tags": ["vip", "203.0.113.9"],
        "pair": ("x", "078-05-1120"),
        "none": None,
    }
    assert depii.redact_obj(data) == {
        "id": 7,
        "note": "call [EMAIL]",
        "user": {"firstName": "[PERSON]", "password": "[SECRET]", "age": 41, "active": True},
        "tags": ["vip", "[IP_ADDRESS]"],
        "pair": ("x", "[US_SSN]"),
        "none": None,
    }


def test_input_is_not_modified():
    data = {"emails": ["jane@example.com"], "user": {"password": "hunter2"}}
    depii.redact_obj(data)
    assert data == {"emails": ["jane@example.com"], "user": {"password": "hunter2"}}


def test_hint_redacts_values_that_do_not_look_like_pii():
    assert depii.redact_obj({"phone": 9876543210, "ssn": "n/a", "dob": 19900102}) == {
        "phone": "[PHONE]",
        "ssn": "[US_SSN]",
        "dob": "[DATE_OF_BIRTH]",
    }


def test_hint_carries_into_children():
    data = {"address": {"line1": "12 High St", "city": "Leeds"}, "phone": ["111", "222"]}
    assert depii.redact_obj(data) == {
        "address": {"line1": "[LOCATION]", "city": "[LOCATION]"},
        "phone": ["[PHONE]", "[PHONE]"],
    }


def test_hint_leaves_empty_none_and_bool():
    data = {"email": "", "phone": None, "mobile": True}
    assert depii.redact_obj(data) == data


def test_key_hints_can_be_disabled():
    assert depii.redact_obj({"password": "hunter2"}, key_hints=False) == {"password": "hunter2"}


def test_hints_use_the_policy():
    redactor = Redactor(policy={"PHONE": Mask(keep_last=2)})
    assert redactor.redact_obj({"phone": "555-0132"}) == {"phone": "***-**32"}


def test_redact_keys():
    data = {"jane@example.com": 1}
    assert depii.redact_obj(data) == data
    assert depii.redact_obj(data, redact_keys=True) == {"[EMAIL]": 1}


def test_scan_numbers():
    data = {"n": 4111111111111111, "m": 12}
    assert depii.redact_obj(data) == data
    assert depii.redact_obj(data, scan_numbers=True) == {"n": "[CREDIT_CARD]", "m": 12}


def test_bytes_sets_and_namedtuples():
    Point = namedtuple("Point", "label mail")
    out = depii.redact_obj(
        {"b": b"jane@example.com", "s": {"jane@example.com"}, "p": Point("x", "jane@example.com")}
    )
    assert out["b"] == b"[EMAIL]"
    assert out["s"] == {"[EMAIL]"}
    assert out["p"] == Point("x", "[EMAIL]")
    assert depii.redact_obj(b"\xff\xfe") == b"\xff\xfe"


def test_cycles_and_shared_references():
    shared = ["jane@example.com"]
    data: dict = {"a": shared, "b": shared}
    data["self"] = data
    out = depii.redact_obj(data)
    assert out["a"] == ["[EMAIL]"]
    assert out["a"] is out["b"]
    assert out["self"] is out


def test_too_deep_raises_instead_of_leaking():
    deep: list = ["jane@example.com"]
    for _ in range(150):
        deep = [deep]
    with pytest.raises(ValueError, match="max_depth"):
        depii.redact_obj(deep)
    assert redact_obj([["jane@example.com"]], Redactor(), max_depth=5) == [["[EMAIL]"]]


def test_unknown_objects_pass_through():
    marker = object()
    assert depii.redact_obj({"x": marker})["x"] is marker
