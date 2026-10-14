"""Reversible pseudonyms: mask for an AI, map the answer back."""

import json
import threading

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from depii import Pseudonymizer, Redactor
from depii.cli import main
from depii.pseudonym import noun_for


@pytest.fixture
def p():
    return Pseudonymizer()


def test_round_trip(p):
    masked = p.mask("Aryan asked Ravan to email aryan@example.com")
    assert masked == "Person A asked Person B to email Email A"
    assert p.unmask("Person A should wait for Person B's reply.") == (
        "Aryan should wait for Ravan's reply."
    )
    assert p.table == {"Person A": "Aryan", "Person B": "Ravan", "Email A": "aryan@example.com"}


def test_labels_last_for_the_whole_conversation(p):
    p.mask("Aryan asked Ravan.")
    assert p.mask("Ravan replied to ARYAN.") == "Person B replied to Person A."
    assert p.mask("Phone 98765 43210, again 98765-43210") == "Phone Phone A, again Phone A"


def test_name_parts_share_the_full_names_label(p):
    assert p.mask("Jane Doe called. Ms Doe will return; Jane agreed.") == (
        "Person A called. Ms Person A will return; Person A agreed."
    )
    assert p.unmask("Ms Person A") == "Ms Jane Doe"


@pytest.mark.parametrize(
    ("reply", "expected"),
    [
        ("PERSON A agreed", "Aryan agreed"),
        ("person-A and Person_B", "Aryan and Ravan"),
        ("[Person A] and **Person B**", "Aryan and Ravan"),
        ("The lead (Person A) agreed.", "The lead (Aryan) agreed."),
        ("Person A's turn", "Aryan's turn"),
        ("a person a day", "a person a day"),
        ("Person AB and Person Z", "Person AB and Person Z"),
    ],
)
def test_unmask_tolerates_what_the_ai_does(p, reply, expected):
    p.mask("Aryan asked Ravan.")
    assert p.unmask(reply) == expected


def test_unknown_labels_are_reported(p):
    p.mask("Aryan asked Ravan.")
    assert p.unknown_labels("Person C, Person A, Email Z, Person C") == ["Person C", "Email Z"]


def test_labels_already_in_the_input_are_skipped(p):
    masked = p.mask("Person A is a role name here. Aryan asked Ravan.")
    assert masked == "Person A is a role name here. Person B asked Person C."
    assert p.unmask(masked) == "Person A is a role name here. Aryan asked Ravan."


def test_masking_twice_changes_nothing(p):
    once = p.mask("Aryan asked Ravan to email aryan@example.com, Name: Meera Iyer")
    assert p.mask(once) == once


def test_instructions_contain_no_label(p):
    assert p.mask(p.instructions) == p.instructions
    assert p.unknown_labels(p.instructions) == []


def test_chat_messages_and_tool_calls(p):
    messages = [
        {"role": "system", "content": p.instructions},
        {"role": "user", "content": "Call Kwame Mensah on +91 98765 43210"},
        {
            "role": "assistant",
            "content": [
                {"type": "text", "text": "Calling Kwame Mensah."},
                {"type": "tool_use", "id": "t1", "name": "send_sms",
                 "input": {"to": "+91 98765 43210", "name": "Kwame Mensah"}},
            ],
        },
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": "Sent to Kwame Mensah"},
        ]},
        {"role": "assistant", "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "lookup", "arguments": '{"email": "kwame@example.com"}'}},
        ]},
    ]  # fmt: skip
    masked = p.mask_messages(messages)
    assert masked[0] == messages[0]
    assert masked[1]["content"] == "Call Person A on Phone A"
    assert masked[2]["content"][0]["text"] == "Calling Person A."
    assert masked[2]["content"][1]["input"] == {"to": "Phone A", "name": "Person A"}
    assert masked[2]["content"][1]["name"] == "send_sms"
    assert masked[3]["content"][0]["content"] == "Sent to Person A"
    assert json.loads(masked[4]["tool_calls"][0]["function"]["arguments"]) == {"email": "Email A"}
    assert messages[1]["content"].startswith("Call Kwame")  # input untouched


def test_objects_both_ways(p):
    masked = p.mask_obj({"phone": 9876543210, "note": "met Aryan", "tags": ["Ravan said hi"]})
    assert masked == {"phone": "Phone A", "note": "met Person A", "tags": ["Person B said hi"]}
    reply = {"summary": "Person A owes Person B", "contacts": {"Person A": "Phone A"}}
    assert p.unmask_obj(reply) == {
        "summary": "Aryan owes Ravan",
        "contacts": {"Aryan": "9876543210"},
    }


@given(st.lists(st.integers(min_value=1, max_value=79), max_size=10))
@settings(max_examples=300, deadline=None)
def test_streaming_matches_whole_unmasking(cuts):
    p = Pseudonymizer()
    p.mask("Aryan asked Ravan to email aryan@example.com")
    reply = "Person A thanked **Person B**. Email A works; Person AB is new. person a."
    points = sorted({c for c in cuts if c < len(reply)})
    parts = [reply[i:j] for i, j in zip([0, *points], [*points, len(reply)], strict=True)]
    assert "".join(p.unmask_stream(parts)) == p.unmask(reply)


def test_save_and_load(tmp_path, p):
    p.mask("Person A is taken. Aryan asked Ravan.")
    path = tmp_path / "table.json"
    p.save(path)
    loaded = Pseudonymizer.load(path)
    assert loaded.table == p.table
    assert loaded.unmask("Person B and Person C") == "Aryan and Ravan"
    # New values continue the sequence instead of reusing labels.
    assert loaded.mask("Meera Iyer joined") == "Person D joined"
    with pytest.raises(ValueError, match="version"):
        Pseudonymizer.from_json('{"version": 99, "entries": []}')


def test_custom_redactor(p):
    p = Pseudonymizer(Redactor(entities=["EMAIL"]))
    assert p.mask("Aryan: aryan@example.com") == "Aryan: Email A"


def test_nouns():
    assert noun_for("PERSON") == "Person"
    assert noun_for("BR_CPF") == "CPF"
    assert noun_for("GB_NHS_NUMBER") == "NHS number"
    assert noun_for("SE_PERSONNUMMER") == "Personnummer"


def test_many_people_get_double_letters(p):
    labels = [p.label_for(f"Name{i}", "PERSON") for i in range(28)]
    assert labels[0] == "Person A" and labels[25] == "Person Z" and labels[26] == "Person AA"
    assert p.unmask("Person AA") == "Name26"


def test_concurrent_masking_gives_one_label_per_value():
    p = Pseudonymizer()
    names = [f"Value{i}" for i in range(100)]

    def work():
        for name in names:
            p.label_for(name, "PERSON")

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(p.table) == 100
    assert len(set(p.table)) == 100


def test_cli_round_trip(tmp_path, capsys):
    source = tmp_path / "in.txt"
    source.write_text("Aryan asked Ravan.\n", encoding="utf-8")
    table = tmp_path / "t.json"
    masked = tmp_path / "masked.txt"
    assert main(["mask", str(source), "--table", str(table), "-o", str(masked)]) == 0
    assert masked.read_text(encoding="utf-8") == "Person A asked Person B.\n"
    reply = tmp_path / "reply.txt"
    reply.write_text("Person B thanked Person A. Person Q too.\n", encoding="utf-8")
    out = tmp_path / "out.txt"
    assert main(["unmask", str(reply), "--table", str(table), "-o", str(out)]) == 0
    assert out.read_text(encoding="utf-8") == "Ravan thanked Aryan. Person Q too.\n"
    assert "Person Q" in capsys.readouterr().err


@given(st.data())
@settings(max_examples=150, deadline=None)
def test_unmask_restores_the_original(data):
    """Masking then unmasking gives back the text, for any mix of planted values."""
    import random

    import synth

    rng = random.Random(data.draw(st.integers(0, 2**32)))
    kinds = [kind for kind in synth.KINDS if not kind.needs_context]
    parts = []
    for _ in range(data.draw(st.integers(1, 6))):
        if data.draw(st.booleans()):
            parts.append(rng.choice(kinds).make(rng))
        else:
            parts.append(data.draw(st.sampled_from(["the", "sent to", "and", "ref", "ok"])))
    text = " ; ".join(parts)
    p = Pseudonymizer()
    masked = p.mask(text)
    assert p.unmask(masked) == text
