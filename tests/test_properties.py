"""Property tests: invariants that must hold for any input."""

import random

from hypothesis import given, settings
from hypothesis import strategies as st

import synth
from depii import Keep, Redactor

REDACTOR = Redactor()
STRICT = Redactor(strict=True)
KEEP_ALL = Redactor(default_operator=Keep())

# Kinds that are detected on shape alone, wherever they appear.
SELF_EVIDENT = [kind for kind in synth.KINDS if kind.entity not in {"NL_BSN", "GB_NHS_NUMBER"}]

FILLER = st.sampled_from(
    ["the", "order", "and", "sent", "to", "on", "Monday", "ref", "x", "ok", "über", "—", "注文"]
)
SEPARATOR = st.sampled_from(
    [" ", ", ", "; ", "\n", " | ", ": ", " (", ") ", ". ", "? ", "! ", "' ", '" ', "] ", " [",
     "- ", " -", "/ ", "… ", "\t", " = ", "> ", " <", ".\n", ":\n", "。", " "]
)  # fmt: skip


@st.composite
def planted_text(draw):
    """Text built from filler words with generated PII values planted in it."""
    rng = random.Random(draw(st.integers(0, 2**32)))
    parts: list[str] = []
    planted: list[str] = []
    for _ in range(draw(st.integers(1, 8))):
        if draw(st.booleans()):
            value = draw(st.sampled_from(SELF_EVIDENT)).make(rng)
            planted.append(value)
            parts.append(value)
        else:
            parts.append(draw(FILLER))
        parts.append(draw(SEPARATOR))
    return "".join(parts), planted


@given(planted_text())
@settings(max_examples=300, deadline=None)
def test_planted_values_do_not_survive(case):
    text, planted = case
    out = REDACTOR.redact(text).text
    for value in planted:
        assert value not in out


@given(planted_text())
@settings(max_examples=300, deadline=None)
def test_redaction_is_idempotent(case):
    text, _ = case
    once = REDACTOR.redact(text).text
    assert REDACTOR.redact(once).text == once


@given(st.text(max_size=300))
@settings(max_examples=500, deadline=None)
def test_spans_are_valid_for_any_text(text):
    for redactor in (REDACTOR, STRICT):
        spans = redactor.scan(text)
        previous_end = 0
        for span in spans:
            assert 0 <= span.start < span.end <= len(text)
            assert span.start >= previous_end
            assert text[span.start : span.end] == span.text
            assert 0.0 < span.score <= 1.0
            previous_end = span.end


@given(st.text(max_size=300))
@settings(max_examples=300, deadline=None)
def test_text_outside_spans_is_preserved(text):
    result = REDACTOR.redact(text)
    rebuilt = []
    position = 0
    for span in result.spans:
        rebuilt.append(text[position : span.start])
        rebuilt.append(f"[{span.entity}]")
        position = span.end
    rebuilt.append(text[position:])
    assert "".join(rebuilt) == result.text
    assert KEEP_ALL.redact(text).text == text


@given(
    st.recursive(
        st.none()
        | st.booleans()
        | st.integers()
        | st.floats(allow_nan=False)
        | st.text(max_size=40),
        lambda children: (
            st.lists(children, max_size=4)
            | st.dictionaries(st.text(max_size=12), children, max_size=4)
        ),
        max_leaves=20,
    )
)
@settings(max_examples=200, deadline=None)
def test_redact_obj_keeps_the_shape(data):
    out = REDACTOR.redact_obj(data, key_hints=False)

    def same_shape(a, b):
        if isinstance(a, dict):
            return (
                isinstance(b, dict)
                and a.keys() == b.keys()
                and all(same_shape(a[k], b[k]) for k in a)
            )
        if isinstance(a, list):
            return isinstance(b, list) and len(a) == len(b) and all(map(same_shape, a, b))
        if isinstance(a, str):
            return isinstance(b, str)
        return a == b

    assert same_shape(data, out)
