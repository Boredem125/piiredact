"""Regression gate on detection quality, measured on the synthetic corpus.

The corpus is generated, so these numbers show that detectors and validators
agree with the formats they claim to support. They do not predict recall on
real-world text.
"""

import pytest

import synth
from depii import Redactor

SAMPLES = synth.corpus(seed=7, per_kind=60)
SCORES = synth.evaluate(Redactor().scan, SAMPLES)


def test_corpus_covers_every_kind():
    assert {kind.entity for kind in synth.KINDS} <= set(SCORES)


@pytest.mark.parametrize("entity", sorted({kind.entity for kind in synth.KINDS}))
def test_recall(entity):
    score = SCORES[entity]
    assert score.recall >= 0.98, f"{entity}: recall {score.recall:.3f} of {score.planted}"
    assert score.coverage >= 0.98


@pytest.mark.parametrize("entity", sorted(SCORES))
def test_precision(entity):
    score = SCORES[entity]
    assert score.precision >= 0.95, f"{entity}: precision {score.precision:.3f}"


def test_negatives_are_left_alone():
    redactor = Redactor()
    flagged = {text: redactor.scan(text) for text in synth.NEGATIVES}
    assert {text: spans for text, spans in flagged.items() if spans} == {}


def test_corpus_is_reproducible():
    assert synth.corpus(seed=7, per_kind=5) == synth.corpus(seed=7, per_kind=5)
