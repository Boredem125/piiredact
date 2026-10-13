"""Named-entity detection through spaCy. Needs the ``ner`` extra.

Regexes cannot find names, street addresses or organisations in free text.
This detector covers them, at the cost of a model download and slower runs::

    pip install "depii[ner]"
    python -m spacy download en_core_web_sm

    from depii import Redactor
    from depii.detectors.ner import SpacyDetector

    redactor = Redactor(detectors=[SpacyDetector()])
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from typing import Any

from ..types import LOCATION, ORGANIZATION, PERSON, Span

DEFAULT_LABELS: Mapping[str, str] = {
    "PERSON": PERSON,
    "PER": PERSON,
    "GPE": LOCATION,
    "LOC": LOCATION,
    "FAC": LOCATION,
    "ORG": ORGANIZATION,
}


class SpacyDetector:
    """Emit PERSON, LOCATION and ORGANIZATION spans from a spaCy pipeline.

    ``model``  name of an installed spaCy model.
    ``nlp``    an already loaded pipeline; overrides ``model``.
    ``labels`` spaCy label -> entity type. Labels not listed are ignored.
    ``score``  score given to every span. spaCy does not expose a per-entity
               confidence, so this is a fixed value.
    """

    name = "spacy"
    entity = "*"

    def __init__(
        self,
        model: str = "en_core_web_sm",
        *,
        nlp: Any = None,
        labels: Mapping[str, str] = DEFAULT_LABELS,
        score: float = 0.6,
    ) -> None:
        if nlp is None:
            try:
                import spacy
            except ImportError as error:
                raise ImportError('SpacyDetector needs spaCy: pip install "depii[ner]"') from error
            try:
                nlp = spacy.load(model)
            except OSError as error:
                raise OSError(
                    f"spaCy model {model!r} is not installed: python -m spacy download {model}"
                ) from error
        self._nlp = nlp
        self._labels = dict(labels)
        self.score = score

    def detect(self, text: str, *, strict: bool = False) -> Iterator[Span]:
        for ent in self._nlp(text).ents:
            entity = self._labels.get(ent.label_)
            if entity is not None:
                yield Span(ent.start_char, ent.end_char, entity, ent.text, self.score, self.name)
