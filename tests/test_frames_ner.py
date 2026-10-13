from types import SimpleNamespace

import pytest

from piiredact import Mask, Redactor
from piiredact.detectors.ner import SpacyDetector

pd = pytest.importorskip("pandas")

from piiredact.frames import redact_dataframe  # noqa: E402


class TestDataFrame:
    def frame(self):
        return pd.DataFrame(
            {
                "id": [1, 2, 3],
                "note": ["mail jane@example.com", None, "ip 203.0.113.9"],
                "phone": [5550132, 5550133, 5550132],
                "email": ["a@example.com", "", "b@example.com"],
                "score": [0.5, 0.7, float("nan")],
                "meta": [{"password": "x1y2z3"}, ["jane@example.com"], None],
            }
        )

    def test_text_columns_and_hints(self):
        frame = self.frame()
        out = redact_dataframe(frame)
        assert out["id"].tolist() == [1, 2, 3]
        assert out["note"][0] == "mail [EMAIL]" and out["note"][2] == "ip [IP_ADDRESS]"
        assert pd.isna(out["note"][1])
        assert out["phone"].tolist() == ["[PHONE]"] * 3
        assert out["email"].tolist() == ["[EMAIL]", "", "[EMAIL]"]
        assert out["score"][0] == 0.5
        assert out["meta"][0] == {"password": "[SECRET]"}
        assert out["meta"][1] == ["[EMAIL]"]

    def test_input_frame_is_not_modified(self):
        frame = self.frame()
        redact_dataframe(frame)
        assert frame["note"][0] == "mail jane@example.com"
        assert frame["phone"].tolist() == [5550132, 5550133, 5550132]

    def test_columns_and_hints_options(self):
        frame = self.frame()
        out = redact_dataframe(frame, columns=["note"])
        assert out["email"].tolist() == frame["email"].tolist()
        out = redact_dataframe(frame, key_hints=False)
        assert out["phone"].tolist() == [5550132, 5550133, 5550132]
        assert out["email"].tolist() == ["[EMAIL]", "", "[EMAIL]"]

    def test_custom_redactor(self):
        out = redact_dataframe(
            pd.DataFrame({"card": ["4111 1111 1111 1111"]}),
            Redactor(default_operator=Mask(keep_last=4)),
        )
        assert out["card"][0] == "**** **** **** 1111"


class FakeNlp:
    """Stands in for a spaCy pipeline: tags fixed strings."""

    known = {"Jane Smith": "PERSON", "Leeds": "GPE", "Acme Ltd": "ORG", "Tuesday": "DATE"}

    def __call__(self, text):
        ents = []
        for value, label in self.known.items():
            start = text.find(value)
            if start >= 0:
                ents.append(
                    SimpleNamespace(
                        start_char=start, end_char=start + len(value), label_=label, text=value
                    )
                )
        return SimpleNamespace(ents=ents)


class TestNer:
    text = "Jane Smith of Acme Ltd, Leeds, wrote on Tuesday from jane@example.com"

    def test_maps_labels_and_ignores_others(self):
        redactor = Redactor(detectors=[SpacyDetector(nlp=FakeNlp())])
        assert redactor.redact(self.text).text == (
            "[PERSON] of [ORGANIZATION], [LOCATION], wrote on Tuesday from [EMAIL]"
        )

    def test_entity_filters_apply_to_ner_spans(self):
        detector = SpacyDetector(nlp=FakeNlp())
        only = Redactor(detectors=[detector], entities=["PERSON"])
        assert only.redact(self.text).text.startswith("[PERSON] of Acme Ltd, Leeds")
        without = Redactor(detectors=[detector], exclude_entities=["ORGANIZATION"])
        assert "Acme Ltd" in without.redact(self.text).text

    def test_score_threshold(self):
        weak = SpacyDetector(nlp=FakeNlp(), score=0.2)
        assert "Jane Smith" in Redactor(detectors=[weak]).redact(self.text).text

    def test_offsets_survive_normalisation(self):
        redactor = Redactor(detectors=[SpacyDetector(nlp=FakeNlp())])
        text = "é​ Jane Smith"
        assert redactor.redact(text).text == "é​ [PERSON]"

    def test_missing_spacy_gives_install_hint(self, monkeypatch):
        import builtins

        real_import = builtins.__import__

        def fake_import(name, *args, **kwargs):
            if name == "spacy":
                raise ImportError("no spacy")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)
        with pytest.raises(ImportError, match=r"piiredact\[ner\]"):
            SpacyDetector()
