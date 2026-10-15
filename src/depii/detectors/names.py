"""Person names in free text, found without a language model.

Evidence, strongest first:

* a title before the name: "Dr. Rao", "Mrs Okafor", "Shri Ram Prasad";
* a greeting or sign-off: "Dear Aanu,", "Regards,\\nKwame";
* a known given name or family name next to another capitalised word:
  "Priya Sharma", "Kavya Sharma", "Jane Okafor";
* a known given or family name on its own: "Priya said", "ask Okafor".

Names that are also ordinary words (Will, May, Grace, Paris) need one of
the first three. The name lists ship with the package and are short, so
an unusual name on its own is missed; with a title, a cue or a known name
beside it, it is found.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterator
from functools import cache, lru_cache
from importlib import resources

from ..types import PERSON, Span


@cache
def _words(name: str) -> frozenset[str]:
    text = resources.files("depii.data").joinpath(f"{name}.txt").read_text(encoding="utf-8")
    return frozenset(
        line.strip().lower() for line in text.splitlines() if line.strip() and line[0] != "#"
    )


def first_names() -> frozenset[str]:
    return _words("first_names")


def surnames() -> frozenset[str]:
    return _words("surnames")


def ambiguous() -> frozenset[str]:
    """Names that are also everyday words."""
    return _words("common_words")


# Capitalised words that are never part of a name, though they often start
# a sentence or a heading next to one.
_NOT_NAMES = frozenset(
    """a an the this that these those i we you he she they it my our your his her their its
    me us him them who what when where why how which please kindly contact call email phone
    mail send dear hi hello hey thanks thank regards best cheers sincerely yours kind warm
    from to cc bcc subject re fwd fw date time note notes status order invoice ticket account
    team all everyone folks guys sir madam support customer client patient user admin staff
    manager director doctor nurse officer agent mr mrs ms miss dr prof and or but if then so
    for with without about after before at by in on of as is are was were be been not no yes
    monday tuesday wednesday thursday friday saturday sunday january february march june july
    september october november december today tomorrow yesterday new old north south east west
    street st road rd avenue lane city state country bank hospital university college school
    company department group ltd inc llc pvt limited corp office building floor room block
    phase sector area district province region nation national international global
    meeting report project budget review update summary agenda action item items here there
    hope will may also just only very much more most some any every each other another
    world friends ask tell told met meet see saw called inform informed per via
    """.split()
)

_TITLES = (
    r"Mr|Mrs|Ms|Miss|Mx|Dr|Prof|Professor|Sir|Dame|Lady|Lord|Rev|Fr|Sr|Sra|Srta|Shri|Sri|Smt"
    r"|Kumari|Herr|Frau|Señor|Señora|Señorita|Mme|Mlle|Monsieur|Madame|Dott|Ing|Mag|Hon|Capt"
)
# These patterns do not start with a lookbehind, which would make the regex
# engine try every position; the word boundary before them is checked in code.
_TITLE = re.compile(rf"(?:{_TITLES})\.?\s+", re.UNICODE)
_CUE = re.compile(
    # Longer phrases first, so "Best regards" is not read as "Best" + "Regards".
    r"(?:Kind regards|Best regards|Warm regards|Best wishes|Many thanks|"
    r"Yours truly|Yours sincerely|Thank you|Dear|Hello|Hi|Hey|Thanks|Regards|Cheers|"
    r"Sincerely)[ \t]*,?[ \t]*(?:\r?\n[ \t]*)?",
    re.IGNORECASE,
)


def _plausible_verb_object(text: str, words: list[str], end: int) -> bool:
    """Whether words next to a person verb can be a name rather than code or a term.

    Rules out acronyms ("according to RFC"), code ("call Logger.__init__"),
    adverbs ("Normally said") and, for a single word, everyday words ("asked May").
    """
    if any(len(w) > 1 and w.isupper() for w in words):
        return False
    following = text[end : end + 2]
    if following[:1] == "(" or (
        following[:1] == "." and (following[1:2].isalnum() or following[1:2] == "_")
    ):
        return False
    if any(w.lower().endswith("ly") for w in words):
        return False
    return not (len(words) == 1 and _key(words[0]) in ambiguous())


def _sentence_start(text: str, index: int) -> bool:
    """Whether ``index`` begins a sentence: start of text, a line, or after ". "."""
    before = text[:index].rstrip(" \t")
    return not before or before[-1] in ".!?\n"


def _starts_word(text: str, index: int) -> bool:
    return index == 0 or not (text[index - 1].isalpha() or text[index - 1].isdigit())


_DEVANAGARI_TITLE = re.compile(r"(?:श्री|श्रीमती|कुमारी|डॉ\.?)\s+")
_DEVANAGARI_WORD = re.compile(r"[ऀ-ॿ]+")
# A capitalised word (any script with case), or an initial such as "R.".
_TOKEN = re.compile(r"[A-Z]\.(?=\s)|[^\W\d_]+(?:['’-](?![sS](?![^\W\d_]))[^\W\d_]+)*", re.UNICODE)

# Uppercase letters of the Latin scripts that the name lists are written in.
_UPPER = "A-ZÀ-ÖØ-ÞĀĂĄĆČĎĐĒĘĚĞĪİŁŃŇŌŐŒŘŚŞŠŢŤŪŮŰŹŻŽ"
# A run of capitalised words (or initials) separated by single spaces.
_CAPITALISED_RUN = re.compile(
    rf"[{_UPPER}][^\W\d_]*(?:['’-](?![sS](?![^\W\d_]))[^\W\d_]+)*"
    # The initial comes first, so "J." is not read as the word "J".
    rf"(?: (?:[A-Z]\.(?= )|[{_UPPER}][^\W\d_]*(?:['’-](?![sS](?![^\W\d_]))[^\W\d_]+)*))*"
)

SCORE_TITLE = 0.9
SCORE_CUE = 0.85
SCORE_PAIR = 0.85
SCORE_FIRST_NAME = 0.6
SCORE_SURNAME = 0.5
SCORE_VERB = 0.6

# Verbs that take a person as their object: "asked Ravan", "emailed Meera".
# "call", "email", "message" and "contact" are left out: as nouns they precede
# class names in technical text ("call Logger", "email Parser").
_VERB_BEFORE_NAME = re.compile(
    r"(?:asked|told|called|emailed|messaged|texted|met|thanked|informed|helped|hired|"
    r"paid|invited|contacted|introduced|pinged|cc'd|according to|ask|tell|meet|thank|"
    r"inform|invite|ping)[ \t]+"
)
# Verbs that follow a person as subject: "Ravan said", "Meera replied".
# Only verbs of speech: "Parser wants" or "Version needed" are not people.
_VERB_AFTER_NAME = re.compile(
    r" (?:said|says|asked|asks|told|tells|wrote|writes|replied|replies|emailed|"
    r"agreed|agrees|confirmed|confirms|mentioned|explained|complained|insisted)\b"
)
# Capitalised words before such a verb that are not people.
_NOT_SUBJECTS = frozenset(
    """everyone everybody someone somebody nobody anyone management police government
    company team customer customers client clients user users staff support system it
    this that he she they we i you who which""".split()
)
# The capitalised words right before a verb: "Ravan", "Meera Iyer".
_TRAILING_NAME = re.compile(
    r"(?:[A-ZÀ-ÖØ-Þ][^\W\d_]*(?:['’-](?![sS](?![^\W\d_]))[^\W\d_]+)*|[A-Z]\.)"
    r"(?: (?:[A-ZÀ-ÖØ-Þ][^\W\d_]*(?:['’-](?![sS](?![^\W\d_]))[^\W\d_]+)*|[A-Z]\.)){0,2}$"
)


@lru_cache(maxsize=4096)
def _key(word: str) -> str:
    """Lookup form of a word: lowercase, no accents, no trailing dot ("José" -> "jose")."""
    decomposed = unicodedata.normalize("NFKD", word.lower().rstrip("."))
    return "".join(ch for ch in decomposed if not unicodedata.combining(ch))


def _is_capitalised(word: str) -> bool:
    return word[0].isupper() and not (len(word) > 1 and word.isupper() and len(word) > 3)


def _is_initial(word: str) -> bool:
    return len(word) == 2 and word[1] == "." and word[0].isupper()


def _name_tokens(text: str, start: int, limit: int = 4) -> list[tuple[int, int]]:
    """Capitalised words (or initials) right after ``start``, separated by single spaces."""
    tokens: list[tuple[int, int]] = []
    position = start
    for match in _TOKEN.finditer(text, start):
        if match.start() != position or len(tokens) == limit:
            break
        word = match.group()
        if not (_is_initial(word) or _is_capitalised(word)) or word.lower() in _NOT_NAMES:
            break
        tokens.append(match.span())
        position = match.end()
        if position < len(text) and text[position] == " ":
            position += 1
        else:
            break
    return tokens


class NameDetector:
    """Find person names from titles, greetings and built-in name lists."""

    name = "names"
    entity = "*"
    entities = frozenset({PERSON})

    def detect(self, text: str, *, strict: bool = False) -> Iterator[Span]:
        if text == text.lower() and not _DEVANAGARI_WORD.search(text):
            return  # names are written with capitals, except in caseless scripts
        yield from self._after(text, _TITLE, SCORE_TITLE, "names_title")
        yield from self._after(text, _CUE, SCORE_CUE, "names_greeting")
        yield from self._after(text, _VERB_BEFORE_NAME, SCORE_VERB, "names_verb")
        yield from self._before_verbs(text)
        yield from self._from_lists(text, strict)
        for match in _DEVANAGARI_TITLE.finditer(text):
            words = list(_DEVANAGARI_WORD.finditer(text, match.end(), match.end() + 40))[:2]
            if words and words[0].start() == match.end():
                start, end = words[0].start(), words[-1].end()
                yield Span(start, end, PERSON, text[start:end], SCORE_TITLE, "names_title")

    def _after(
        self, text: str, pattern: re.Pattern[str], score: float, name: str
    ) -> Iterator[Span]:
        for match in pattern.finditer(text):
            if not _starts_word(text, match.start()):
                continue
            tokens = _name_tokens(text, match.end(), limit=3)
            if not tokens:
                continue
            start, end = tokens[0][0], tokens[-1][1]
            words = text[start:end].split()
            if len(words) == 1 and _is_initial(words[0]):
                continue
            if pattern is _VERB_BEFORE_NAME and not _plausible_verb_object(text, words, end):
                continue
            # After a greeting, an unknown word is a name only when the greeting
            # is punctuated like one: "Hi Aanu," or "Regards,\nAanu", but not
            # "Thanks Giving".
            if pattern is _CUE and not self._known(words):
                after = text[end : end + 1]
                cue_punctuated = "\n" in match.group() or "," in match.group()
                if not (cue_punctuated or (after and after in ",\n\r!:")):
                    continue
            yield Span(start, end, PERSON, text[start:end], score, name)

    def _before_verbs(self, text: str) -> Iterator[Span]:
        common = ambiguous()
        for match in _VERB_AFTER_NAME.finditer(text):
            head = text[max(0, match.start() - 60) : match.start()]
            found = _TRAILING_NAME.search(head)
            if found is None:
                continue
            start = match.start() - len(head) + found.start()
            if not _starts_word(text, start):
                continue
            words = found.group().split()
            # Drop leading words that cannot be part of a name ("Then Ravan said").
            while words and words[0].lower() in _NOT_NAMES | _NOT_SUBJECTS:
                start += len(words[0]) + 1
                words = words[1:]
            # A capital that opens a sentence proves nothing: "Later Jane wrote".
            if len(words) > 1 and _sentence_start(text, start) and not self._known(words[:1]):
                start += len(words[0]) + 1
                words = words[1:]
            if not words or (len(words) == 1 and _key(words[0]) in common):
                continue
            end = start + len(" ".join(words))
            if not _plausible_verb_object(text, words, end):
                continue
            yield Span(start, end, PERSON, text[start:end], SCORE_VERB, "names_verb")

    @staticmethod
    def _known(words: list[str]) -> bool:
        first, family = first_names(), surnames()
        return any(_key(w) in first or _key(w) in family for w in words)

    def _from_lists(self, text: str, strict: bool) -> Iterator[Span]:
        first, family, common = first_names(), surnames(), ambiguous()
        # Only runs of capitalised words can hold a name, and the regex finds
        # them without visiting every word of the text.
        for block in _CAPITALISED_RUN.finditer(text):
            begin = block.start()
            if not _starts_word(text, begin):
                # A capital inside a word, as in "iPhone Smith": skip that word.
                space = text.find(" ", begin, block.end())
                if space < 0:
                    continue
                begin = space + 1
            run: list[re.Match[str]] = []
            for match in _TOKEN.finditer(text, begin, block.end()):
                word = match.group()
                usable = _is_initial(word) or _is_capitalised(word)
                if not usable or word.lower() in _NOT_NAMES or len(run) == 4:
                    if run:
                        yield from self._judge(text, run, first, family, common, strict)
                    run = [match] if usable and word.lower() not in _NOT_NAMES else []
                    continue
                if not run and _is_initial(word):
                    continue
                run.append(match)
            if run:
                yield from self._judge(text, run, first, family, common, strict)

    def _judge(
        self,
        text: str,
        run: list[re.Match[str]],
        first: frozenset[str],
        family: frozenset[str],
        common: frozenset[str],
        strict: bool,
    ) -> Iterator[Span]:
        words = [_key(m.group()) for m in run]
        known = [w in first or w in family for w in words]
        if not any(known):
            return
        if len(run) >= 2:
            unambiguous = [w for w, k in zip(words, known, strict=True) if k and w not in common]
            # Two known names together ("Grace Hall") are a name even if both
            # are everyday words; otherwise one unambiguous known name is needed.
            if not (unambiguous or sum(known) >= 2):
                return
            low = known.index(True)
            high = len(known) - 1 - known[::-1].index(True)
            # An unknown word before a family name is likely a given name
            # ("Kavya Sharma"); an unknown word after a given name is likely a
            # family name ("Priya Venkataraman"). Anything further out is not.
            if low > 0 and words[low] in family:
                low -= 1
            if high < len(run) - 1 and words[high] in first and words[high] not in family:
                # Middle initials do not count: "Steven J. Bethard".
                while high < len(run) - 2 and _is_initial(run[high + 1].group()):
                    high += 1
                high += 1
            if low == high and (words[low] in common and not strict):
                return
            start, end = run[low].start(), run[high].end()
            score = SCORE_PAIR if high > low else SCORE_FIRST_NAME
            yield Span(start, end, PERSON, text[start:end], score, "names_list")
            return
        word = words[0]
        if word in common and not strict:
            return
        score = SCORE_FIRST_NAME if word in first else SCORE_SURNAME
        start, end = run[0].span()
        yield Span(start, end, PERSON, text[start:end], score, "names_list")


DETECTORS: tuple[NameDetector, ...] = (NameDetector(),)
