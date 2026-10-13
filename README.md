# piiredact

[![CI](https://github.com/Boredem125/piiredact/actions/workflows/ci.yml/badge.svg)](https://github.com/Boredem125/piiredact/actions/workflows/ci.yml)

Detect and redact personally identifiable information (PII) in text, nested data, logs, files and DataFrames.

- **No dependencies** in the core. Pure Python, 3.10 and later.
- **Validated, not just matched.** Card numbers, IBANs, Aadhaar, NHS numbers and other identifiers are checked against their check digits, so a random run of digits is not flagged.
- **Country packs** for the United States, India, the United Kingdom, Germany, France, Spain, Italy, the Netherlands and the EU, plus a plug-in mechanism for more.
- **Secrets too.** API keys, tokens, private keys and `password=...` assignments.
- **Several ways in:** strings, nested dicts and lists, a `logging` filter, a command line tool, and pandas.

```python
>>> import piiredact
>>> piiredact.redact("Mail jane@example.com or call +1 415 555 0132")
'Mail [EMAIL] or call [PHONE]'

```

## Read this first

No tool finds every piece of PII, and this one does not either. Names, street addresses and free-form descriptions ("the tall man from flat 4") cannot be found by patterns at all. Treat the output as reduced-risk data, not as anonymous data.

Using this library does not by itself make a system compliant with GDPR, HIPAA, India's DPDP Act or any other law. Measure recall on a sample of your own data before you depend on it; [Evaluation](#evaluation) shows how.

## Install

```bash
pip install piiredact
```

Optional extras: `piiredact[pandas]` for DataFrames, `piiredact[ner]` for names and places through spaCy, `piiredact[phone]` for stricter validation of international phone numbers, `piiredact[all]` for all three.

## Usage

### Text

```python
>>> from piiredact import Redactor, Mask
>>> redactor = Redactor(policy={"CREDIT_CARD": Mask(keep_last=4)})
>>> result = redactor.redact("jane@example.com paid with 4111 1111 1111 1111")
>>> result.text
'[EMAIL] paid with **** **** **** 1111'
>>> result.stats
{'EMAIL': 1, 'CREDIT_CARD': 1}

```

Build a `Redactor` once and reuse it. It is immutable and safe to share between threads.

`scan` reports what was found without changing the text. The `repr` of a span leaves the matched value out, so spans can be logged:

```python
>>> piiredact.scan("SSN 078-05-1120")
[Span(start=4, end=15, entity='US_SSN', score=1.0, detector='us_ssn')]

```

### Options

| Option | Meaning |
|---|---|
| `locales` | Country packs to load, for example `["us", "in"]`. Default: all installed. Loading only the packs you need reduces false positives. |
| `entities` / `exclude_entities` | Limit detection to, or exempt, some entity types. |
| `policy` | Entity type to operator. Others use `default_operator`. |
| `min_score` | Detections below this score are ignored. Default 0.5. |
| `strict` | Prefer over-redaction: lower the threshold and drop the need for a context word. |
| `allow` | Exact values never to redact, such as your own support address. |
| `detectors` | Extra detectors of your own. |

### Operators

| Operator | `4111 1111 1111 1111` becomes |
|---|---|
| `Replace()` (default) | `[CREDIT_CARD]` |
| `Mask(keep_last=4)` | `**** **** **** 1111` |
| `Hash(key)` | `[CREDIT_CARD:` 16 hex digits `]` |
| `Tokenize(vault)` | `[CREDIT_CARD_1]`, reversible with `vault.restore(text)` |
| `Drop()` | nothing |
| `Keep()` | unchanged |

`Hash` needs a secret key of at least 16 bytes and uses HMAC-SHA256. An unkeyed hash of a phone number or national ID can be reversed by trying every possible value, so it is not offered. `Mask` never reveals more than half of a value. A `Vault` holds the original values: protect it as you would the unredacted data.

### Nested data

```python
>>> piiredact.redact_obj({
...     "note": "call jane@example.com",
...     "user": {"firstName": "Jane", "password": "hunter2", "age": 41},
... })
{'note': 'call [EMAIL]', 'user': {'firstName': '[PERSON]', 'password': '[SECRET]', 'age': 41}}

```

Field names are used as hints. A field called `password`, `ssn`, `userEmail` or `phone_number` has its whole value redacted, even when the value does not look like PII. Pass `key_hints=False` to turn this off. The input object is not modified.

### Logging

```python
import logging
from piiredact import PIIFilter

handler = logging.StreamHandler()
handler.addFilter(PIIFilter())
logging.getLogger().addHandler(handler)
```

Attach the filter to handlers, not loggers: a filter on a logger does not see records that propagate up from child loggers. The message, its arguments, exception text, stack info and `extra` fields are all redacted. If redaction itself fails, the message is replaced with a fixed notice instead of being written unredacted.

### Command line

```bash
piiredact redact notes.txt -o clean.txt
cat app.log | piiredact redact - > clean.log
piiredact redact events.jsonl --format jsonl -o clean.jsonl
piiredact redact people.csv --format csv --operator mask --keep-last 4 -o clean.csv
piiredact scan notes.txt
piiredact entities --locales us,in
```

`scan` prints `file:line:column: ENTITY (score)` for each finding and exits with status 1 when anything is found, so it can gate a commit or a CI job. It does not print the matched values unless you pass `--show-values`.

For `--operator hash`, the key is read from the environment variable `PIIREDACT_HASH_KEY`, so that it does not appear in the process list or shell history.

Text input is streamed in chunks, so large files do not need to fit in memory. A file that is one single very long line is the exception.

### pandas

```python
from piiredact.frames import redact_dataframe

clean = redact_dataframe(df)  # every text column
clean = redact_dataframe(df, columns=["notes"])  # only these
```

Column names are used as hints in the same way as field names.

### Names and places

Patterns cannot find names. The optional spaCy detector can, at the cost of a model download and slower runs:

```bash
pip install "piiredact[ner]"
python -m spacy download en_core_web_sm
```

```python
from piiredact import Redactor
from piiredact.detectors.ner import SpacyDetector

redactor = Redactor(detectors=[SpacyDetector()])
```

It emits `PERSON`, `LOCATION` and `ORGANIZATION`. Its accuracy is that of the spaCy model you load.

### Your own detectors

```python
>>> from piiredact import PatternDetector, Redactor
>>> employee_id = PatternDetector(
...     "EMPLOYEE_ID",
...     r"\bE\d{5}\b",
...     score=0.4,
...     context=("employee", "staff"),
...     require_context=True,
... )
>>> Redactor(detectors=[employee_id]).redact("staff E12345 badge").text
'staff [EMPLOYEE_ID] badge'

```

A country pack is a module that exports `DETECTORS`. A separate package can register one under the `piiredact.locales` entry-point group, and it is then loaded like a built-in pack:

```toml
[project.entry-points."piiredact.locales"]
br = "piiredact_br:DETECTORS"
```

## What is detected

| Pack | Entity types |
|---|---|
| Always on | `EMAIL`, `PHONE`, `CREDIT_CARD`, `IBAN`, `BIC`, `IP_ADDRESS`, `MAC_ADDRESS`, `URL`, `IMEI`, `VIN`, `GEO_COORDINATES`, `CRYPTO_WALLET`, `DATE_OF_BIRTH`, `SECRET` |
| `us` | `US_SSN`, `US_ITIN`, `US_EIN`, `US_PASSPORT`, `US_ROUTING_NUMBER`, `US_ZIP` |
| `in` | `IN_AADHAAR`, `IN_PAN`, `IN_GSTIN`, `IN_VOTER_ID`, `IN_PASSPORT`, `IN_IFSC`, `IN_UPI_ID`, `IN_PIN_CODE` |
| `gb` | `GB_NINO`, `GB_NHS_NUMBER`, `GB_POSTCODE`, `GB_DRIVING_LICENCE` |
| `de` | `DE_TAX_ID`, `DE_ID_CARD` |
| `fr` | `FR_NIR` |
| `es` | `ES_DNI`, `ES_NIE` |
| `it` | `IT_FISCAL_CODE` |
| `nl` | `NL_BSN` |
| `eu` | `EU_VAT` |

Field-name hints can also produce `PERSON`, `LOCATION`, `PASSPORT`, `BANK_ACCOUNT`, `NATIONAL_ID`, `TAX_ID` and `DRIVING_LICENCE`.

### Behaviour worth knowing

- **Context words.** Shapes that are too common to trust alone need a nearby word: a bare nine-digit number is an SSN only next to "SSN", a date is a date of birth only next to "born" or "DOB", and so on. `strict=True` removes this requirement.
- **Context reaches across sentences.** The window is about 48 characters before a value and 24 after. A second date shortly after "born 3 March 1985" is redacted as well.
- **URLs.** A URL is redacted when it carries credentials or a query string. A plain link is left alone unless `strict=True`.
- **Aadhaar.** A bare twelve-digit number starting with 2 to 9 that passes the Verhoeff check is treated as an Aadhaar number. About one in twelve arbitrary twelve-digit numbers does. If your data has no Indian identifiers, leave the `in` pack out.
- **Labels can be ambiguous.** A number that is valid as two things gets one label. It is redacted either way.
- **Unicode.** Full-width digits, non-Latin digits, unusual dashes and zero-width characters inside a value are handled. Internationalised email addresses are not.
- **Not handled:** images, PDFs, audio, and PII that is written out in words ("jane at example dot com").

## Evaluation

```bash
python benchmarks/evaluate.py
python benchmarks/throughput.py
```

`evaluate.py` scores the detectors on a generated corpus: valid identifiers planted in sentences, plus numeric text that holds no PII. On that corpus every listed type currently reaches a recall and precision of 1.0. This shows that the detectors agree with the formats they claim to support. It does not predict recall on real text, which is messier than anything a generator produces. To measure on your own data, label a sample and pass it to `synth.evaluate` in `tests/synth.py`.

Throughput on one development laptop (Python 3.12, all packs loaded), for orientation only:

| Input | Speed |
|---|---|
| Prose without digits | about 3.6 MB/s |
| Text dense with identifiers | about 0.3 MB/s |
| One short log line | 40 to 200 microseconds |

Loading fewer packs is the simplest way to go faster.

## Development

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"     # .venv\Scripts\pip on Windows
ruff check . && ruff format --check .
mypy
pytest
```

The test suite includes property tests (Hypothesis) and a timing test that guards every pattern against catastrophic regex backtracking. Test data is generated: do not add real personal data to this repository.

## Licence

Apache-2.0. See [LICENSE](LICENSE).
