# depii

[![CI](https://github.com/Boredem125/piiredact/actions/workflows/ci.yml/badge.svg)](https://github.com/Boredem125/piiredact/actions/workflows/ci.yml)

Detect and redact personally identifiable information (PII) in text, nested data, logs, files and DataFrames.

- **No dependencies** in the core. Pure Python, 3.10 and later.
- **Validated, not just matched.** Card numbers, IBANs, Aadhaar, NHS numbers and other identifiers are checked against their check digits, so a random run of digits is not flagged.
- **Country packs for 32 countries and the EU**: the Americas, Europe, Asia-Pacific, Africa and the Middle East (see [What is detected](#what-is-detected)), plus a plug-in mechanism for more.
- **Context-aware.** Values after a label (`Email: jane at example dot com`) or in a table column, person names, street addresses, the same person mentioned several ways, and details that identify someone only together (age, city, job). Built in: no model, no download.
- **Secrets too.** API keys, tokens, private keys and `password=...` assignments.
- **Several ways in:** strings, nested dicts and lists, a `logging` filter, a command line tool, and pandas.

```python
>>> import depii
>>> depii.redact("Mail jane@example.com or call +1 415 555 0132")
'Mail [EMAIL] or call [PHONE]'

```

## Read this first

No tool finds every piece of PII, and this one does not either. Name detection relies on titles, greetings, labels and built-in name lists, so an unusual name mentioned once with no context is missed. Free-form descriptions ("the tall man from flat 4") are not found. Treat the output as reduced-risk data, not as anonymous data.

Using this library does not by itself make a system compliant with GDPR, HIPAA, India's DPDP Act or any other law. Measure recall on a sample of your own data before you depend on it; [Evaluation](#evaluation) shows how.

## Install

```bash
pip install depii
```

Optional extras: `depii[pandas]` for DataFrames, `depii[ner]` for names and places through spaCy, `depii[phone]` for stricter validation of international phone numbers, `depii[all]` for all three.

## Usage

### Text

```python
>>> from depii import Redactor, Mask
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
>>> depii.scan("SSN 078-05-1120")
[Span(start=4, end=15, entity='US_SSN', score=1.0, detector='us_ssn')]

```

### Context

Beyond the shape of a value, depii looks at what surrounds it. All of this is on by default and needs nothing beyond `pip install depii`.

**Labels and tables.** The label decides, whatever the value looks like. This covers prose (`Name: ...`, `my email is ...`, `I live at ...`), JSON and key-value pairs (`"fullName": ...`, `user_email=...`), and table columns in Markdown or tab-separated text:

```python
>>> depii.redact("Email: jane at example dot com")
'Email: [EMAIL]'
>>> print(depii.redact("| Name | Phone |\n|---|---|\n| Ravi Kumar | 98765 43210 |"))
| Name | Phone |
|---|---|
| [PERSON] | [PHONE] |

```

**Names and addresses.** Person names are found from titles (`Dr. R. Iyer`, `Smt. Meena`), greetings and sign-offs (`Dear Aanu,`, `Regards,` then a name), and lists of common given names and family names from many cultures. Street addresses are found from a house number next to a street word in several languages (`221B Baker Street`, `42 MG Road`, `Hauptstraße 5`, `12 rue de Rivoli`), and PO boxes.

**The same person, everywhere.** A value found once is redacted wherever else it appears, and the parts of a detected name are redacted on their own and linked to the full name. With `Tokenize` or `Hash`, every mention gets the same output:

```python
>>> from depii import Tokenize, Vault
>>> Redactor(default_operator=Tokenize(Vault())).redact(
...     "Jane Doe called. Ms Doe will return; Jane agreed."
... ).text
'[PERSON_1] called. Ms [PERSON_1] will return; [PERSON_1] agreed.'

```

`vault.restore()` puts back the full name for every linked mention, so "Ms Doe" restores as "Ms Jane Doe".

**Identifying combinations.** An age, a gender, a city, an occupation or an employer is not personal data on its own. Several of them about one person can be. When at least three kinds occur within a few sentences (postcodes, birth dates and addresses count too), all of them are redacted:

```python
>>> depii.redact("The patient is a 42-year-old woman from Pune who works as a nurse.")
'The patient is a [AGE] [GENDER] from [CITY] who works as a [OCCUPATION].'
>>> depii.redact("A 42-year-old woman attended.")
'A 42-year-old woman attended.'

```

Change the number with `quasi_threshold`, or turn this off with `quasi_threshold=None`. `contextual=False` turns off all of the above and keeps only the pattern detectors, which is several times faster on short strings such as log lines.

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
| `contextual` | Labels, names, addresses, linking and combinations. Default `True`. |
| `propagate` | Redact every other occurrence of a found value, and link name parts. Follows `contextual`. |
| `quasi_threshold` | How many kinds of identifying detail together trigger redaction. Default 3; `None` turns it off. |

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
>>> depii.redact_obj({
...     "note": "call jane@example.com",
...     "user": {"firstName": "Jane", "password": "hunter2", "age": 41},
... })
{'note': 'call [EMAIL]', 'user': {'firstName': '[PERSON]', 'password': '[SECRET]', 'age': 41}}

```

Field names are used as hints. A field called `password`, `ssn`, `userEmail` or `phone_number` has its whole value redacted, even when the value does not look like PII. Pass `key_hints=False` to turn this off. The input object is not modified.

### Logging

```python
import logging
from depii import PIIFilter

handler = logging.StreamHandler()
handler.addFilter(PIIFilter())
logging.getLogger().addHandler(handler)
```

Attach the filter to handlers, not loggers: a filter on a logger does not see records that propagate up from child loggers. The message, its arguments, exception text, stack info and `extra` fields are all redacted. If redaction itself fails, the message is replaced with a fixed notice instead of being written unredacted.

### Command line

```bash
depii redact notes.txt -o clean.txt
cat app.log | depii redact - > clean.log
depii redact events.jsonl --format jsonl -o clean.jsonl
depii redact people.csv --format csv --operator mask --keep-last 4 -o clean.csv
depii scan notes.txt
depii entities --locales us,in
```

`scan` prints `file:line:column: ENTITY (score)` for each finding and exits with status 1 when anything is found, so it can gate a commit or a CI job. It does not print the matched values unless you pass `--show-values`.

For `--operator hash`, the key is read from the environment variable `DEPII_HASH_KEY`, so that it does not appear in the process list or shell history.

Text input is streamed in chunks, so large files do not need to fit in memory. A file that is one single very long line is the exception.

### pandas

```python
from depii.frames import redact_dataframe

clean = redact_dataframe(df)  # every text column
clean = redact_dataframe(df, columns=["notes"])  # only these
```

Column names are used as hints in the same way as field names.

### A language model for names

The built-in name detection needs a title, a greeting, a label or a name it knows. A language model also finds names it has never seen, from how they are used. The optional spaCy detector adds one, at the cost of a model download and slower runs:

```bash
pip install "depii[ner]"
python -m spacy download en_core_web_sm
```

```python
from depii import Redactor
from depii.detectors.ner import SpacyDetector

redactor = Redactor(detectors=[SpacyDetector()])
```

It emits `PERSON`, `LOCATION` and `ORGANIZATION` alongside the built-in detectors. Its accuracy is that of the spaCy model you load.

### Your own detectors

```python
>>> from depii import PatternDetector, Redactor
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

A country pack is a module that exports `DETECTORS`. A separate package can register one under the `depii.locales` entry-point group, and it is then loaded like a built-in pack:

```toml
[project.entry-points."depii.locales"]
br = "depii_br:DETECTORS"
```

## What is detected

| Pack | Entity types |
|---|---|
| Always on | `EMAIL`, `PHONE`, `CREDIT_CARD`, `IBAN`, `BIC`, `IP_ADDRESS`, `MAC_ADDRESS`, `URL`, `IMEI`, `VIN`, `GEO_COORDINATES`, `CRYPTO_WALLET`, `DATE_OF_BIRTH`, `SECRET` |
| Context | `PERSON`, `LOCATION` (addresses), `ORGANIZATION` and `USERNAME` from labels; any type above when its label says so |
| Combinations | `AGE`, `GENDER`, `OCCUPATION`, `CITY`, `ORGANIZATION`, only when enough of them occur together |
| `us` | `US_SSN`, `US_ITIN`, `US_EIN`, `US_PASSPORT`, `US_ROUTING_NUMBER`, `US_ZIP` |
| `in` | `IN_AADHAAR`, `IN_PAN`, `IN_GSTIN`, `IN_VOTER_ID`, `IN_PASSPORT`, `IN_IFSC`, `IN_UPI_ID`, `IN_PIN_CODE` |
| `gb` | `GB_NINO`, `GB_NHS_NUMBER`, `GB_POSTCODE`, `GB_DRIVING_LICENCE` |
| `de` | `DE_TAX_ID`, `DE_ID_CARD` |
| `fr` | `FR_NIR` |
| `es` | `ES_DNI`, `ES_NIE` |
| `it` | `IT_FISCAL_CODE` |
| `nl` | `NL_BSN` |
| `eu` | `EU_VAT` |
| `ca` | `CA_SIN`, `CA_POSTAL_CODE` |
| `br` | `BR_CPF`, `BR_CNPJ` (including the 2026 alphanumeric format) |
| `mx` | `MX_CURP`, `MX_RFC` |
| `cl` | `CL_RUT` |
| `ar` | `AR_CUIT` |
| `au` | `AU_TFN`, `AU_ABN`, `AU_MEDICARE` |
| `nz` | `NZ_IRD`, `NZ_NHI` |
| `sg` | `SG_NRIC` |
| `jp` | `JP_MY_NUMBER` |
| `kr` | `KR_RRN` |
| `cn` | `CN_RESIDENT_ID` |
| `pl` | `PL_PESEL`, `PL_NIP`, `PL_ID_CARD` |
| `se` | `SE_PERSONNUMMER` |
| `dk` | `DK_CPR` |
| `fi` | `FI_HETU` |
| `no` | `NO_FNR` |
| `be` | `BE_NATIONAL_NUMBER` |
| `pt` | `PT_NIF` |
| `ie` | `IE_PPSN` |
| `at` | `AT_SVNR` |
| `ch` | `CH_AHV` |
| `tr` | `TR_TCKN` |
| `za` | `ZA_ID` |
| `ae` | `AE_EMIRATES_ID` |

Field-name hints can also produce `PERSON`, `LOCATION`, `PASSPORT`, `BANK_ACCOUNT`, `NATIONAL_ID`, `TAX_ID` and `DRIVING_LICENCE`.

### Behaviour worth knowing

- **Context words.** Shapes that are too common to trust alone need a nearby word: a bare nine-digit number is an SSN only next to "SSN", a date is a date of birth only next to "born" or "DOB", and so on. Most national numbers written without their usual separators fall in this group: `52998224725` is a Brazilian CPF only next to "CPF", while `529.982.247-25` is one on its own. Context words include the local language ("PESEL", "fødselsnummer", "マイナンバー", "주민등록번호"). `strict=True` removes this requirement.
- **Context reaches across sentences.** The window is about 48 characters before a value and 24 after. A second date shortly after "born 3 March 1985" is redacted as well.
- **URLs.** A URL is redacted when it carries credentials or a query string. A plain link is left alone unless `strict=True`.
- **Aadhaar.** A bare twelve-digit number starting with 2 to 9 that passes the Verhoeff check is treated as an Aadhaar number. About one in twelve arbitrary twelve-digit numbers does. If your data has no Indian identifiers, leave the `in` pack out.
- **Labels can be ambiguous.** A number that is valid as two things gets one label: a Swedish personnummer can also be a valid Finnish or Danish one, a twelve-digit number can be an Aadhaar or a Japanese My Number. It is redacted either way.
- **Only the date is checked for some numbers.** Danish CPR numbers since 2007 and Korean RRNs since 2020 have no check digit, and Singapore M-series FINs use an unpublished one, so for these the shape and the date are all there is to go on.
- **Unicode.** Full-width digits, non-Latin digits, unusual dashes and zero-width characters inside a value are handled. Internationalised email addresses are not.
- **Not handled:** images, PDFs, audio, and PII written out in words with no label ("write to jane at example dot com"). With a label ("Email: jane at example dot com") it is found.
- **Names in scripts without capitals.** Chinese, Japanese, Arabic and similar names are found only with a label, or with a Devanagari title such as श्री.

## Evaluation

```bash
python benchmarks/evaluate.py
python benchmarks/throughput.py
```

`evaluate.py` scores the detectors on a generated corpus: valid identifiers planted in sentences, plus numeric text that holds no PII. On that corpus every listed type currently reaches a recall and precision of 1.0. This shows that the detectors agree with the formats they claim to support. It does not predict recall on real text, which is messier than anything a generator produces. To measure on your own data, label a sample and pass it to `synth.evaluate` in `tests/synth.py`.

Throughput on one development laptop (Python 3.12), for orientation only:

| Input | Default | `locales=["us", "in"]` | `contextual=False` |
|---|---|---|---|
| Prose | about 2 MB/s | about 2 MB/s | about 5 MB/s |
| Text dense with identifiers | about 0.15 MB/s | about 0.3 MB/s | about 0.2 MB/s |
| One short log line with numbers | about 270 microseconds | about 140 microseconds | about 200 microseconds |
| One short log line without digits | about 65 microseconds | about 65 microseconds | about 30 microseconds |

Loading only the packs you need is the simplest way to go faster, and it also reduces false positives. For high-volume logs, `contextual=False` trades the context features for speed.

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
