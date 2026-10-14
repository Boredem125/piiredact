# Changelog

This project follows [Semantic Versioning](https://semver.org/). Entity names and the fields of `Span` and `Result` are part of the public interface.

## 0.3.0 (unreleased)

Contextual detection, on by default and built in: no model and no download.

- **Labels and tables.** A value is redacted because of its label, whatever it looks like: `Email: jane at example dot com`, `Name: ...`, `my name is ...`, `I live at ...`, JSON keys and `key=value` pairs (`"fullName": ...`, `user_email=...`), and columns of Markdown and tab-separated tables. Compound labels such as "file name" or "host name" are ignored.
- **Person names** from titles (`Dr.`, `Mrs`, `Shri`, `श्री`), greetings and sign-offs, and built-in lists of common given and family names from many cultures. Names that are also everyday words (Will, May, Grace) need extra evidence.
- **Street addresses** in English, South Asian, German, Nordic, Dutch, French, Spanish, Portuguese, Italian and Polish forms, and PO boxes.
- **Propagation.** A value found once is redacted wherever else it appears.
- **Person linking.** The parts of a detected name are redacted where they appear alone and linked to the full name, so `Tokenize` and `Hash` give "Jane Doe", "Ms Doe" and "Jane" the same output. `Span.link` holds the full name.
- **Identifying combinations.** `AGE`, `GENDER`, `OCCUPATION`, `CITY` and `ORGANIZATION` are redacted when at least three kinds (counting postcodes, birth dates and addresses) occur within a few sentences. Set with `quasi_threshold`.
- New `Redactor` options: `contextual` (turns all of the above off for speed), `propagate`, `quasi_threshold`.
- New entity types: `USERNAME`, `AGE`, `GENDER`, `OCCUPATION`, `CITY`.
- Detectors can declare `needs_any` substrings, and open-ended detectors can declare the `entities` they emit.
- Fixed: a labelled value now outranks smaller matches inside it, so an address label covers the postcode within it.

## 0.2.0 (2026-10-14)

- 24 new country packs, 32 new entity types, each with its check-digit or date validation and context words in the local language:
  - Americas: `ca` (`CA_SIN`, `CA_POSTAL_CODE`), `br` (`BR_CPF`, `BR_CNPJ`, including the alphanumeric CNPJ issued from July 2026), `mx` (`MX_CURP`, `MX_RFC`), `cl` (`CL_RUT`), `ar` (`AR_CUIT`).
  - Asia-Pacific: `au` (`AU_TFN`, `AU_ABN`, `AU_MEDICARE`), `nz` (`NZ_IRD`, `NZ_NHI`), `sg` (`SG_NRIC`), `jp` (`JP_MY_NUMBER`), `kr` (`KR_RRN`), `cn` (`CN_RESIDENT_ID`).
  - Europe: `pl` (`PL_PESEL`, `PL_NIP`, `PL_ID_CARD`), `se` (`SE_PERSONNUMMER`), `dk` (`DK_CPR`), `fi` (`FI_HETU`), `no` (`NO_FNR`), `be` (`BE_NATIONAL_NUMBER`), `pt` (`PT_NIF`), `ie` (`IE_PPSN`), `at` (`AT_SVNR`), `ch` (`CH_AHV`), `tr` (`TR_TCKN`).
  - Africa and the Middle East: `za` (`ZA_ID`), `ae` (`AE_EMIRATES_ID`).
- Locale aliases `uae`, `kor` and `chn`.
- Phone context words in more languages.
- Detectors that need a context word are skipped when none of their words appear in the text, which keeps the larger default pack set fast.
- Fixed: `+35236450.6` is no longer read as a phone number, and `1.38435736E+12` no longer as a Spanish DNI.
- Package metadata names the author.

## 0.1.0 (2026-10-13)

First version.

- Detection engine: Unicode normalisation with offsets mapped back to the original text, scoring with context words, deterministic overlap resolution.
- Global detectors: email, phone, credit card, IBAN, BIC, IPv4 and IPv6, MAC address, URL, IMEI, VIN, coordinates, crypto wallets, date of birth.
- Secret detectors: cloud and service tokens, JWTs, private key blocks, bearer tokens, `key = value` assignments.
- Country packs: `us`, `in`, `gb`, `de`, `fr`, `es`, `it`, `nl`, `eu`. Third-party packs load through the `depii.locales` entry-point group.
- Operators: `Replace`, `Mask`, `Hash` (HMAC-SHA256, key required), `Tokenize` with a reversible `Vault`, `Drop`, `Keep`.
- `redact_obj` for nested data, with field-name hints.
- `PIIFilter` for the `logging` module.
- Command line: `redact` (text, JSON Lines, CSV), `scan`, `entities`.
- `redact_dataframe` for pandas (extra `pandas`).
- `SpacyDetector` for names, places and organisations (extra `ner`).
