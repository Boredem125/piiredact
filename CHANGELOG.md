# Changelog

This project follows [Semantic Versioning](https://semver.org/). Entity names and the fields of `Span` and `Result` are part of the public interface.

## 0.1.0 (unreleased)

First version.

- Detection engine: Unicode normalisation with offsets mapped back to the original text, scoring with context words, deterministic overlap resolution.
- Global detectors: email, phone, credit card, IBAN, BIC, IPv4 and IPv6, MAC address, URL, IMEI, VIN, coordinates, crypto wallets, date of birth.
- Secret detectors: cloud and service tokens, JWTs, private key blocks, bearer tokens, `key = value` assignments.
- Country packs: `us`, `in`, `gb`, `de`, `fr`, `es`, `it`, `nl`, `eu`. Third-party packs load through the `piiredact.locales` entry-point group.
- Operators: `Replace`, `Mask`, `Hash` (HMAC-SHA256, key required), `Tokenize` with a reversible `Vault`, `Drop`, `Keep`.
- `redact_obj` for nested data, with field-name hints.
- `PIIFilter` for the `logging` module.
- Command line: `redact` (text, JSON Lines, CSV), `scan`, `entities`.
- `redact_dataframe` for pandas (extra `pandas`).
- `SpacyDetector` for names, places and organisations (extra `ner`).
