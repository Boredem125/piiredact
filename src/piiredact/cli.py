"""Command line interface.

    piiredact redact notes.txt -o clean.txt
    cat app.log | piiredact redact - > clean.log
    piiredact scan notes.txt          # exit status 1 when PII is found
    piiredact entities
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
import sys
from collections import Counter
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any, TextIO

from . import __version__, locales, registry
from .engine import Redactor
from .operators import Drop, Hash, Mask, Operator, Replace
from .stream import chunks, redact_stream
from .structured import entity_for_key

EXIT_OK = 0
EXIT_FOUND = 1
EXIT_ERROR = 2


def _split(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [item.strip() for item in value.split(",") if item.strip()]


def _operator(args: argparse.Namespace) -> Operator:
    if args.operator == "mask":
        return Mask(keep_last=args.keep_last)
    if args.operator == "drop":
        return Drop()
    if args.operator == "hash":
        # The key comes from the environment: a command-line argument would
        # be visible in the process list and the shell history.
        key = os.environ.get(args.hash_key_env)
        if not key:
            raise SystemExit(f"piiredact: --operator hash needs a key in ${args.hash_key_env}")
        return Hash(key)
    return Replace()


def _redactor(args: argparse.Namespace) -> Redactor:
    entities = _split(args.entities)
    if entities is not None:
        entities = [name.upper() for name in entities]
    exclude = [name.upper() for name in _split(args.exclude) or []]
    return Redactor(
        locales=_split(args.locales),
        entities=entities,
        exclude_entities=exclude,
        default_operator=_operator(args) if hasattr(args, "operator") else None,
        min_score=args.min_score,
        strict=args.strict,
    )


@contextmanager
def _reader(path: str, encoding: str) -> Iterator[TextIO]:
    # newline="" keeps line endings exactly as they are in the input.
    if path == "-":
        yield io.TextIOWrapper(sys.stdin.buffer, encoding=encoding, newline="")
    else:
        with open(path, encoding=encoding, newline="") as handle:
            yield handle


@contextmanager
def _writer(path: str | None, encoding: str) -> Iterator[TextIO]:
    if path is None or path == "-":
        wrapper = io.TextIOWrapper(sys.stdout.buffer, encoding=encoding, newline="")
        try:
            yield wrapper
        finally:
            wrapper.flush()
            wrapper.detach()
    else:
        with open(path, "w", encoding=encoding, newline="") as handle:
            yield handle


def _redact_jsonl(source: TextIO, sink: TextIO, redactor: Redactor) -> dict[str, int]:
    totals: Counter[str] = Counter()
    for line in source:
        body = line.rstrip("\r\n")
        ending = line[len(body) :]
        if not body.strip():
            sink.write(line)
            continue
        try:
            record: Any = json.loads(body)
        except json.JSONDecodeError:
            # Not JSON: redact it as plain text rather than passing it through.
            result = redactor.redact(body)
            totals.update(span.entity for span in result.spans)
            sink.write(result.text + ending)
            continue
        clean = redactor.redact_obj(record)
        if clean != record:
            totals["records_changed"] += 1
        sink.write(json.dumps(clean, ensure_ascii=False) + ending)
    return dict(totals)


def _redact_csv(
    source: TextIO, sink: TextIO, redactor: Redactor, *, header: bool
) -> dict[str, int]:
    totals: Counter[str] = Counter()
    reader = csv.reader(source)
    writer = csv.writer(sink, lineterminator="\n")
    hints: list[str | None] = []
    for index, row in enumerate(reader):
        if index == 0 and header:
            hints = [entity_for_key(name) for name in row]
            writer.writerow(row)
            continue
        clean: list[str] = []
        for column, cell in enumerate(row):
            hint = hints[column] if column < len(hints) else None
            if hint is not None and cell:
                clean.append(redactor.operator_for(hint).apply(cell, hint))
                totals[hint] += 1
            else:
                result = redactor.redact(cell)
                totals.update(span.entity for span in result.spans)
                clean.append(result.text)
        writer.writerow(clean)
    return dict(totals)


def _cmd_redact(args: argparse.Namespace) -> int:
    redactor = _redactor(args)
    with _reader(args.input, args.encoding) as source, _writer(
        args.output, args.encoding
    ) as sink:
        if args.format == "jsonl":
            totals = _redact_jsonl(source, sink, redactor)
        elif args.format == "csv":
            totals = _redact_csv(source, sink, redactor, header=not args.no_header)
        else:
            totals = redact_stream(source, sink, redactor)
    if args.report:
        print(json.dumps(totals, sort_keys=True), file=sys.stderr)
    return EXIT_OK


def _cmd_scan(args: argparse.Namespace) -> int:
    redactor = _redactor(args)
    found = 0
    line_number = 1
    with _reader(args.input, args.encoding) as source:
        for chunk in chunks(source):
            newlines = [i for i, ch in enumerate(chunk) if ch == "\n"]
            cursor = 0
            for span in redactor.scan(chunk):
                while cursor < len(newlines) and newlines[cursor] < span.start:
                    cursor += 1
                line = line_number + cursor
                column = span.start - (newlines[cursor - 1] + 1 if cursor else 0) + 1
                found += 1
                record: dict[str, Any] = {
                    "line": line,
                    "column": column,
                    "entity": span.entity,
                    "score": round(span.score, 2),
                    "detector": span.detector,
                }
                if args.show_values:
                    record["value"] = span.text
                if args.json:
                    print(json.dumps(record, ensure_ascii=False))
                else:
                    value = f"  {span.text!r}" if args.show_values else ""
                    print(f"{args.input}:{line}:{column}: {span.entity} ({span.score:.2f}){value}")
            line_number += len(newlines)
    if not args.json:
        print(f"{found} finding(s)", file=sys.stderr)
    return EXIT_FOUND if found else EXIT_OK


def _cmd_entities(args: argparse.Namespace) -> int:
    for name in registry.supported_entities(_split(args.locales)):
        print(name)
    return EXIT_OK


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="piiredact", description="Detect and redact PII in text, JSON Lines and CSV."
    )
    parser.add_argument("--version", action="version", version=f"piiredact {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    def common(sub: argparse.ArgumentParser) -> None:
        sub.add_argument("input", nargs="?", default="-", help="file to read, or - for stdin")
        sub.add_argument(
            "--locales",
            help=f"comma-separated country packs (default: all of {','.join(locales.available())})",
        )
        sub.add_argument("--entities", help="comma-separated entity types to detect")
        sub.add_argument("--exclude", help="comma-separated entity types to leave alone")
        sub.add_argument("--min-score", type=float, default=0.5, help="default: 0.5")
        sub.add_argument("--strict", action="store_true", help="prefer over-redaction")
        sub.add_argument("--encoding", default="utf-8", help="default: utf-8")

    redact = commands.add_parser("redact", help="write a redacted copy of the input")
    common(redact)
    redact.add_argument("-o", "--output", help="file to write (default: stdout)")
    redact.add_argument("--format", choices=("text", "jsonl", "csv"), default="text")
    redact.add_argument("--no-header", action="store_true", help="csv: first row is data")
    redact.add_argument(
        "--operator", choices=("replace", "mask", "hash", "drop"), default="replace"
    )
    redact.add_argument("--keep-last", type=int, default=0, help="mask: characters left visible")
    redact.add_argument(
        "--hash-key-env",
        default="PIIREDACT_HASH_KEY",
        help="hash: environment variable holding the key (default: PIIREDACT_HASH_KEY)",
    )
    redact.add_argument("--report", action="store_true", help="print counts to stderr as JSON")
    redact.set_defaults(run=_cmd_redact)

    scan = commands.add_parser("scan", help="list findings; exit status 1 if any")
    common(scan)
    scan.add_argument("--json", action="store_true", help="one JSON object per finding")
    scan.add_argument(
        "--show-values", action="store_true", help="print the matched text (it is PII)"
    )
    scan.set_defaults(run=_cmd_scan)

    entities = commands.add_parser("entities", help="list supported entity types")
    entities.add_argument("--locales", help="comma-separated country packs")
    entities.set_defaults(run=_cmd_entities)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return int(args.run(args))
    except (OSError, ValueError, UnicodeError) as error:
        print(f"piiredact: {error}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
