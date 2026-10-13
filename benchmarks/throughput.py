"""Measure redaction throughput in MB/s on synthetic log-like text.

    python benchmarks/throughput.py [--mb 5]
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))

import synth
from piiredact import Redactor


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--mb", type=float, default=5.0)
    args = parser.parse_args()

    lines = [sample.text for sample in synth.corpus(per_kind=20)]
    block = "\n".join(lines) + "\n"
    text = block * max(1, int(args.mb * 1024 * 1024 / len(block)))
    size_mb = len(text.encode()) / 1024 / 1024

    for label, options in (("all locales", {}), ("no locales", {"locales": []})):
        redactor = Redactor(**options)
        started = time.perf_counter()
        result = redactor.redact(text)
        elapsed = time.perf_counter() - started
        print(
            f"{label:12s} {size_mb:.1f} MB in {elapsed:.2f} s = {size_mb / elapsed:.2f} MB/s, "
            f"{len(result.spans)} redactions, {len(redactor.detectors)} detectors"
        )


if __name__ == "__main__":
    main()
