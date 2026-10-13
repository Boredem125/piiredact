"""Guard against catastrophic regex backtracking.

Each detector is run against inputs built to trigger backtracking. Matching
time must grow roughly linearly: doubling the input may not quadruple the
time. A quadratic pattern fails this by a wide margin on these sizes.
"""

import time

import pytest

from depii import Redactor, registry

SIZE = 20_000

# Each entry is repeated to SIZE characters.
ATTACKS = [
    "a", "1", "A", "0", ".", "-", " ", ":", "@", "/", "+", "(", "_", "\n",
    "1 ", "1-", "1.", "12 ", "1234 ", "1234-", "123 456 ", "+1 ", "(1) ", "0 1 ",
    "a.", "a@", "a@a", "a@a.", "a.a@", "a-", "a_", "a.b-c_",
    "1:", "a:", "::", "1.1.", "255.", "ff:", "0x", "0xf",
    "AB", "A1", "AB12 ", "DE00 ", "AAAA0", "ABCDE1234",
    "eyJ", "eyJa.", "eyJa.eyJ", "sk-", "ghp_", "xoxb-", "AKIA",
    "-----BEGIN PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----\n", "-----",
    "password=", "token: ", "bearer ", "key=a ", "pwd:'",
    "http://", "http://a", "https://a/?", "://",
    "jan 1 ", "1 jan ", "1/1/", "01.01.", "2000-01-",
    "​", "１", "é", "１２３４ ", "a​@",
]  # fmt: skip


def fill(seed: str, size: int) -> str:
    return (seed * (size // len(seed) + 1))[:size]


def best_time(detector, text: str) -> float:
    best = float("inf")
    for _ in range(3):
        started = time.perf_counter()
        for _ in detector.detect(text, strict=True):
            pass
        best = min(best, time.perf_counter() - started)
    return best


@pytest.mark.parametrize("detector", registry.build(), ids=lambda d: d.name)
def test_detector_time_is_linear(detector):
    for seed in ATTACKS:
        small = best_time(detector, fill(seed, SIZE))
        if small < 0.02:
            continue  # too fast to measure growth; certainly not quadratic at this size
        large = best_time(detector, fill(seed, SIZE * 2))
        assert large < small * 3.2 + 0.05, (
            f"{detector.name} on {seed!r}: {small:.3f}s for {SIZE}, {large:.3f}s for {SIZE * 2}"
        )
        assert small < 2.0, f"{detector.name} on {seed!r} took {small:.2f}s for {SIZE} chars"


def test_whole_pipeline_on_hostile_input():
    redactor = Redactor(strict=True)
    text = "".join(fill(seed, 2_000) + "\n" for seed in ATTACKS)
    started = time.perf_counter()
    redactor.redact(text)
    assert time.perf_counter() - started < 20
