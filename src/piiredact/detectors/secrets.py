"""Detectors for credentials: API keys, tokens, private keys, passwords.

Secrets are not PII in the legal sense, but they leak through the same logs
and tickets and are more damaging, so they are redacted by default.
"""

from __future__ import annotations

import re
from typing import Any

from ..types import SECRET
from .pattern import PatternDetector

_B = r"(?<![A-Za-z0-9_])(?<![A-Za-z0-9_]-)"
_E = r"(?![A-Za-z0-9_])(?!-[A-Za-z0-9_])"

DETECTORS: tuple[Any, ...] = (
    PatternDetector(
        SECRET,
        _B + r"(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}" + _E,
        name="aws_access_key_id",
        score=0.95,
    ),
    PatternDetector(
        SECRET,
        _B + r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})" + _E,
        name="github_token",
        score=0.95,
        needs=("_",),
    ),
    PatternDetector(
        SECRET,
        _B + r"xox[abeoprs]-[A-Za-z0-9-]{10,250}" + _E,
        name="slack_token",
        score=0.95,
        needs=("xox",),
    ),
    PatternDetector(
        SECRET,
        _B + r"[rs]k_(?:live|test)_[A-Za-z0-9]{16,250}" + _E,
        name="stripe_key",
        score=0.95,
        needs=("k_",),
    ),
    PatternDetector(
        SECRET,
        _B + r"AIza[0-9A-Za-z_-]{35}" + _E,
        name="google_api_key",
        score=0.95,
        needs=("AIza",),
    ),
    PatternDetector(
        SECRET,
        _B + r"sk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,250}" + _E,
        name="llm_api_key",
        score=0.9,
        needs=("sk-",),
    ),
    PatternDetector(
        SECRET,
        _B + r"eyJ[A-Za-z0-9_-]{8,4096}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{8,4096}" + _E,
        name="jwt",
        score=0.95,
        needs=("eyJ",),
    ),
    PatternDetector(
        SECRET,
        r"-----BEGIN (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY-----"
        r"[\s\S]{1,16384}?"
        r"-----END (?:[A-Z0-9]{1,20} ){0,3}PRIVATE KEY-----",
        name="private_key_block",
        score=1.0,
        needs=("-----BEGIN",),
    ),
    PatternDetector(
        SECRET,
        r"(?<![A-Za-z0-9])(?:bearer|basic) ([A-Za-z0-9._~+/=-]{16,4096})",
        name="authorization_header",
        score=0.9,
        group=1,
        flags=re.IGNORECASE,
    ),
    # key = value assignments, as found in config files, URLs and log lines.
    # Only the value is redacted so the line stays readable.
    PatternDetector(
        SECRET,
        r"(?<![A-Za-z0-9])(?:password|passwd|pwd|passphrase|secret|client[_-]?secret"
        r"|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|private[_-]?key"
        r"|access[_-]?token|auth[_-]?token|refresh[_-]?token|token)"
        r"[\"']?\s{0,4}[:=]\s{0,4}[\"']?([^\s\"',;&]{4,512})",
        name="secret_assignment",
        score=0.8,
        group=1,
        flags=re.IGNORECASE,
    ),
)
