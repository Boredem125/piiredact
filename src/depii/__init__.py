"""depii: detect and redact personally identifiable information.

    >>> import depii
    >>> depii.redact("Mail jane@example.com")
    'Mail [EMAIL]'

No detector finds every piece of PII. Treat the output as reduced-risk data,
not as anonymous data, and measure recall on your own text before relying on it.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from .detectors import Detector, PatternDetector
from .engine import Redactor
from .logfilter import PIIFilter
from .operators import Drop, Hash, Keep, Mask, Operator, Replace, Tokenize, Vault
from .registry import supported_entities
from .structured import redact_obj as _redact_obj
from .types import Result, Span

__version__ = "0.1.0"

__all__ = [
    "Detector",
    "Drop",
    "Hash",
    "Keep",
    "Mask",
    "Operator",
    "PIIFilter",
    "PatternDetector",
    "Redactor",
    "Replace",
    "Result",
    "Span",
    "Tokenize",
    "Vault",
    "__version__",
    "redact",
    "redact_obj",
    "scan",
    "supported_entities",
]


@lru_cache(maxsize=1)
def _default() -> Redactor:
    return Redactor()


def _redactor(options: dict[str, Any]) -> Redactor:
    return Redactor(**options) if options else _default()


def redact(text: str, **options: Any) -> str:
    """Return ``text`` with PII replaced. ``options`` are passed to :class:`Redactor`.

    For repeated calls with options, build one ``Redactor`` and reuse it.
    """
    return _redactor(options).redact(text).text


def scan(text: str, **options: Any) -> list[Span]:
    """Return the PII found in ``text`` without changing it."""
    return _redactor(options).scan(text)


def redact_obj(obj: Any, **options: Any) -> Any:
    """Return a redacted copy of nested data, using the default ``Redactor``.

    ``options`` are those of :func:`depii.structured.redact_obj`.
    """
    return _redact_obj(obj, _default(), **options)
