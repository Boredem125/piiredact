"""A ``logging`` filter that redacts records before they are written."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engine import Redactor

FAILED = "[piiredact: redaction failed, message withheld]"

_STANDARD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", (), None))) | {
    "message",
    "asctime",
    "taskName",
}
_FORMATTER = logging.Formatter()


class PIIFilter(logging.Filter):
    """Redact the message, exception text, stack info and ``extra`` fields of a record.

    Attach it to **handlers**, not loggers: a filter on a logger does not see
    records that propagate up from child loggers. ::

        handler = logging.StreamHandler()
        handler.addFilter(PIIFilter())

    If redaction itself fails, the message is replaced with a fixed notice.
    A logging filter must not raise, and must not let the original through.
    """

    def __init__(self, redactor: Redactor | None = None, *, redact_extra: bool = True) -> None:
        super().__init__()
        if redactor is None:
            from .engine import Redactor

            redactor = Redactor()
        self.redactor = redactor
        self.redact_extra = redact_extra

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            self._redact(record)
        except Exception:
            record.msg = FAILED
            record.args = None
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True

    def _redact(self, record: logging.LogRecord) -> None:
        redact = self.redactor.redact
        # Format first, so PII passed as arguments is covered too.
        record.msg = redact(record.getMessage()).text
        record.args = None
        if record.exc_info and not record.exc_text:
            record.exc_text = _FORMATTER.formatException(record.exc_info)
        if record.exc_text:
            # Formatters reuse exc_text when it is set, so the redacted
            # version is what ends up in the output.
            record.exc_text = redact(record.exc_text).text
        if record.stack_info:
            record.stack_info = redact(record.stack_info).text
        if self.redact_extra:
            for name, value in vars(record).items():
                if name not in _STANDARD_ATTRS and isinstance(value, (str, dict, list, tuple)):
                    setattr(record, name, self.redactor.redact_obj({name: value})[name])
