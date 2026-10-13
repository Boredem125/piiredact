"""pandas support. Needs the ``pandas`` extra: ``pip install "depii[pandas]"``."""

from __future__ import annotations

from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from .structured import entity_for_key

if TYPE_CHECKING:
    import pandas as pd

    from .engine import Redactor


def redact_dataframe(
    frame: pd.DataFrame,
    redactor: Redactor | None = None,
    *,
    columns: Iterable[str] | None = None,
    key_hints: bool = True,
) -> pd.DataFrame:
    """Return a copy of ``frame`` with PII redacted in its text columns.

    ``columns``   columns to process. Default: every object or string column.
    ``key_hints`` redact whole cells of columns whose name says what they
                  hold (``email``, ``ssn``, ``phone``), numeric ones included.
                  Such a column comes back with string values.

    Each distinct value is redacted once, so repetitive columns are cheap.
    """
    try:
        import pandas as pd
    except ImportError as error:
        raise ImportError('redact_dataframe needs pandas: pip install "depii[pandas]"') from error

    if redactor is None:
        from .engine import Redactor

        redactor = Redactor()

    out: pd.DataFrame = frame.copy()
    selected = list(frame.columns) if columns is None else list(columns)
    for name in selected:
        series = frame[name]
        hint = entity_for_key(name) if key_hints else None
        is_text = pd.api.types.is_object_dtype(series) or pd.api.types.is_string_dtype(series)
        if hint is None and not is_text:
            continue

        out[name] = series.map(_converter(redactor, hint, pd))
    return out


def _converter(redactor: Redactor, hint: str | None, pd: Any) -> Any:
    cache: dict[Any, Any] = {}

    def convert(value: Any) -> Any:
        if isinstance(value, (dict, list, tuple, set)):
            return redactor.redact_obj(value)
        if isinstance(value, bool) or pd.isna(value):
            return value
        if hint is None and not isinstance(value, str):
            return value
        if value not in cache:
            text = str(value)
            if hint is not None:
                cache[value] = redactor.operator_for(hint).apply(text, hint) if text else value
            else:
                cache[value] = redactor.redact(text).text
        return cache[value]

    return convert
