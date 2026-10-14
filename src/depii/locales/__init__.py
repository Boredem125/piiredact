"""Country packs.

A pack is a module that exports ``DETECTORS``, a sequence of detectors.
Built-in packs live in this package. Third-party packs register themselves
under the ``depii.locales`` entry-point group::

    [project.entry-points."depii.locales"]
    br = "depii_br:DETECTORS"
"""

from __future__ import annotations

import importlib
from collections.abc import Sequence
from functools import cache
from importlib.metadata import entry_points
from typing import Any

ENTRY_POINT_GROUP = "depii.locales"

# locale code -> module name inside this package
BUILTIN: dict[str, str] = {
    "us": "us",
    "in": "in_",
    "gb": "gb",
    "de": "de",
    "fr": "fr",
    "es": "es",
    "it": "it",
    "nl": "nl",
    "eu": "eu",
    # added in 0.2
    "ca": "ca",
    "au": "au",
    "nz": "nz",
    "br": "br",
    "mx": "mx",
    "cl": "cl",
    "ar": "ar",
    "sg": "sg",
    "jp": "jp",
    "kr": "kr",
    "cn": "cn",
    "pl": "pl",
    "se": "se",
    "dk": "dk",
    "fi": "fi",
    "be": "be",
    "pt": "pt",
    "ie": "ie",
    "at": "at",
    "ch": "ch",
    "no": "no",
    "tr": "tr",
    "za": "za",
    "ae": "ae",
}

_ALIASES = {"uk": "gb", "usa": "us", "ind": "in", "uae": "ae", "kor": "kr", "chn": "cn"}


def _plugins() -> dict[str, Any]:
    return {ep.name.lower(): ep for ep in entry_points(group=ENTRY_POINT_GROUP)}


def available() -> list[str]:
    """Codes of every installed locale pack, built-in and third-party."""
    return sorted({*BUILTIN, *_plugins()})


@cache
def load(code: str) -> tuple[Any, ...]:
    """Return the detectors of one locale pack."""
    key = _ALIASES.get(code.lower(), code.lower())
    if key in BUILTIN:
        module = importlib.import_module(f"{__name__}.{BUILTIN[key]}")
        return tuple(module.DETECTORS)
    plugin = _plugins().get(key)
    if plugin is None:
        raise ValueError(f"unknown locale {code!r}; available: {', '.join(available())}")
    loaded = plugin.load()
    detectors: Sequence[Any] = getattr(loaded, "DETECTORS", loaded)
    return tuple(detectors)
