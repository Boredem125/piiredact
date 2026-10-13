"""Country packs.

A pack is a module that exports ``DETECTORS``, a sequence of detectors.
Built-in packs live in this package. Third-party packs register themselves
under the ``piiredact.locales`` entry-point group::

    [project.entry-points."piiredact.locales"]
    br = "piiredact_br:DETECTORS"
"""

from __future__ import annotations

import importlib
from collections.abc import Sequence
from functools import cache, lru_cache
from importlib.metadata import entry_points
from typing import Any

ENTRY_POINT_GROUP = "piiredact.locales"

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
}

_ALIASES = {"uk": "gb", "usa": "us", "ind": "in"}


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
