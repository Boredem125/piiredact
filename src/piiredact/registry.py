"""Assemble the detector list for a Redactor."""

from __future__ import annotations

from collections.abc import Iterable

from . import locales as _locales
from .detectors.base import Detector
from .detectors.global_ import DETECTORS as _GLOBAL
from .detectors.secrets import DETECTORS as _SECRETS


def build(
    locales: Iterable[str] | None = None,
    entities: Iterable[str] | None = None,
    exclude_entities: Iterable[str] | None = None,
    extra: Iterable[Detector] = (),
) -> tuple[Detector, ...]:
    """Return global, secret, locale and extra detectors, filtered by entity.

    ``locales=None`` means every installed pack. Detectors that emit several
    entity types declare ``entity = "*"`` and are filtered per span later.
    """
    codes = _locales.available() if locales is None else list(locales)
    detectors: list[Detector] = [*_GLOBAL, *_SECRETS]
    for code in codes:
        detectors.extend(_locales.load(code))
    detectors.extend(extra)

    wanted = None if entities is None else set(entities)
    unwanted = set(exclude_entities or ())
    return tuple(
        detector
        for detector in detectors
        if detector.entity == "*"
        or ((wanted is None or detector.entity in wanted) and detector.entity not in unwanted)
    )


def supported_entities(locales: Iterable[str] | None = None) -> list[str]:
    """Entity types the built-in and installed detectors can emit."""
    return sorted({d.entity for d in build(locales) if d.entity != "*"})
