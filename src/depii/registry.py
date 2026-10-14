"""Assemble the detector list for a Redactor."""

from __future__ import annotations

from collections.abc import Iterable

from . import locales as _locales
from .detectors.addresses import DETECTORS as _ADDRESSES
from .detectors.base import Detector
from .detectors.global_ import DETECTORS as _GLOBAL
from .detectors.labels import DETECTORS as _LABELS
from .detectors.names import DETECTORS as _NAMES
from .detectors.secrets import DETECTORS as _SECRETS


def build(
    locales: Iterable[str] | None = None,
    entities: Iterable[str] | None = None,
    exclude_entities: Iterable[str] | None = None,
    extra: Iterable[Detector] = (),
    *,
    contextual: bool = True,
) -> tuple[Detector, ...]:
    """Return global, secret, locale and extra detectors, filtered by entity.

    ``locales=None`` means every installed pack. Detectors that emit several
    entity types declare ``entity = "*"`` and are filtered per span later.
    ``contextual=False`` leaves out the label, name and address detectors.
    """
    codes = _locales.available() if locales is None else list(locales)
    detectors: list[Detector] = [*_GLOBAL, *_SECRETS]
    if contextual:
        detectors += [*_ADDRESSES, *_LABELS, *_NAMES]
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
    names: set[str] = set()
    for detector in build(locales):
        if detector.entity == "*":
            names |= set(getattr(detector, "entities", ()))
        else:
            names.add(detector.entity)
    # The engine's combination pass adds these on top of the detectors.
    from .quasi import QUASI_ENTITIES

    return sorted(names | QUASI_ENTITIES)
