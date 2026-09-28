"""Rule registry. Registration pushes; the registry never pulls.

This module imports NOTHING from `ciscocheck.rules`, ever.
"""
from __future__ import annotations

from typing import Callable

from .model import ExtractorFn, RuleFn

_RULES: dict[str, RuleFn] = {}
_EXTRACTORS: dict[str, ExtractorFn] = {}
_SUPPLIES: dict[str, tuple[str, ...]] = {}


def _check_new(check_id: str) -> None:
    if check_id in _RULES or check_id in _EXTRACTORS:
        raise ValueError(f"check id {check_id} is registered twice")


def register(check_id: str, fn: RuleFn, *, supplies: tuple[str, ...] = ()) -> None:
    _check_new(check_id)
    _RULES[check_id] = fn
    _SUPPLIES[check_id] = tuple(supplies)


def register_extractor(check_id: str, fn: ExtractorFn, *,
                       supplies: tuple[str, ...] = ()) -> None:
    _check_new(check_id)
    _EXTRACTORS[check_id] = fn
    _SUPPLIES[check_id] = tuple(supplies)


def rules() -> tuple[tuple[str, RuleFn], ...]:
    return tuple(sorted(_RULES.items()))


def extractors() -> tuple[tuple[str, ExtractorFn], ...]:
    return tuple(sorted(_EXTRACTORS.items()))


def supplies_of(check_id: str) -> tuple[str, ...]:
    return _SUPPLIES.get(check_id, ())


def lookup(check_id: str) -> RuleFn | ExtractorFn | None:
    """The rule or extractor bound to a check id (engine use)."""
    return _RULES.get(check_id) or _EXTRACTORS.get(check_id)


def clear() -> None:
    """Test isolation only."""
    _RULES.clear()
    _EXTRACTORS.clear()
    _SUPPLIES.clear()


def rule(check_id: str, *, supplies: tuple[str, ...] = ()) -> Callable[[RuleFn], RuleFn]:
    def deco(fn: RuleFn) -> RuleFn:
        register(check_id, fn, supplies=supplies)
        return fn
    return deco


def extractor(check_id: str, *,
              supplies: tuple[str, ...] = ()) -> Callable[[ExtractorFn], ExtractorFn]:
    def deco(fn: ExtractorFn) -> ExtractorFn:
        register_extractor(check_id, fn, supplies=supplies)
        return fn
    return deco
