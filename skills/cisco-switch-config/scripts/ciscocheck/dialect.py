"""IOS vs IOS-XE surface forms. Operates on masked text only."""
from __future__ import annotations

import json
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Mapping

if TYPE_CHECKING:  # pragma: no cover
    from .model import Node, Platform
    from .parser import Config


class DialectError(Exception):
    """`data/dialect.json` missing or malformed (an unusable build, exit 3)."""


def _data_path(name: str) -> Path:
    return Path(__file__).resolve().parent.parent.parent / "data" / name


class DialectTable:
    """Maps a stable intent id to per-platform token-prefix forms and canonical remediation."""

    __slots__ = ("_intents",)

    def __init__(self, intents: Mapping[str, Mapping[str, Any]]) -> None:
        self._intents = MappingProxyType({k: MappingProxyType(dict(v)) for k, v in intents.items()})

    def intents(self) -> tuple[str, ...]:
        return tuple(sorted(self._intents))

    def forms(self, intent: str, platform: "Platform") -> tuple[str, ...]:
        entry = self._intents.get(intent)
        if entry is None:
            return ()
        return tuple(entry.get(platform, ()))

    def matches(self, cfg: "Config", intent: str, platform: "Platform", *,
                scope: "Node | None" = None) -> tuple["Node", ...]:
        seen: dict[int, "Node"] = {}
        for form in self.forms(intent, platform):
            for node in cfg.find(form, scope=scope):
                seen.setdefault(id(node), node)
        return tuple(sorted(seen.values(), key=lambda n: n.line.line_no))

    def canonical_remediation(self, intent: str, platform: "Platform") -> tuple[str, ...]:
        entry = self._intents.get(intent)
        if entry is None:
            return ()
        rem = entry.get("remediation") or {}
        return tuple(rem.get(platform, ()))

    @classmethod
    def load(cls, path: str | None = None) -> "DialectTable":
        p = Path(path) if path else _data_path("dialect.json")
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise DialectError("data/dialect.json is missing or not valid JSON") from None
        if not isinstance(doc, dict) or doc.get("version") != 1 or not isinstance(
                doc.get("intents"), dict):
            raise DialectError("data/dialect.json has an unexpected shape")
        return cls(doc["intents"])
