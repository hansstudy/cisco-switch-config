"""Per-platform implicit defaults.

`effective()` is the supported way to write an absence check: it looks for the positive and
negated surface forms (through the dialect table) and falls back to the platform default.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Mapping

from .mask import tokenize

if TYPE_CHECKING:  # pragma: no cover
    from .dialect import DialectTable
    from .model import Node, Platform
    from .parser import Config


class DefaultsError(Exception):
    """`data/defaults.json` missing or malformed (an unusable build, exit 3)."""


@dataclass(frozen=True, slots=True)
class DefaultValue:
    state: Literal["on", "off", "unset"]
    value: str | None
    shown_when_default: bool


@dataclass(frozen=True, slots=True)
class Effective:
    value: str | None
    state: Literal["on", "off", "unset"]
    observed: bool


_UNSET = DefaultValue(state="unset", value=None, shown_when_default=False)


def _data_path(name: str) -> Path:
    return Path(__file__).resolve().parent.parent.parent / "data" / name


class DefaultsTable:
    __slots__ = ("_doc", "_dialect", "cisco_heads", "mode_heads", "line_universe")

    def __init__(self, doc: Mapping[str, Any], dialect: "DialectTable") -> None:
        self._doc = doc
        self._dialect = dialect
        self.cisco_heads: frozenset[str] = frozenset(h.lower() for h in doc.get("cisco_heads", ()))
        self.mode_heads: Mapping[str, tuple[str, ...]] = {
            k: tuple(v) for k, v in (doc.get("mode_heads") or {}).items()}
        self.line_universe: Mapping[str, tuple[int, int] | None] = {
            k: (tuple(v) if v is not None else None)
            for k, v in (doc.get("line_universe") or {"con": [0, 0], "aux": None}).items()}

    def _key(self, platform: "Platform", key: str) -> Mapping[str, Any] | None:
        plat = (self._doc.get("platforms") or {}).get(platform) or {}
        return (plat.get("keys") or {}).get(key)

    def keys(self, platform: "Platform") -> tuple[str, ...]:
        plat = (self._doc.get("platforms") or {}).get(platform) or {}
        return tuple(sorted(plat.get("keys") or {}))

    def value(self, platform: "Platform", key: str) -> DefaultValue:
        k = self._key(platform, key)
        if k is None:
            return _UNSET
        return DefaultValue(state=k.get("state", "unset"), value=k.get("value"),
                            shown_when_default=bool(k.get("shown_when_default", False)))

    def vty_universe(self, platform: "Platform") -> tuple[int, int]:
        plat = (self._doc.get("platforms") or {}).get(platform) or {}
        u = plat.get("vty_universe") or [0, 15]
        return int(u[0]), int(u[1])

    def forms(self, platform: "Platform", key: str) -> tuple[str, ...]:
        """Positive surface forms for a key: its dialect intent, else its explicit `form`,
        else the key name as a literal token-prefix (dots become spaces)."""
        k = self._key(platform, key) or {}
        intent = k.get("intent")
        if intent:
            forms = self._dialect.forms(intent, platform)
            if forms:
                return forms
        if k.get("form"):
            return (str(k["form"]),)
        return (key.replace(".", " "),)

    def value_slots(self, platform: "Platform", key: str) -> tuple[int, int]:
        """(min, max) trailing value tokens a key's form takes; (0, 0) = the exact form."""
        k = self._key(platform, key) or {}
        v = k.get("values") or [0, 0]
        return int(v[0]), int(v[1])

    def effective(self, cfg: "Config", platform: "Platform", key: str, *,
                  scope: "Node | None" = None) -> Effective:
        """A form matches only when the line equals it exactly or its trailing tokens are the
        key's declared value slots: `ip dhcp snooping vlan 10`
        is a sub-command, never `ip dhcp snooping`."""
        lo, hi = self.value_slots(platform, key)
        best = None                  # (line_no, state, value)
        for form in self.forms(platform, key):
            width = len(tokenize(form))
            for node in cfg.find(form, scope=scope):
                rest = node.line.tokens[width:]
                if not lo <= len(rest) <= hi:
                    continue
                cand = (node.line.line_no, "on", " ".join(rest) if rest else None)
                if best is None or cand[0] > best[0]:
                    best = cand
            for node in cfg.find("no " + form, scope=scope):
                if len(node.line.tokens) - width - 1 > hi:     # a `no` form may omit values
                    continue
                cand = (node.line.line_no, "off", None)
                if best is None or cand[0] > best[0]:
                    best = cand
        if best is not None:
            return Effective(value=best[2], state=best[1], observed=True)
        dv = self.value(platform, key)
        return Effective(value=dv.value, state=self._release_state(cfg, platform, key, dv.state),
                         observed=False)

    def _release_state(self, cfg: "Config", platform: "Platform", key: str, base: str) -> str:
        """Additive `state_from_release`: {"16": "off"} means the default is
        off from major release 16. An unknown release keeps the fail-safe base state."""
        table = (self._key(platform, key) or {}).get("state_from_release")
        if not table:
            return base
        major = cfg.value_of(r"(?i)^version ([0-9]+)\.")
        if major is None:
            return base
        state = base
        for threshold in sorted(table, key=int):
            if int(major) >= int(threshold):
                state = table[threshold]
        return state

    @classmethod
    def load(cls, path: str | None, dialect: "DialectTable") -> "DefaultsTable":
        p = Path(path) if path else _data_path("defaults.json")
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raise DefaultsError("data/defaults.json is missing or not valid JSON") from None
        if not isinstance(doc, dict) or doc.get("version") != 1:
            raise DefaultsError("data/defaults.json has an unexpected shape")
        return cls(doc, dialect)
