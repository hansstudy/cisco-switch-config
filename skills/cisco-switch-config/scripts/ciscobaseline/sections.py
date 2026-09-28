"""The section list of the baseline: `data/baseline/sections.json`.

Each section names one `string.Template` file under `data/baseline/`, its position in the
paste order, and an optional named predicate that decides whether it is emitted at all.
`parts` names the per-item and fragment templates the section's renderer fills and splices
in; templates hold no loops and no conditionals. A missing or malformed build file raises
`BaselineBuildError`, which the CLI reports as an unusable build (exit 3).
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from string import Template

__all__ = ["Section", "BaselineBuildError", "load_sections", "load_template", "data_dir",
           "PREDICATES"]

# The only predicate names a section may carry; render.py evaluates them.
PREDICATES = frozenset({"uplinks", "access_ports", "unused_ports"})

_NAME_RE = re.compile(r"^[0-9]{2}-[a-z0-9-]+$")
_FILE_RE = re.compile(r"^[0-9]{2}-[a-z0-9-]+(?:\.[a-z0-9-]+)?\.tmpl$")


class BaselineBuildError(Exception):
    """The generator's own data files are missing or malformed. Names a file, no content."""


@dataclass(frozen=True, slots=True)
class Section:
    name: str
    order: int
    template: str                                # filename under data/baseline/
    when: str | None                             # a named predicate, e.g. "unused_ports"
    parts: tuple[tuple[str, str], ...] = ()      # (part name, template filename)


def data_dir() -> Path:
    """`data/baseline/` of the installed skill."""
    return Path(__file__).resolve().parent.parent.parent / "data" / "baseline"


def _read(path: Path) -> str:
    try:
        with open(path, "rb") as fh:
            return fh.read().decode("utf-8")
    except (OSError, UnicodeDecodeError):
        raise BaselineBuildError(f"baseline build file missing or unreadable: {path.name}") \
            from None


def load_template(name: str, base: Path | None = None) -> Template:
    if not _FILE_RE.match(name):
        raise BaselineBuildError(f"baseline template name is malformed: {name}")
    text = _read((base or data_dir()) / name).replace("\r\n", "\n")
    return Template(text[:-1] if text.endswith("\n") else text)


def load_sections(path: str | None = None) -> tuple[Section, ...]:
    """Load and check `sections.json`. Every named template must exist."""
    p = Path(path) if path else data_dir() / "sections.json"
    try:
        doc = json.loads(_read(p))
    except json.JSONDecodeError:
        raise BaselineBuildError(f"baseline build file is not valid JSON: {p.name}") from None
    if not isinstance(doc, dict) or doc.get("version") != 1 or \
            not isinstance(doc.get("sections"), list) or not doc["sections"]:
        raise BaselineBuildError(f"baseline build file is malformed: {p.name}")
    out: list[Section] = []
    for item in doc["sections"]:
        if not isinstance(item, dict) or set(item) - {"name", "order", "template", "when",
                                                      "parts"}:
            raise BaselineBuildError(f"baseline section entry is malformed in {p.name}")
        name, order, tmpl = item.get("name"), item.get("order"), item.get("template")
        when = item.get("when")
        parts = item.get("parts", {})
        if not (isinstance(name, str) and _NAME_RE.match(name) and isinstance(order, int)
                and not isinstance(order, bool) and isinstance(tmpl, str)
                and isinstance(parts, dict)
                and all(isinstance(k, str) and isinstance(v, str) for k, v in parts.items())):
            raise BaselineBuildError(f"baseline section entry is malformed in {p.name}")
        if when is not None and when not in PREDICATES:
            raise BaselineBuildError(f"baseline section {name} names an unknown predicate")
        for fname in (tmpl, *parts.values()):
            load_template(fname, p.parent)                 # existence and name check
        out.append(Section(name, order, tmpl, when, tuple(parts.items())))
    orders = [s.order for s in out]
    if orders != sorted(orders) or len(set(orders)) != len(orders) or \
            len({s.name for s in out}) != len(out):
        raise BaselineBuildError(f"baseline sections are not uniquely ordered in {p.name}")
    return tuple(out)
