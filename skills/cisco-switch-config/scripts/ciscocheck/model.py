"""Frozen records of the object model plus the catalogue loader.

Nothing here carries raw configuration content: `Line.text` is masked by construction and
there is deliberately no `raw` field anywhere.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, Callable, Iterable, Literal, Mapping

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .defaults import DefaultsTable
    from .dialect import DialectTable
    from .refs import ReferenceIndex
    from .parser import Config

Severity = Literal["critical", "high", "medium", "low", "info"]
Category = Literal["security", "reliability"]
Confidence = Literal["deterministic", "heuristic", "manual-review"]
Platform = Literal["ios", "iosxe"]
Profile = Literal["campus", "stig"]
Role = Literal["access", "voice-access", "trunk", "uplink",
               "management", "routed", "unused", "unknown"]
Extent = Literal["value-token", "embedded-substring", "opaque-body", "span"]
LineKind = Literal["command", "comment", "blank", "opaque", "opaque-open", "opaque-close"]

SEVERITIES: tuple[str, ...] = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK: Mapping[str, int] = MappingProxyType({s: i for i, s in enumerate(SEVERITIES)})
CATEGORIES: tuple[str, ...] = ("security", "reliability")
CONFIDENCES: tuple[str, ...] = ("deterministic", "heuristic", "manual-review")
PLATFORMS: tuple[str, ...] = ("ios", "iosxe")
PROFILES: tuple[str, ...] = ("campus", "stig")
ROLES: tuple[str, ...] = ("access", "voice-access", "trunk", "uplink",
                          "management", "routed", "unused", "unknown")
TEST_KINDS: tuple[str, ...] = ("absent", "present", "value", "not-effectively-set", "referential")
AUTHORITIES: tuple[str, ...] = ("DISA-STIG", "CIS", "Cisco", "NSA", "CISA", "NIST")
PARAM_VOCABULARY: frozenset[str] = frozenset(
    {"interface", "vlan", "acl_name", "acl_number", "host", "group", "key_id", "line_range"})


@dataclass(frozen=True, slots=True)
class Redaction:
    cls: str
    length: int | None
    key: str
    extent: Extent
    changed: bool | None


@dataclass(frozen=True, slots=True)
class Line:
    line_no: int
    source_line_no: int
    text: str
    indent: int
    head: str
    tokens: tuple[str, ...]
    kind: LineKind
    redactions: tuple[Redaction, ...]


@dataclass(frozen=True, slots=True)
class Node:
    line: Line
    mode_path: tuple[str, ...]
    # children and parent are excluded from comparison and repr: they form a cycle.
    children: tuple["Node", ...] = field(compare=False, repr=False)
    parent: "Node | None" = field(compare=False, repr=False)


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    kind: str
    node: Node
    from_range: bool
    evidence_line: Line
    role: Role
    role_source: str


@dataclass(frozen=True, slots=True)
class LineRange:
    kind: Literal["con", "vty", "aux"]
    first: int
    last: int
    node: Node | None
    observed: bool


@dataclass(frozen=True, slots=True)
class Note:
    code: str
    line_no: int | None
    detail: str


@dataclass(frozen=True, slots=True)
class Ref:
    authority: Literal["DISA-STIG", "CIS", "Cisco", "NSA", "CISA", "NIST"]
    id: str
    version: str | None
    url: str | None


@dataclass(frozen=True, slots=True)
class Evidence:
    line_no: int | None
    source_line_no: int | None
    text: str
    masked: bool
    redactions: int
    anchor: Literal["line", "range-line", "absent"]


@dataclass(frozen=True, slots=True)
class Finding:
    check_id: str
    severity: Severity
    category: Category
    confidence: Confidence
    catalogue_confidence: Confidence
    title: str
    rationale: str
    evidence: Evidence
    remediation: tuple[str, ...]
    refs: tuple[Ref, ...]
    params: Mapping[str, str]
    platform: Platform
    platform_source: str
    profile: Profile
    skill_version: str
    catalogue_version: str


# --------------------------------------------------------------------------- catalogue

class CatalogueError(Exception):
    """`data/catalogue.json` missing, unparseable or malformed. Carries no config content."""


# family may contain digits (CSC-L2-*); [0-9] not \d, which matches non-ASCII digits
_ID_RE = re.compile(r"^CSC-[A-Z0-9]{2,5}-[0-9]{4}$")
_REQUIRED = ("id", "title", "severity", "category", "confidence", "platforms", "profiles",
             "test_kind", "subject", "rationale", "params_required", "refs")


@dataclass(frozen=True, slots=True)
class CatalogueEntry:
    id: str
    title: str
    severity: Severity
    category: Category
    confidence: Confidence
    platforms: tuple[str, ...]
    profiles: tuple[str, ...]
    test_kind: str
    subject: tuple[str, ...]
    rationale: str
    params_required: tuple[str, ...]
    refs: tuple[Ref, ...]
    defaults_key: str | None = None
    remediation_intent: str | None = None
    remediation: tuple[str, ...] | None = None
    severity_by_profile: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    severity_allowed_overrides: tuple[str, ...] = ()
    min_release: str | None = None
    notes: str | None = None

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "CatalogueEntry":
        """Stdlib field-presence and enum check only."""
        if not isinstance(d, Mapping):
            raise CatalogueError("catalogue entry is not an object")
        cid = d.get("id")
        if not isinstance(cid, str) or not _ID_RE.match(cid) or cid.startswith("CSC-SELF-"):
            raise CatalogueError("catalogue entry has a missing or invalid id")
        for k in _REQUIRED:
            if k not in d:
                raise CatalogueError(f"catalogue entry {cid} lacks field {k}")

        def _enum(name: str, value: Any, allowed: tuple[str, ...]) -> str:
            if value not in allowed:
                raise CatalogueError(f"catalogue entry {cid} field {name} has an invalid value")
            return value

        def _enum_list(name: str, value: Any, allowed: tuple[str, ...]) -> tuple[str, ...]:
            if not isinstance(value, list) or not value:
                raise CatalogueError(f"catalogue entry {cid} field {name} must be a non-empty list")
            return tuple(_enum(name, v, allowed) for v in value)

        refs = []
        raw_refs = d["refs"]
        if not isinstance(raw_refs, list) or not raw_refs:
            raise CatalogueError(f"catalogue entry {cid} field refs must be a non-empty list")
        for r in raw_refs:
            if not isinstance(r, Mapping) or "authority" not in r or "id" not in r:
                raise CatalogueError(f"catalogue entry {cid} has a malformed ref")
            refs.append(Ref(authority=_enum("refs.authority", r["authority"], AUTHORITIES),
                            id=str(r["id"]), version=r.get("version"), url=r.get("url")))
        remediation = d.get("remediation")
        intent = d.get("remediation_intent")
        if (remediation is None) == (intent is None):
            raise CatalogueError(
                f"catalogue entry {cid} needs exactly one of remediation / remediation_intent")
        if remediation is not None:
            if not isinstance(remediation, list) or not all(isinstance(x, str) for x in remediation):
                raise CatalogueError(f"catalogue entry {cid} field remediation must be a list")
            remediation = tuple(remediation)
        params = d["params_required"]
        if not isinstance(params, list) or any(p not in PARAM_VOCABULARY for p in params):
            raise CatalogueError(f"catalogue entry {cid} field params_required is invalid")
        sbp = d.get("severity_by_profile") or {}
        if not isinstance(sbp, Mapping):
            raise CatalogueError(f"catalogue entry {cid} field severity_by_profile is invalid")
        for k, v in sbp.items():
            _enum("severity_by_profile", k, PROFILES)
            _enum("severity_by_profile", v, SEVERITIES)
        overrides = tuple(_enum("severity_allowed_overrides", v, SEVERITIES)
                          for v in (d.get("severity_allowed_overrides") or []))
        test_kind = _enum("test_kind", d["test_kind"], TEST_KINDS)
        subject = d["subject"]
        if not isinstance(subject, list):
            raise CatalogueError(f"catalogue entry {cid} field subject must be a list")
        return cls(
            id=cid, title=str(d["title"]),
            severity=_enum("severity", d["severity"], SEVERITIES),
            category=_enum("category", d["category"], CATEGORIES),
            confidence=_enum("confidence", d["confidence"], CONFIDENCES),
            platforms=_enum_list("platforms", d["platforms"], PLATFORMS),
            profiles=_enum_list("profiles", d["profiles"], PROFILES),
            test_kind=test_kind, subject=tuple(str(s) for s in subject),
            rationale=str(d["rationale"]), params_required=tuple(params), refs=tuple(refs),
            defaults_key=d.get("defaults_key"), remediation_intent=intent,
            remediation=remediation, severity_by_profile=MappingProxyType(dict(sbp)),
            severity_allowed_overrides=overrides, min_release=d.get("min_release"),
            notes=d.get("notes"))


def _default_catalogue_path() -> Path:
    return Path(__file__).resolve().parent.parent.parent / "data" / "catalogue.json"


class Catalogue:
    """Loaded `data/catalogue.json`. Entries are kept sorted by id."""

    __slots__ = ("version", "catalogue_version", "authorities", "entries", "_by_id")

    def __init__(self, version: int, catalogue_version: str,
                 authorities: Mapping[str, Any], entries: Iterable[CatalogueEntry]) -> None:
        self.version = version
        self.catalogue_version = catalogue_version
        self.authorities = MappingProxyType(dict(authorities))
        ordered = tuple(sorted(entries, key=lambda e: e.id))
        by_id: dict[str, CatalogueEntry] = {}
        for e in ordered:
            if e.id in by_id:
                raise CatalogueError(f"duplicate catalogue id {e.id}")
            by_id[e.id] = e
        self.entries = ordered
        self._by_id = by_id

    def get(self, check_id: str) -> CatalogueEntry | None:
        return self._by_id.get(check_id)

    def __iter__(self):
        return iter(self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    @classmethod
    def from_dict(cls, doc: Mapping[str, Any]) -> "Catalogue":
        if not isinstance(doc, Mapping):
            raise CatalogueError("catalogue document is not an object")
        for k in ("version", "catalogue_version", "checks"):
            if k not in doc:
                raise CatalogueError(f"catalogue document lacks field {k}")
        if doc["version"] != 1:
            raise CatalogueError("catalogue document version is not 1")
        checks = doc["checks"]
        if not isinstance(checks, list):
            raise CatalogueError("catalogue field checks is not a list")
        return cls(1, str(doc["catalogue_version"]), doc.get("authorities") or {},
                   (CatalogueEntry.from_dict(c) for c in checks))

    @classmethod
    def load(cls, path: str | None = None) -> "Catalogue":
        p = Path(path) if path else _default_catalogue_path()
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise CatalogueError("data/catalogue.json is missing: this build is incomplete") from None
        except (OSError, ValueError):
            raise CatalogueError("data/catalogue.json is unreadable or not valid JSON") from None
        return cls.from_dict(doc)


# --------------------------------------------------------------------------- Context

_TEMPLATE_RE = re.compile(r"\{\{|\}\}|\{([A-Za-z_][A-Za-z0-9_]*)\}")


def substitute(template: str, params: Mapping[str, str]) -> tuple[str, tuple[str, ...]]:
    """Total `{name}` substitution with `{{`/`}}` escapes.

    Returns the rendered line and the names that were not supplied (rendered `<TODO:name>`).
    Never raises KeyError and never evaluates attribute or index access.
    """
    missing: list[str] = []

    def _sub(m: re.Match[str]) -> str:
        tok = m.group(0)
        if tok == "{{":
            return "{"
        if tok == "}}":
            return "}"
        name = m.group(1)
        if name in params:
            return str(params[name])
        missing.append(name)
        return f"<TODO:{name}>"

    return _TEMPLATE_RE.sub(_sub, template), tuple(missing)


@dataclass(frozen=True, slots=True)
class Context:
    platform: Platform
    platform_source: Literal["given", "inferred-version", "inferred-image",
                             "inferred-surface", "default"]
    profile: Profile
    role_map: Mapping[str, Role]
    defaults: "DefaultsTable"
    dialect: "DialectTable"
    refs_index: "ReferenceIndex"
    entry: CatalogueEntry
    skill_version: str
    catalogue_version: str
    # Engine-internal sink for CSC-SELF-0002 notes; not part of the rule-facing API.
    note_sink: list | None = field(default=None, compare=False, repr=False)

    def finding(self, *,
                line: Line | None = None,
                params: Mapping[str, str] | None = None,
                role_source: str | None = None,
                severity: Severity | None = None,
                title_suffix: str | None = None) -> Finding:
        e = self.entry
        params = dict(params or {})
        # 5. severity
        base = e.severity_by_profile.get(self.profile, e.severity)
        if severity is not None:
            if severity not in e.severity_allowed_overrides:
                raise ValueError(f"severity override not allowed for {e.id}")
            base = severity
        # 4. confidence, computed never passed
        confidence = e.confidence
        if e.confidence == "heuristic" and role_source == "role-map":
            confidence = "deterministic"
        # 2. evidence
        if line is None:
            ev = Evidence(line_no=None, source_line_no=None, text="", masked=False,
                          redactions=0, anchor="absent")
        else:
            is_range = (line.head == "interface" and len(line.tokens) > 1
                        and line.tokens[1].lower() == "range")
            ev = Evidence(line_no=line.line_no, source_line_no=line.source_line_no,
                          text=line.text, masked=len(line.redactions) > 0,
                          redactions=len(line.redactions),
                          anchor="range-line" if is_range else "line")
        # 6. remediation, total substitution
        if e.remediation is not None:
            templates = e.remediation
        else:
            templates = self.dialect.canonical_remediation(e.remediation_intent or "",
                                                           self.platform)
        rendered: list[str] = []
        for t in templates:
            text, missing = substitute(t, params)
            rendered.append(text)
            for name in missing:
                self.note("CSC-SELF-0002", detail=f"check={e.id} var={name}")
        title = e.title + (f" - {title_suffix}" if title_suffix else "")
        return Finding(
            check_id=e.id, severity=base, category=e.category, confidence=confidence,
            catalogue_confidence=e.confidence, title=title, rationale=e.rationale,
            evidence=ev, remediation=tuple(rendered), refs=e.refs,
            params=MappingProxyType({str(k): str(v) for k, v in params.items()}),
            platform=self.platform, platform_source=self.platform_source,
            profile=self.profile, skill_version=self.skill_version,
            catalogue_version=self.catalogue_version)

    def note(self, code: str, *, line_no: int | None = None, detail: str = "") -> Note:
        n = Note(code=code, line_no=line_no, detail=detail)
        if self.note_sink is not None:
            self.note_sink.append(n)
        return n


RuleFn = Callable[["Config", Context], Iterable[Finding]]
ExtractorFn = Callable[["Config", Context], Iterable[Finding]]


def __getattr__(name: str):  # lazy re-export so `from ciscocheck.model import Config` works
    if name == "Config":
        from .parser import Config
        return Config
    raise AttributeError(name)
