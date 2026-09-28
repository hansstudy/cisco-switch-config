"""The audit engine and the structural differ.

`run()` iterates catalogue entries in id order, builds one Context per check, and calls the
registered rule inside a guard so one bad rule cannot destroy a whole audit.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Literal, Mapping

from . import SKILL_VERSION, registry
from .mask import REDACTION_RE, tokenize
from .model import (SEVERITY_RANK, SEVERITIES, Catalogue, Context, Finding, Line, Note,
                    Platform, Profile, Severity)
from .parser import Config

# CSC-MGT-0014 excludes (kind, name) pairs a specific check already reported (4.6, r1 N6).
_GENERIC_REF = "CSC-MGT-0014"
_SPECIFIC_REF = ("CSC-VTY-0003", "CSC-SNMP-0005", "CSC-NTP-0005", "CSC-AAA-0009")
_REF_PARAMS = ("acl_name", "acl_number", "key_id", "group", "vlan")


@dataclass(frozen=True, slots=True)
class Report:
    findings: tuple[Finding, ...]
    notes: tuple[Note, ...]
    platform: Platform
    platform_source: str
    profile: Profile
    skill_version: str
    catalogue_version: str
    counts: Mapping[str, int]
    # additive fields for the JSON `run` block and the table footer (6.3)
    checks_evaluated: int = 0
    severity_min: str = "info"
    category: str = "all"
    role_map_applied: bool = False


def run(cfg: Config, catalogue: Catalogue, *,
        profile: Profile = "campus",
        severity_min: Severity = "info",
        category: Literal["security", "reliability", "all"] = "all") -> Report:
    if profile not in ("campus", "stig"):
        raise ValueError("profile must be campus or stig")
    if severity_min not in SEVERITY_RANK:
        raise ValueError("severity_min is not a severity")
    sink: list[Note] = []
    base = Context(platform=cfg.platform, platform_source=cfg.platform_source,  # type: ignore[arg-type]
                   profile=profile, role_map=cfg.role_map, defaults=cfg.defaults,
                   dialect=cfg.dialect, refs_index=cfg.refs,
                   entry=catalogue.entries[0] if len(catalogue) else None,  # type: ignore[arg-type]
                   skill_version=SKILL_VERSION,
                   catalogue_version=catalogue.catalogue_version, note_sink=sink)
    findings: list[Finding] = []
    evaluated = 0
    for entry in catalogue.entries:                         # id order, not registry order
        if cfg.platform not in entry.platforms or profile not in entry.profiles:
            continue
        if category != "all" and entry.category != category:
            continue
        evaluated += 1
        fn = registry.lookup(entry.id)
        if fn is None:
            sink.append(Note("CSC-SELF-0004", None, f"no rule for {entry.id}"))
            continue
        ctx = replace(base, entry=entry)
        try:
            produced = list(fn(cfg, ctx))
            if not all(isinstance(f, Finding) and f.check_id == entry.id for f in produced):
                raise TypeError("rule yielded a foreign object")
        except Exception:                                   # noqa: BLE001 - the guard is the point
            sink.append(Note("CSC-SELF-0004", None, f"rule error in {entry.id}"))
            continue
        findings.extend(produced)

    findings = _exclude_generic_refs(findings)
    floor = SEVERITY_RANK[severity_min]
    findings = [f for f in findings if SEVERITY_RANK[f.severity] <= floor]
    findings.sort(key=lambda f: (SEVERITY_RANK[f.severity], f.check_id,
                                 f.evidence.line_no or 0))
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    counts["total"] = len(findings)
    return Report(findings=tuple(findings), notes=tuple(cfg.notes) + tuple(sink),
                  platform=cfg.platform, platform_source=cfg.platform_source, profile=profile,
                  skill_version=SKILL_VERSION, catalogue_version=catalogue.catalogue_version,
                  counts=MappingProxyType(counts), checks_evaluated=evaluated,
                  severity_min=severity_min, category=category,
                  role_map_applied=bool(cfg.role_map))


def _exclude_generic_refs(findings: list[Finding]) -> list[Finding]:
    specific = {(k, v) for f in findings if f.check_id in _SPECIFIC_REF
                for k, v in f.params.items() if k in _REF_PARAMS}
    if not specific:
        return findings
    out = []
    for f in findings:
        if f.check_id == _GENERIC_REF and any(
                (k, v) in specific for k, v in f.params.items() if k in _REF_PARAMS):
            continue
        out.append(f)
    return out


# --------------------------------------------------------------------------- differ (3.11)

@dataclass(frozen=True, slots=True)
class Change:
    kind: Literal["added", "removed", "changed", "secret-rotated"]
    mode_path: tuple[str, ...]
    old: Line | None
    new: Line | None
    crosses_checks: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DiffResult:
    changes: tuple[Change, ...]
    notes: tuple[Note, ...]
    old_platform: Platform
    new_platform: Platform
    skill_version: str
    catalogue_version: str


def skeleton(text: str) -> str:
    """The length-elided alignment skeleton of a masked line (3.1.1, r2 N7)."""
    return REDACTION_RE.sub(lambda m: f"[{m.group('cls')}]", " ".join(tokenize(text)))


def _subject_hits(line: Line, catalogue: Catalogue) -> tuple[str, ...]:
    toks = [t.lower() for t in line.tokens]
    if toks[:1] == ["no"]:
        toks = toks[1:]
    out = []
    for e in catalogue.entries:
        for subj in e.subject:
            st = [t.lower() for t in tokenize(subj)]
            if st and toks[:len(st)] == st:
                out.append(e.id)
                break
    return tuple(out)


def diff(old: Config, new: Config, catalogue: Catalogue) -> DiffResult:
    def keyed(cfg: Config) -> dict[tuple, list]:
        out: dict[tuple, list] = {}
        for n in cfg.walk():
            if n.line.kind in ("blank", "comment"):
                continue
            out.setdefault((n.mode_path, skeleton(n.line.text)), []).append(n)
        return out

    a, b = keyed(old), keyed(new)
    removed, added, rotated = [], [], []
    for key, olds in a.items():
        news = b.get(key, [])
        for i, o in enumerate(olds):
            if i < len(news):
                nn = news[i]
                if any(r.changed for r in nn.line.redactions):
                    rotated.append((o, nn))
            else:
                removed.append(o)
    for key, news in b.items():
        olds = a.get(key, [])
        added.extend(news[len(olds):])

    def sig(n) -> tuple:
        t = [x.lower() for x in n.line.tokens]
        return (n.mode_path, tuple(t[:2]) if len(t) >= 3 else tuple(t[:1]))

    changes: list[Change] = []
    pending_added = list(added)
    for o in removed:
        match = next((x for x in pending_added if sig(x) == sig(o)), None)
        if match is not None:
            pending_added.remove(match)
            changes.append(Change("changed", match.mode_path, o.line, match.line,
                                  tuple(dict.fromkeys(_subject_hits(o.line, catalogue)
                                                      + _subject_hits(match.line, catalogue)))))
        else:
            changes.append(Change("removed", o.mode_path, o.line, None,
                                  _subject_hits(o.line, catalogue)))
    for n in pending_added:
        changes.append(Change("added", n.mode_path, None, n.line, _subject_hits(n.line, catalogue)))
    for o, n in rotated:
        changes.append(Change("secret-rotated", n.mode_path, o.line, n.line,
                              _subject_hits(n.line, catalogue)))

    def order(c: Change) -> tuple:
        if c.new is not None:
            return (c.new.line_no, 0)
        return (c.old.line_no if c.old else 0, 1)

    changes.sort(key=order)
    notes = tuple(new.notes)
    return DiffResult(changes=tuple(changes), notes=notes, old_platform=old.platform,
                      new_platform=new.platform, skill_version=SKILL_VERSION,
                      catalogue_version=catalogue.catalogue_version)

