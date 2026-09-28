"""The boundary writer. The ONLY module under skills/ that writes anything.

Every outgoing line passes through `mask.scrub()`, which DETECTS known unmasked secret
constructs and never rewrites. A hit raises EgressGuardError before a single byte of that
text is written; the CLIs turn it into exit 5.
"""
from __future__ import annotations

import json
import os
import sys
from typing import TYPE_CHECKING, Any, Literal

from . import mask
from .mask import EgressGuardError

if TYPE_CHECKING:  # pragma: no cover
    from .engine import DiffResult, Report

__all__ = ["emit", "emit_error", "write_out", "render_table", "render_json",
           "render_diff_table", "render_diff_json", "EgressGuardError", "exit_code"]

TOOL_NAME = "cisco-switch-config"

# Only these classes print their message: each is constructed by this project and carries no
# configuration content. Anything else prints its class name only.
_MESSAGE_CLASSES = frozenset({"NotACiscoConfigError", "RoleMapError", "SpecError",
                              "EgressGuardError"})
_OWN_PACKAGES = frozenset({"ciscocheck", "ciscobaseline"})

_exit_code = 0


def exit_code() -> int:
    """The exit code recorded by the last emit_error() call (0 when none)."""
    return _exit_code


def _guard(text: str) -> None:
    for line in text.split("\n"):
        hits = mask.scrub(line)          # looked up at call time, so a test can patch it
        if hits:
            raise EgressGuardError(hits[0].cls, hits[0].token_index)


def _flush(stream: Any) -> None:
    try:
        stream.flush()
    except (AttributeError, OSError, ValueError):
        pass


def _console_text(stream: Any, text: str) -> str:
    """The exact string a text stream can carry: characters the console code page cannot encode
    become its replacement character, so the table stays readable on any console."""
    enc = getattr(stream, "encoding", None)
    if not enc:
        return text
    try:
        text.encode(enc)
        return text
    except (UnicodeEncodeError, LookupError):
        return text.encode(enc, "replace").decode(enc, "replace")


def _write(stream: Any, text: str) -> None:
    """Guard, then write, the exact string that reaches the console."""
    out = _console_text(stream, text)
    _guard(out)
    stream.write(out)
    _flush(stream)


def _write_utf8(stream: Any, text: str) -> None:
    """Machine formats (JSON, SARIF) are UTF-8 bytes whatever the console code page. They are
    written straight to the byte buffer (explicit encode, LF line endings, identical to
    --out); a stream with no buffer (an in-process capture) already carries str."""
    buf = getattr(stream, "buffer", None)
    if buf is None:
        stream.write(text)
        _flush(stream)
        return
    _flush(stream)                      # keep ordering with anything already written as text
    buf.write(text.encode("utf-8"))
    _flush(buf)


def emit(text: str, *, stream: Literal["out", "err"] = "out", utf8: bool = False) -> None:
    """Check every line, then write `text` unchanged. Never rewrites.

    `utf8=True` (JSON/SARIF) writes UTF-8 bytes regardless of the console encoding; the guard
    has scanned `text`, and the bytes are exactly `text.encode("utf-8")`. Without it (table,
    messages) the text goes to the console encoding, and the guard scans the exact string
    written, after any replacement-character fallback."""
    target = sys.stdout if stream == "out" else sys.stderr
    if utf8:
        _guard(text)
        _write_utf8(target, text)
    else:
        _write(target, text)


def _message(exc_or_text: BaseException | str) -> str:
    if isinstance(exc_or_text, BaseException):
        cls = type(exc_or_text)
        if cls.__name__ in _MESSAGE_CLASSES and cls.__module__.split(".")[0] in _OWN_PACKAGES:
            return str(exc_or_text)
        return f"{cls.__name__} (internal)"
    return str(exc_or_text)


def emit_error(exc_or_text: BaseException | str, *, line_no: int | None = None,
               code: int = 4) -> None:
    """Type and message only, never a traceback frame; gated by exception class."""
    global _exit_code
    _exit_code = code
    text = "error: " + _message(exc_or_text)
    if line_no is not None:
        text += f" at line {int(line_no)}"
    _guard(text)
    _write(sys.stderr, text + "\n")


def out_conflicts(out: str | None, inputs: "list[str | None]") -> bool:
    """True when --out names an input file - the same path, a hard link to
    it, or a symlink resolving to it (os.path.samefile compares device and inode after
    following links). A --out that does not exist yet cannot be an input."""
    if not out:
        return False
    for p in inputs:
        if not p or p == "-":
            continue
        try:
            if os.path.samefile(out, p):
                return True
        except OSError:
            continue
    return False


OUT_CONFLICT_MESSAGE = "--out names an input file; refusing to overwrite it"


def render_masked(cfg: Any, input_lines: int) -> str:
    """`--format masked`: the whole configuration as masked text, one output line per input
    line, prefixed with the original line number. A line removed by pre-clean shows its
    content-free artefact class; a trimmed trailing blank line is empty. Nothing here is raw:
    every text is a masked Line.text, a fixed literal or a note's content-free class."""
    by_src = {line.source_line_no: line.text for line in cfg.lines()}
    artefacts = {n.line_no: n.detail for n in cfg.notes
                 if n.code == "CSC-SELF-0003" and n.line_no is not None}
    out = []
    for n in range(1, input_lines + 1):
        if n in by_src:
            text = by_src[n]
        elif n in artefacts:
            text = f"! [pre-clean artefact: {artefacts[n]}]"
        else:
            text = ""
        out.append(f"{n:>5}  {text}".rstrip())
    return "\n".join(out) + "\n"


def write_out(path: str, text: str) -> None:
    """The only file writer: exactly `path`, UTF-8, LF, no temporary sibling."""
    _guard(text)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


# --------------------------------------------------------------------------- renderers

_CONF = {"deterministic": "det", "heuristic": "heur", "manual-review": "man"}


def _footer(rep: "Report") -> list[str]:
    parts = [f"{rep.counts.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low", "info")
             if rep.counts.get(s, 0)]
    summary = ", ".join(parts) if parts else "none"
    return [f"{rep.checks_evaluated} checks evaluated - {rep.counts.get('total', 0)} findings "
            f"({summary})",
            f"platform {rep.platform} ({rep.platform_source}) - skill {rep.skill_version} - "
            f"catalogue {rep.catalogue_version}"]


def render_table(rep: "Report") -> str:
    out = [f"{'SEVERITY':<9} {'CHECK':<14} {'CONF':<4} {'LINE':>5}  TITLE"]
    for f in rep.findings:
        ln = f.evidence.source_line_no if f.evidence.source_line_no is not None else "-"
        out.append(f"{f.severity:<9} {f.check_id:<14} {_CONF.get(f.confidence, f.confidence):<4} "
                   f"{ln:>5}  {f.title}")
        if f.evidence.anchor == "absent":
            out.append(f"{'':10}evidence: (not configured)")
        else:
            out.append(f"{'':10}evidence: {f.evidence.text.strip()}")
        for i, r in enumerate(f.remediation):
            out.append(f"{'':10}{'fix: ' if i == 0 else '     '}{r}")
    out.extend(_footer(rep))
    if rep.notes:
        out.append(f"notes: {len(rep.notes)}  (run with --no-notes to hide)")
        for n in rep.notes:
            where = str(n.line_no) if n.line_no is not None else "-"
            out.append(f"  {n.code}  {where:>5}  {n.detail}")
    return "\n".join(out) + "\n"


def finding_dict(f: Any) -> dict:
    return {
        "check_id": f.check_id, "severity": f.severity, "category": f.category,
        "confidence": f.confidence, "catalogue_confidence": f.catalogue_confidence,
        "title": f.title, "rationale": f.rationale,
        "evidence": {"line_no": f.evidence.line_no, "source_line_no": f.evidence.source_line_no,
                     "text": f.evidence.text, "masked": f.evidence.masked,
                     "redactions": f.evidence.redactions, "anchor": f.evidence.anchor},
        "remediation": list(f.remediation),
        "refs": [{"authority": r.authority, "id": r.id, "version": r.version, "url": r.url}
                 for r in f.refs],
        "params": dict(f.params), "platform": f.platform, "platform_source": f.platform_source,
        "profile": f.profile, "skill_version": f.skill_version,
        "catalogue_version": f.catalogue_version,
    }


def _note_dict(n: Any) -> dict:
    return {"code": n.code, "line_no": n.line_no, "detail": n.detail}


def render_json(rep: "Report") -> str:
    doc = {
        "schema_version": 1,
        "tool": {"name": TOOL_NAME, "skill_version": rep.skill_version,
                 "catalogue_version": rep.catalogue_version},
        "run": {"platform": rep.platform, "platform_source": rep.platform_source,
                "profile": rep.profile, "severity_min": rep.severity_min,
                "category": rep.category, "role_map_applied": rep.role_map_applied,
                "checks_evaluated": rep.checks_evaluated},
        "counts": {k: rep.counts.get(k, 0)
                   for k in ("critical", "high", "medium", "low", "info", "total")},
        "findings": [finding_dict(f) for f in rep.findings],
        "notes": [_note_dict(n) for n in rep.notes],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def _line_dict(line: Any) -> dict | None:
    if line is None:
        return None
    return {"line_no": line.line_no, "source_line_no": line.source_line_no, "text": line.text,
            "redactions": len(line.redactions)}


def render_diff_table(d: "DiffResult") -> str:
    out = [f"{'CHANGE':<15} {'OLD':>5} {'NEW':>5}  TEXT"]
    for c in d.changes:
        o = c.old.source_line_no if c.old else "-"
        n = c.new.source_line_no if c.new else "-"
        where = " > ".join(c.mode_path)
        if where:
            out.append(f"{'':15} {'':>5} {'':>5}  [{where}]")
        if c.old is not None and c.kind != "secret-rotated":
            out.append(f"{c.kind:<15} {o:>5} {n:>5}  - {c.old.text.strip()}")
            if c.new is not None:
                out.append(f"{'':15} {'':>5} {'':>5}  + {c.new.text.strip()}")
        else:
            label = c.kind
            out.append(f"{label:<15} {o:>5} {n:>5}  + {c.new.text.strip() if c.new else ''}")
        if c.crosses_checks:
            out.append(f"{'':15} {'':>5} {'':>5}  crosses: {', '.join(c.crosses_checks)}")
    counts = {k: sum(1 for c in d.changes if c.kind == k)
              for k in ("added", "removed", "changed", "secret-rotated")}
    out.append(f"{len(d.changes)} changes ({counts['added']} added, {counts['removed']} removed, "
               f"{counts['changed']} changed, {counts['secret-rotated']} secret-rotated)")
    out.append(f"platform old {d.old_platform} / new {d.new_platform} - skill {d.skill_version}"
               f" - catalogue {d.catalogue_version}")
    return "\n".join(out) + "\n"


def render_diff_json(d: "DiffResult", *, explain: dict | None = None) -> str:
    doc: dict[str, Any] = {
        "schema_version": 1,
        "tool": {"name": TOOL_NAME, "skill_version": d.skill_version,
                 "catalogue_version": d.catalogue_version},
        "run": {"old_platform": d.old_platform, "new_platform": d.new_platform},
        "changes": [{"kind": c.kind, "mode_path": list(c.mode_path), "old": _line_dict(c.old),
                     "new": _line_dict(c.new), "crosses_checks": list(c.crosses_checks)}
                    for c in d.changes],
        "notes": [_note_dict(n) for n in d.notes],
    }
    if explain:
        doc["explain"] = explain
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
