"""SARIF 2.1.0 rendering. Imports nothing from `mask`; every snippet is the
already-masked Evidence.text, and the fingerprint is computed over that masked text."""
from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover
    from .engine import Report
    from .model import Catalogue

SCHEMA_URI = ("https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/"
              "sarif-schema-2.1.0.json")
INFORMATION_URI = "https://hans.study/tools/cisco-switch-config/"
_SECURITY_SEVERITY = {"critical": "9.5", "high": "8.0", "medium": "5.5", "low": "3.0",
                      "info": "0.0"}
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "warning",
          "info": "note"}


def fingerprint(check_id: str, evidence_text: str) -> str:
    return hashlib.sha256((check_id + "\n" + evidence_text).encode("utf-8")).hexdigest()


def _result(rule_id: str, level: str, message: str, artifact_uri: str, line: int,
            snippet: str) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": level,
        "message": {"text": message},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": artifact_uri},
            "region": {"startLine": line, "snippet": {"text": snippet}}}}],
        "partialFingerprints": {"primaryLocationLineHash": fingerprint(rule_id, snippet)},
    }


def to_sarif(rep: "Report", *, artifact_uri: str, catalogue: "Catalogue") -> dict:
    rules: list[dict[str, Any]] = []
    seen: set[str] = set()
    results: list[dict[str, Any]] = []
    for f in rep.findings:
        if f.check_id not in seen:
            seen.add(f.check_id)
            entry = catalogue.get(f.check_id)
            refs = entry.refs if entry is not None else f.refs
            rules.append({
                "id": f.check_id,
                "shortDescription": {"text": entry.title if entry is not None else f.title},
                "fullDescription": {"text": f.rationale},
                "help": {"text": "\n".join(f.remediation)},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[f.severity],
                    "tags": [f.category, f.catalogue_confidence,
                             *[f"{r.authority}:{r.id}" for r in refs]],
                },
            })
        absent = f.evidence.anchor == "absent"
        line = f.evidence.source_line_no or f.evidence.line_no or 1
        message = ("Not configured: " + f.title) if absent else f.title
        results.append(_result(f.check_id, _LEVEL[f.severity], message, artifact_uri,
                               1 if absent else line, f.evidence.text))
    for n in rep.notes:
        if n.code not in seen:
            seen.add(n.code)
            rules.append({
                "id": n.code,
                "shortDescription": {"text": "Engine diagnostic note"},
                "fullDescription": {"text": "Produced by the engine itself; not a catalogue check."},
                "help": {"text": "See references/audit-workflow.md for engine notes."},
                "properties": {"security-severity": "0.0", "tags": ["reliability", "engine-note"]},
            })
        results.append(_result(n.code, "note", n.detail, artifact_uri, n.line_no or 1, ""))
    return {
        "$schema": SCHEMA_URI,
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "cisco-switch-config",
                "informationUri": INFORMATION_URI,
                "semanticVersion": rep.skill_version,
                "version": rep.catalogue_version,
                "rules": rules,
            }},
            "results": results,
        }],
    }
