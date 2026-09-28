#!/usr/bin/env python3
"""Build skills/cisco-switch-config/data/catalogue.json from catalogue-src/*.yaml.

Usage:
    python packaging/build_catalogue.py --out skills/cisco-switch-config/data/catalogue.json
    python packaging/build_catalogue.py --check
    python packaging/build_catalogue.py --docs skills/cisco-switch-config/references/check-catalogue.md

`pyyaml` and `jsonschema` are development-time dependencies only; nothing under
`skills/` imports either. This script is not shipped inside the skill directory.

Determinism rules, frozen so byte-identity is achievable:
  1. Load every catalogue-src/*.yaml except _meta.yaml, sorted by filename.
  2. Concatenate entries, then sort by id (ASCII).
  3. Emit {"version": 1, "catalogue_version": <from _meta>, "authorities": {...},
     "checks": [...]}.
  4. json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True,
     separators=(",", ": ")) plus one trailing "\n".
  5. Write with encoding="utf-8", newline="\n", no BOM.
  6. No timestamps, no host names, no absolute paths, no build counters anywhere
     in the output.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

import yaml

try:
    import jsonschema
except ImportError:  # pragma: no cover - dev dependency missing
    jsonschema = None

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "catalogue-src"
SCHEMA_PATH = ROOT / "skills" / "cisco-switch-config" / "data" / "schema" / "catalogue.schema.json"
DEFAULT_OUT = ROOT / "skills" / "cisco-switch-config" / "data" / "catalogue.json"
DEFAULT_DOCS = ROOT / "skills" / "cisco-switch-config" / "references" / "check-catalogue.md"

ID_RE = re.compile(r"^CSC-([A-Z0-9]{2,5})-[0-9]{4}$")
SELF_RE = re.compile(r"^CSC-SELF-")
PLACEHOLDER_RE = re.compile(r"(?<!\{)\{([a-zA-Z_][a-zA-Z0-9_]*)\}(?!\})")
CLOSED_VOCAB = {
    "interface", "vlan", "acl_name", "acl_number",
    "host", "group", "key_id", "line_range",
}


class CatalogueError(Exception):
    """Carries file, entry id and field name so the CLI can print one clean line."""

    def __init__(self, file: str, entry_id: str | None, field: str, detail: str):
        self.file = file
        self.entry_id = entry_id
        self.field = field
        self.detail = detail
        super().__init__(f"{file}: {entry_id or '<no id>'}: {field}: {detail}")


def load_meta() -> dict:
    meta_path = SRC_DIR / "_meta.yaml"
    with meta_path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_family_files() -> list[Path]:
    files = sorted(p for p in SRC_DIR.glob("*.yaml") if p.name != "_meta.yaml")
    return files


def load_entries() -> list[dict]:
    entries: list[dict] = []
    for path in load_family_files():
        try:
            with path.open("r", encoding="utf-8") as fh:
                docs = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise CatalogueError(path.name, None, "<file>", f"YAML parse error: {exc}") from exc
        if not docs:
            continue
        if not isinstance(docs, list):
            raise CatalogueError(path.name, None, "<file>", "expected a YAML list of entries")
        for entry in docs:
            entry["__file__"] = path.name
            entries.append(entry)
    return entries


def validate_schema(entry: dict, schema: dict) -> None:
    fname = entry["__file__"]
    eid = entry.get("id")
    clean = {k: v for k, v in entry.items() if k != "__file__"}
    if jsonschema is None:
        raise RuntimeError(
            "jsonschema is required to build/validate the catalogue "
            "(development dependency; not shipped under skills/)"
        )
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    validator = validator_cls(schema)
    errors = sorted(validator.iter_errors(clean), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        field = ".".join(str(p) for p in first.path) or "<entry>"
        raise CatalogueError(fname, eid, field, first.message)


def validate_id_pattern(entry: dict) -> None:
    fname = entry["__file__"]
    eid = entry.get("id", "")
    if SELF_RE.match(eid):
        raise CatalogueError(fname, eid, "id", "CSC-SELF- is reserved for engine notes")
    m = ID_RE.match(eid)
    if not m:
        raise CatalogueError(fname, eid, "id", "does not match ^CSC-[A-Z]{2,5}-[0-9]{4}$")


def validate_no_duplicates(entries: list[dict]) -> None:
    seen: dict[str, str] = {}
    for entry in entries:
        eid = entry.get("id")
        fname = entry["__file__"]
        if eid in seen:
            raise CatalogueError(fname, eid, "id", f"duplicate id, first seen in {seen[eid]}")
        seen[eid] = fname


def validate_refs(entry: dict) -> None:
    fname = entry["__file__"]
    eid = entry.get("id")
    for ref in entry.get("refs", []):
        if "authority" not in ref or "id" not in ref:
            raise CatalogueError(fname, eid, "refs", "each ref requires authority and id")
        if ref["authority"] == "CIS":
            if "title" in ref:
                raise CatalogueError(fname, eid, "refs.title", "a CIS ref may not carry a title field")
            if not ref.get("version"):
                raise CatalogueError(fname, eid, "refs.version", "a CIS ref requires a version")


def template_vars(text: str) -> set[str]:
    return set(PLACEHOLDER_RE.findall(text))


def validate_template_vars(entry: dict) -> None:
    fname = entry["__file__"]
    eid = entry.get("id")
    lines = entry.get("remediation") or []
    used: set[str] = set()
    for line in lines:
        used |= template_vars(line)
    outside = used - CLOSED_VOCAB
    if outside:
        raise CatalogueError(
            fname, eid, "remediation",
            f"variable(s) outside the closed vocabulary: {sorted(outside)}",
        )
    required = set(entry.get("params_required") or [])
    if entry.get("remediation") is not None and used != required:
        raise CatalogueError(
            fname, eid, "params_required",
            f"template variables {sorted(used)} != params_required {sorted(required)}",
        )


def validate_defaults_key(entry: dict) -> None:
    fname = entry["__file__"]
    eid = entry.get("id")
    tk = entry.get("test_kind")
    # Presence, not non-null: a not-effectively-set entry with no matching defaults.json key
    # yet carries `defaults_key: null` (still "required" in the JSON-Schema/field-presence
    # sense); a non-not-effectively-set entry must not carry the field at all, null or not.
    present = "defaults_key" in entry
    if tk == "not-effectively-set" and not present:
        raise CatalogueError(fname, eid, "defaults_key",
                              "required (string or null) when test_kind is not-effectively-set")
    if tk != "not-effectively-set" and present:
        raise CatalogueError(fname, eid, "defaults_key", "must be absent unless test_kind is not-effectively-set")


def build_document(check_out_of_date_only: bool = False) -> dict:
    meta = load_meta()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    entries = load_entries()

    for entry in entries:
        validate_id_pattern(entry)
        validate_refs(entry)
        validate_template_vars(entry)
        validate_defaults_key(entry)
        validate_schema(entry, schema)
    validate_no_duplicates(entries)

    checks = []
    for entry in sorted(entries, key=lambda e: e["id"]):
        clean = {k: v for k, v in entry.items() if k != "__file__"}
        checks.append(clean)

    return {
        "version": 1,
        "catalogue_version": meta["catalogue_version"],
        "authorities": meta["authorities"],
        "checks": checks,
    }


def serialise(doc: dict) -> str:
    return json.dumps(doc, ensure_ascii=False, indent=2, sort_keys=True,
                       separators=(",", ": ")) + "\n"


def write_docs(doc: dict, out_path: Path) -> None:
    families: dict[str, list[dict]] = {}
    for check in doc["checks"]:
        fam = check["id"].split("-")[1]
        families.setdefault(fam, []).append(check)

    lines = ["# Check catalogue", "", f"Catalogue version: `{doc['catalogue_version']}`. "
             f"{len(doc['checks'])} checks.", "", "## Table of contents", ""]
    for fam in families:
        lines.append(f"- [{fam}](#{fam.lower()})")
    lines.append("")

    for fam, checks in families.items():
        lines.append(f"## {fam}")
        lines.append("")
        lines.append("| id | title | severity | category | confidence |")
        lines.append("|---|---|---|---|---|")
        for c in checks:
            lines.append(
                f"| {c['id']} | {c['title']} | {c['severity']} | {c['category']} | {c['confidence']} |"
            )
        lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines).rstrip("\n") + "\n", encoding="utf-8", newline="\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the cisco-switch-config catalogue")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                         help="path to write skills/cisco-switch-config/data/catalogue.json")
    parser.add_argument("--check", action="store_true",
                         help="exit 1 if the committed file differs from a fresh build")
    parser.add_argument("--docs", nargs="?", const=str(DEFAULT_DOCS), default=None,
                         help="also (re)generate references/check-catalogue.md")
    args = parser.parse_args(argv)

    try:
        doc = build_document()
    except CatalogueError as exc:
        print(f"catalogue build failed: {exc}", file=sys.stderr)
        return 1

    text = serialise(doc)

    if args.check:
        target = args.out
        if not target.exists():
            print(f"catalogue build failed: {target} does not exist", file=sys.stderr)
            return 1
        current = target.read_text(encoding="utf-8")
        if current != text:
            print(f"catalogue build failed: {target} is stale relative to catalogue-src/**",
                  file=sys.stderr)
            return 1
        print(f"{target} is up to date")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(text, encoding="utf-8", newline="\n")
    print(f"wrote {args.out} ({len(doc['checks'])} checks)")

    if args.docs is not None:
        write_docs(doc, Path(args.docs))
        print(f"wrote {args.docs}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
