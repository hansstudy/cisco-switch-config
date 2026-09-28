#!/usr/bin/env python3
"""Build the shippable skill zip for cisco-switch-config.

Zips ONLY skills/cisco-switch-config/**, rooted at skills/cisco-switch-config/SKILL.md - one of
the two layouts claude.ai documents (the skill directory itself is the zip root, so SKILL.md
lands at the zip's top level, not behind a `cisco-switch-config/` prefix).

Usage:
    python3 packaging/build_skill_zip.py --out dist

Writes exactly one file: <out>/cisco-switch-config-<version>.zip, where <version> is read from
.claude-plugin/plugin.json. Refuses to write anything outside <out>. Exits 1 if SKILL.md is
missing (wrong depth or not authored), or if the
uncompressed total exceeds 30 MB.

Stdlib only. This script is packaging tooling, not shipped code, so it is out of scope for the
skills/-only import and unsafe-calls scanners in verify_package.py.
"""
from __future__ import annotations

import argparse
import json
import sys
import zipfile
from pathlib import Path

MAX_UNCOMPRESSED_BYTES = 30 * 1024 * 1024  # uncompressed total under 30 MB
SKILL_NAME = "cisco-switch-config"

# Never shipped, even if present on disk (editor/OS cruft that must not reach a public zip).
EXCLUDE_NAMES = {"__pycache__", ".DS_Store", "Thumbs.db", "desktop.ini"}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}


def repo_root() -> Path:
    # packaging/build_skill_zip.py -> repo root is this file's grandparent.
    return Path(__file__).resolve().parent.parent


def iter_skill_files(skill_dir: Path):
    for path in sorted(skill_dir.rglob("*")):
        if path.is_dir():
            continue
        if any(part in EXCLUDE_NAMES for part in path.parts):
            continue
        if path.suffix in EXCLUDE_SUFFIXES:
            continue
        yield path


def read_version(root: Path) -> str:
    plugin_json = root / ".claude-plugin" / "plugin.json"
    if not plugin_json.is_file():
        print(f"error: {plugin_json} does not exist; cannot determine the version to build", file=sys.stderr)
        raise SystemExit(1)
    try:
        data = json.loads(plugin_json.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"error: {plugin_json} does not parse as JSON: {exc}", file=sys.stderr)
        raise SystemExit(1)
    version = data.get("version")
    if not version or not isinstance(version, str):
        print(f"error: {plugin_json} has no string 'version' field", file=sys.stderr)
        raise SystemExit(1)
    return version


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="dist directory to write the zip into")
    args = parser.parse_args(argv)

    root = repo_root()
    skill_dir = root / "skills" / SKILL_NAME
    skill_md = skill_dir / "SKILL.md"

    if not skill_md.is_file():
        print(
            f"error: {skill_md} does not exist. The zip must be rooted at "
            f"skills/{SKILL_NAME}/SKILL.md.",
            file=sys.stderr,
        )
        return 1

    out_dir = Path(args.out)
    # Refuse to write outside the named --out directory.
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir = out_dir.resolve()

    files = list(iter_skill_files(skill_dir))
    if not files:
        print(f"error: {skill_dir} contains no files to zip", file=sys.stderr)
        return 1

    total_bytes = 0
    print(f"Files to package (rooted at {skill_dir}):")
    for f in files:
        size = f.stat().st_size
        total_bytes += size
        arcname = f.relative_to(skill_dir).as_posix()
        print(f"  {size:>10}  {arcname}")

    print(f"Uncompressed total: {total_bytes} bytes ({total_bytes / (1024 * 1024):.2f} MiB)")
    if total_bytes > MAX_UNCOMPRESSED_BYTES:
        print(
            f"error: uncompressed total {total_bytes} bytes exceeds the 30 MB limit",
            file=sys.stderr,
        )
        return 1

    version = read_version(root)
    zip_path = out_dir / f"{SKILL_NAME}-{version}.zip"
    if zip_path.resolve().parent != out_dir:
        print(f"error: refusing to write outside {out_dir}", file=sys.stderr)
        return 1

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for f in files:
            arcname = f.relative_to(skill_dir).as_posix()
            zf.write(f, arcname=arcname)

    names = zipfile.ZipFile(zip_path).namelist()
    if "SKILL.md" not in names:
        print(f"error: {zip_path} was written but does not contain SKILL.md at its root", file=sys.stderr)
        return 1

    print(f"Wrote {zip_path} ({zip_path.stat().st_size} bytes compressed, {len(files)} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
