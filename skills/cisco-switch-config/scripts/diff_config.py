#!/usr/bin/env python3
"""Compare two Cisco IOS / IOS-XE configurations structurally.

    diff_config.py <old-path> <new-path> [--platform ios|iosxe] [--format table|json]
                   [--explain-checks] [--role-map <path>] [--out <path>]

Both inputs are ingested through parse_pair(), so a rotated key is reported as
`secret-rotated` without either value ever leaving the masker.
Exit codes: 0 ran; 2 unusable input; 3 unusable build; 4 internal error; 5 egress guard.
"""
from __future__ import annotations

import argparse
import sys

from ciscocheck import engine, model, report
from ciscocheck import parser as cparser
from ciscocheck.defaults import DefaultsError
from ciscocheck.dialect import DialectError
from ciscocheck.mask import EgressGuardError


class _UsageExit(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class _ArgParser(argparse.ArgumentParser):
    """argparse routed through report.emit(): its messages quote flags, never config."""

    def _print_message(self, message: str, file=None) -> None:
        if message:
            report.emit(message, stream="err" if file is sys.stderr else "out")

    def exit(self, status: int = 0, message: str | None = None):  # type: ignore[override]
        if message:
            report.emit(message, stream="err")
        raise _UsageExit(status)


def read_input_codec(path: str) -> tuple[str, str]:
    """Read a config file; decode with no replacement character."""
    with open(path, "rb") as fh:
        return cparser.decode_input(fh.read())


def read_input(path: str) -> str:
    return read_input_codec(path)[0]


def load_role_map_file(path: str) -> cparser.RoleMap:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        raise cparser.RoleMapError("role-map file cannot be read") from None
    try:
        doc = data.decode("utf-8-sig")         # strict: no replacement character
    except UnicodeDecodeError:
        raise cparser.RoleMapError("role-map file is not valid UTF-8") from None
    return cparser.load_role_map(doc)


def build_parser() -> _ArgParser:
    p = _ArgParser(prog="diff_config.py",
                   description="Structurally compare two Cisco switch configurations.")
    p.add_argument("old", help="the earlier configuration file")
    p.add_argument("new", help="the later configuration file")
    p.add_argument("--platform", choices=("ios", "iosxe"))
    p.add_argument("--format", choices=("table", "json"), default="table")
    p.add_argument("--explain-checks", action="store_true")
    p.add_argument("--role-map")
    p.add_argument("--out")
    return p


def _load_catalogue() -> model.Catalogue:
    return model.Catalogue.load(None)


def _explain(d: engine.DiffResult, catalogue: model.Catalogue) -> dict:
    ids = sorted({cid for c in d.changes for cid in c.crosses_checks})
    out = {}
    for cid in ids:
        e = catalogue.get(cid)
        if e is not None:
            out[cid] = {"title": e.title, "rationale": e.rationale}
    return out


def _main(argv: list[str] | None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except _UsageExit as e:
        return e.status

    # --out must never overwrite an input (same file, hard link or symlink)
    if report.out_conflicts(args.out, [args.old, args.new, args.role_map]):
        report.emit_error(report.OUT_CONFLICT_MESSAGE, code=2)
        return 2

    try:
        import ciscocheck.rules  # noqa: F401  (registration side effect; 3.7)
    except ModuleNotFoundError as exc:
        if exc.name != "ciscocheck.rules":
            raise
        report.emit_error("rule package not installed: this build is incomplete", code=3)
        return 3

    try:
        catalogue = _load_catalogue()
    except model.CatalogueError as exc:
        report.emit_error(str(exc), code=3)
        return 3

    role_map = None
    if args.role_map:
        try:
            role_map = load_role_map_file(args.role_map)
        except cparser.RoleMapError as exc:
            report.emit_error(exc, code=2)
            return 2

    texts, codecs = [], []
    for path in (args.old, args.new):
        try:
            text, codec = read_input_codec(path)
            texts.append(text)
            codecs.append(codec)
        except OSError:
            report.emit_error(f"cannot read input file: {path}", code=2)
            return 2

    try:
        old_cfg, new_cfg = cparser.parse_pair(texts[0], texts[1], platform=args.platform,
                                              role_map=role_map)
    except cparser.NotACiscoConfigError as exc:
        report.emit_error(exc, code=2)
        return 2
    except (DefaultsError, DialectError) as exc:
        report.emit_error(str(exc), code=3)
        return 3
    del texts
    for cfg, codec in ((old_cfg, codecs[0]), (new_cfg, codecs[1])):
        note = cparser.decoding_note(codec)
        if note is not None:
            cfg.notes = cfg.notes + (note,)

    d = engine.diff(old_cfg, new_cfg, catalogue)
    explain = _explain(d, catalogue) if args.explain_checks else None
    if args.format == "json":
        out = report.render_diff_json(d, explain=explain)
    else:
        out = report.render_diff_table(d)
        if explain:
            lines = [out.rstrip("\n"), "", "checks crossed:"]
            for cid, info in explain.items():
                lines.append(f"  {cid}  {info['title']}")
                lines.append(f"      {' '.join(info['rationale'].split())}")
            out = "\n".join(lines) + "\n"

    if args.out:
        report.write_out(args.out, out)
    else:
        report.emit(out, utf8=args.format == "json")    # JSON/SARIF: UTF-8 bytes on any console
    return 0


def main(argv: list[str] | None = None) -> int:
    try:
        return _main(argv)
    except EgressGuardError as exc:
        try:
            report.emit_error(exc, code=5)
        except EgressGuardError:
            pass
        return 5
    except Exception as exc:                          # noqa: BLE001
        try:
            report.emit_error(exc, code=4)
        except EgressGuardError as guard:        # the message itself tripped the guard
            report.emit_error(guard, code=5)
            return 5
        return 4


if __name__ == "__main__":
    sys.exit(main())
