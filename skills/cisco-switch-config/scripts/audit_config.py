#!/usr/bin/env python3
"""Audit a Cisco IOS / IOS-XE switch running-configuration.

    audit_config.py <config-path|-> [--platform ios|iosxe] [--format table|json|sarif]
                    [--profile campus|stig] [--severity-min info|low|medium|high|critical]
                    [--category security|reliability|all] [--role-map <path>]
                    [--fail-on high|critical|none] [--out <path>] [--no-notes]

Exit codes: 0 ran, nothing at or above --fail-on; 1 findings at or above --fail-on;
2 unusable input; 3 unusable build; 4 internal error; 5 egress guard tripped.
Every byte of output leaves through ciscocheck.report.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys

from ciscocheck import engine, model, report
from ciscocheck import parser as cparser
from ciscocheck import sarif
from ciscocheck.defaults import DefaultsError
from ciscocheck.dialect import DialectError
from ciscocheck.mask import EgressGuardError


class _UsageExit(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class _ArgParser(argparse.ArgumentParser):
    """argparse routed through report.emit(): its messages quote flags, never config."""

    def _print_message(self, message: str, file=None) -> None:  # noqa: D401
        if message:
            report.emit(message, stream="err" if file is sys.stderr else "out")

    def exit(self, status: int = 0, message: str | None = None):  # type: ignore[override]
        if message:
            report.emit(message, stream="err")
        raise _UsageExit(status)


def build_parser() -> argparse.ArgumentParser:
    p = _ArgParser(prog="audit_config.py",
                   description="Audit a Cisco IOS/IOS-XE switch running-configuration.")
    p.add_argument("config", help="configuration file, or - for stdin")
    p.add_argument("--platform", choices=("ios", "iosxe"))
    p.add_argument("--format", choices=("table", "json", "sarif", "masked"), default="table",
                   help="table (default), json, sarif, or masked: the whole configuration as "
                        "masked text, one numbered line per input line, no findings")
    p.add_argument("--profile", choices=("campus", "stig"), default="campus")
    p.add_argument("--severity-min", choices=("info", "low", "medium", "high", "critical"),
                   default="info")
    p.add_argument("--category", choices=("security", "reliability", "all"), default="all")
    p.add_argument("--role-map")
    p.add_argument("--fail-on", choices=("high", "critical", "none"), default="none")
    p.add_argument("--out")
    p.add_argument("--no-notes", action="store_true")
    return p


def _load_catalogue() -> model.Catalogue:
    return model.Catalogue.load(None)


def read_input_codec(path: str) -> tuple[str, str]:
    """Read a config file or stdin; decode with no replacement character:
    strict UTF-8, else cp1252, else latin-1 (a UTF-16 BOM is honoured). OSError propagates."""
    if path == "-":
        buf = getattr(sys.stdin, "buffer", None)
        data = buf.read() if buf is not None else sys.stdin.read()
    else:
        with open(path, "rb") as fh:
            data = fh.read()
    if isinstance(data, bytes):
        return cparser.decode_input(data)
    return data, "utf-8"


def read_input(path: str) -> str:
    return read_input_codec(path)[0]


def count_input_lines(text: str) -> int:
    """How many lines the pre-clean split sees (a count only; no content is inspected)."""
    t = text.replace("\r\n", "\n").replace("\r", "\n")
    if not t:
        return 0
    return t.count("\n") + (0 if t.endswith("\n") else 1)


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


def _main(argv: list[str] | None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except _UsageExit as e:
        return e.status

    # --out must never overwrite an input (same file, hard link or symlink)
    if report.out_conflicts(args.out, [args.config, args.role_map]):
        report.emit_error(report.OUT_CONFLICT_MESSAGE, code=2)
        return 2

    masked = args.format == "masked"     # masked text only: needs no rules and no catalogue
    catalogue = None
    if not masked:
        # Deferred, guarded binding of the rule package: a missing package is an
        # unusable build (exit 3), never a silent zero-finding report.
        try:
            import ciscocheck.rules  # noqa: F401  (registration side effect)
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

    try:
        text, codec = read_input_codec(args.config)
    except (FileNotFoundError, PermissionError, IsADirectoryError, OSError):
        report.emit_error(f"cannot read input file: {args.config}", code=2)
        return 2
    input_lines = count_input_lines(text)

    try:
        cfg = cparser.parse(text, platform=args.platform, role_map=role_map)
    except cparser.NotACiscoConfigError as exc:
        report.emit_error(exc, code=2)
        return 2
    except (DefaultsError, DialectError) as exc:
        report.emit_error(str(exc), code=3)
        return 3
    del text
    note = cparser.decoding_note(codec)
    if note is not None:
        cfg.notes = cfg.notes + (note,)

    if masked:
        out = report.render_masked(cfg, input_lines)
        if args.out:
            report.write_out(args.out, out)
        else:
            report.emit(out, utf8=True)
        return 0

    rep = engine.run(cfg, catalogue, profile=args.profile, severity_min=args.severity_min,
                     category=args.category)
    if args.no_notes:
        rep = dataclasses.replace(rep, notes=())

    if args.format == "json":
        out = report.render_json(rep)
    elif args.format == "sarif":
        uri = "stdin" if args.config == "-" else args.config.replace(chr(92), "/")
        out = json.dumps(sarif.to_sarif(rep, artifact_uri=uri, catalogue=catalogue),
                         indent=2, ensure_ascii=False) + "\n"
    else:
        out = report.render_table(rep)

    if args.out:
        report.write_out(args.out, out)
    else:
        report.emit(out, utf8=args.format != "table")    # JSON/SARIF: UTF-8 bytes on any console

    if args.fail_on == "high" and (rep.counts.get("critical", 0) or rep.counts.get("high", 0)):
        return 1
    if args.fail_on == "critical" and rep.counts.get("critical", 0):
        return 1
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
    except Exception as exc:                          # noqa: BLE001 - routed, never re-raised
        try:
            report.emit_error(exc, code=4)
        except EgressGuardError as guard:        # the message itself tripped the guard
            report.emit_error(guard, code=5)
            return 5
        return 4


if __name__ == "__main__":
    sys.exit(main())
