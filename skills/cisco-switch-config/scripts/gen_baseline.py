#!/usr/bin/env python3
"""Generate a hardened Cisco IOS / IOS-XE switch baseline from a JSON spec.

    gen_baseline.py <spec-path|-> [--format cli|json] [--out <path>]

The spec carries no secrets: a secret-named key is rejected, and every secret slot in the
output is a <REPLACE-ME:name> placeholder to be filled on the device.

Exit codes: 0 generated; 2 unusable input (unreadable or invalid spec, usage error);
3 unusable build (a baseline template or build file is missing); 4 internal error;
5 egress guard tripped. Every byte of output leaves through ciscocheck.report.
"""
from __future__ import annotations

import argparse
import sys

from ciscocheck import report
from ciscocheck.mask import EgressGuardError


class _UsageExit(Exception):
    def __init__(self, status: int) -> None:
        super().__init__(status)
        self.status = status


class _ArgParser(argparse.ArgumentParser):
    """argparse routed through report.emit(): its messages quote flags, never spec content."""

    def _print_message(self, message: str, file=None) -> None:  # noqa: D401
        if message:
            report.emit(message, stream="err" if file is sys.stderr else "out")

    def exit(self, status: int = 0, message: str | None = None):  # type: ignore[override]
        if message:
            report.emit(message, stream="err")
        raise _UsageExit(status)


def build_parser() -> argparse.ArgumentParser:
    p = _ArgParser(prog="gen_baseline.py",
                   description="Generate a hardened switch baseline from a JSON spec.")
    p.add_argument("spec", help="spec file, or - for stdin")
    p.add_argument("--format", choices=("cli", "json"), default="cli")
    p.add_argument("--out")
    return p


def read_spec_text(path: str) -> str:
    """Read the spec file or stdin as strict UTF-8, a leading BOM allowed.
    OSError propagates; invalid UTF-8 raises ciscobaseline.spec.SpecError (exit 2)."""
    from ciscobaseline.spec import decode_bytes
    if path == "-":
        buf = getattr(sys.stdin, "buffer", None)
        data = buf.read() if buf is not None else sys.stdin.read()
    else:
        with open(path, "rb") as fh:
            data = fh.read()
    if isinstance(data, bytes):
        return decode_bytes(data)
    return data[1:] if data.startswith(chr(0xFEFF)) else data


def _main(argv: list[str] | None) -> int:
    try:
        args = build_parser().parse_args(argv)
    except _UsageExit as e:
        return e.status

    # --out must never overwrite the spec it reads
    if report.out_conflicts(args.out, [args.spec]):
        report.emit_error(report.OUT_CONFLICT_MESSAGE, code=2)
        return 2

    from ciscobaseline import render as brender
    from ciscobaseline import spec as bspec
    from ciscobaseline.sections import BaselineBuildError

    try:
        text = read_spec_text(args.spec)
    except OSError:
        report.emit_error(f"cannot read spec file: {args.spec}", code=2)
        return 2
    except bspec.SpecError as exc:
        report.emit_error(exc, code=2)
        return 2

    try:
        spec = bspec.from_doc(bspec.parse_text(text))
    except bspec.SpecError as exc:
        report.emit_error(exc, code=2)
        return 2
    del text

    try:
        if args.format == "json":
            out = brender.render_json(spec)
        else:
            out = "\n".join(brender.render(spec)) + "\n"
    except BaselineBuildError as exc:
        report.emit_error(str(exc), code=3)
        return 3

    if args.out:
        report.write_out(args.out, out)
    else:
        report.emit(out, utf8=(args.format == "json"))
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
