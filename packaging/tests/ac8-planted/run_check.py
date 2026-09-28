#!/usr/bin/env python3
"""Runner for the AC8 planted-shape fixture tree, the scanner self-test tree described in
PLANTED.md in this directory.

    python packaging/tests/ac8-planted/run_check.py

Loads the real packaging/verify_package.py by path (no install step, no pytest dependency - this
tree lives outside tests/) and runs its `check_unsafe_calls` and `check_imports` scanners directly
against this fixture tree, which is never shipped: it sits under packaging/tests/, uses a fake
skill name ("testskill"), and build_skill_zip.py only ever zips skills/cisco-switch-config/.

Prints "Caught X/27" for the planted tree (7 baseline-caught shapes + 20 shapes that close gaps in
scanner coverage), confirms the clean.py control file gives 0 findings, and exits 1 if either
check fails. See PLANTED.md in this directory for the full per-shape list and the before/after
counts.
"""
from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
VP_PATH = HERE.parent.parent / "verify_package.py"       # packaging/verify_package.py
PLANTED_PY = HERE / "skills" / "testskill" / "scripts" / "planted.py"
CLEAN_PY = HERE / "skills" / "testskill" / "scripts" / "clean.py"

FINDING_RE = re.compile(r"^(?P<path>.+):(?P<line>\d+): (?P<rule>.*)$")
SHAPE_TAG_RE = re.compile(r"#\s*SHAPE:\s*(\d+)")

TOTAL_SHAPES = 27  # 7 always-caught + 20 that close scanner-coverage gaps


def load_verify_package():
    spec = importlib.util.spec_from_file_location("verify_package", VP_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def findings_by_file(findings: list[str]) -> dict[str, set[int]]:
    out: dict[str, set[int]] = {}
    for f in findings:
        m = FINDING_RE.match(f)
        assert m, f"finding does not match the expected 'path:line: rule' shape: {f!r}"
        out.setdefault(m.group("path"), set()).add(int(m.group("line")))
    return out


def main() -> int:
    vp = load_verify_package()
    ok = True

    def report(label: str, condition: bool, detail: str = "") -> None:
        nonlocal ok
        status = "PASS" if condition else "FAIL"
        if not condition:
            ok = False
        print(f"[{status}] {label}" + (f" - {detail}" if detail else ""))

    unsafe_findings = vp.check_unsafe_calls(HERE)
    import_findings = vp.check_imports(HERE)
    all_findings = unsafe_findings + import_findings

    print(f"\n=== {len(unsafe_findings)} unsafe-calls finding(s), {len(import_findings)} imports finding(s) ===")
    for f in sorted(all_findings):
        print(f"  {f}")

    hits = findings_by_file(all_findings)
    planted_hits = hits.get(str(PLANTED_PY), set())
    clean_hits = hits.get(str(CLEAN_PY), set())

    # -- the 7 always-caught shapes: import-level denials plus 3 direct calls ------------
    planted_text = PLANTED_PY.read_text(encoding="utf-8").splitlines()
    always_caught_markers = [
        "import multiprocessing", "import runpy", "import traceback", "import webbrowser",
        "import ftplib", "import http.client", "import smtplib", "import socket",
        "os.open(p, os.O_WRONLY)", "shutil.copy(", "tempfile.mkstemp()",
    ]
    caught_lines: set[int] = set()
    missing_markers = []
    for marker in always_caught_markers:
        line_no = next((i + 1 for i, l in enumerate(planted_text) if marker in l), None)
        if line_no is None:
            missing_markers.append(marker)
            continue
        if line_no in planted_hits:
            caught_lines.add(line_no)

    # -- the 20 SHAPE-tagged lines (the fixed gaps) ----------------------------------------
    shape_lines: dict[int, int] = {}
    for i, line in enumerate(planted_text, start=1):
        m = SHAPE_TAG_RE.search(line)
        if m:
            shape_lines[int(m.group(1))] = i
    missing_shapes = [n for n, ln in sorted(shape_lines.items()) if ln not in planted_hits]
    for n, ln in shape_lines.items():
        if ln in planted_hits:
            caught_lines.add(ln)

    before_caught = len(always_caught_markers) - len(missing_markers)  # sanity: should be 7 always
    after_caught = len(caught_lines)

    print(f"\nCaught by the baseline scanner:  7/{TOTAL_SHAPES}")
    print(f"Caught by the current scanner:   {after_caught}/{TOTAL_SHAPES}")

    report(f"all {len(always_caught_markers)} always-caught markers found in planted.py", not missing_markers, f"missing: {missing_markers}" if missing_markers else "")
    report(
        f"all 20 SHAPE-tagged lines (the previously-missed shapes) now produce >= 1 finding",
        not missing_shapes,
        f"still missing shape #(s): {missing_shapes}" if missing_shapes else "all 20 caught",
    )
    report("clean.py gives 0 findings", len(clean_hits) == 0, f"hits: {sorted(clean_hits)}" if clean_hits else "")
    report(f"total caught == {TOTAL_SHAPES}/{TOTAL_SHAPES}", after_caught == TOTAL_SHAPES, f"got {after_caught}")

    print(f"\n=== AC8 planted-shape scanner result: {'ALL PASS' if ok else 'FAILURES ABOVE'} ===")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
