"""Shared pytest fixtures and helpers for the cisco-switch-config test suite.

This module is deliberately dependency-light: it must import cleanly even before
`ciscocheck` or `ciscobaseline` exist, so that a test module which does NOT need the engine
can still collect and run. Anything that needs the engine is imported lazily, inside the
helper function body, not at module scope.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
from typing import Iterable, Sequence

import pytest

# ---------------------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------------------

TESTS_DIR = pathlib.Path(__file__).resolve().parent
REPO_ROOT = TESTS_DIR.parent
FIXTURES_DIR = TESTS_DIR / "fixtures"
GOLDEN_DIR = TESTS_DIR / "golden"
SCHEMA_DIR = TESTS_DIR / "schema"
MANIFESTS_DIR = FIXTURES_DIR / "manifests"
SKILL_DIR = REPO_ROOT / "skills" / "cisco-switch-config"
SCRIPTS_DIR = SKILL_DIR / "scripts"


def fixture_path(relative: str) -> pathlib.Path:
    """Resolve a fixture path relative to `tests/fixtures/`.

    `relative` uses forward slashes always, e.g.
    `"synthetic/canary-secrets.cfg"` or `"third-party/napalm/show_running_config.txt"`.
    """
    path = FIXTURES_DIR / relative
    if not path.is_file():
        raise FileNotFoundError(f"fixture not found: {relative} (resolved to {path})")
    return path


def fixture_text(relative: str) -> str:
    """Read a fixture as text, decoding UTF-8 with errors="replace" -- the same decoding
    rule `parser.parse()` uses on ingest."""
    return fixture_path(relative).read_bytes().decode("utf-8", errors="replace")


def fixture_bytes(relative: str) -> bytes:
    return fixture_path(relative).read_bytes()


def all_manifests() -> list[dict]:
    """Load every `tests/fixtures/manifests/*.json` manifest.

    Manifests are deliberately tolerant (id sets and substring hints, never byte-exact
    golden JSON) -- a byte-exact golden would be a merge-conflict factory as the catalogue
    and rules evolve.
    """
    out = []
    for p in sorted(MANIFESTS_DIR.glob("*.json")):
        with p.open(encoding="utf-8") as fh:
            manifest = json.load(fh)
        if "fixture" not in manifest:
            # Not a fixture-expectation manifest (e.g. a helper file dropped in the wrong
            # directory by mistake) -- skip it rather than fail collection for every test
            # module that calls all_manifests().
            continue
        manifest["_manifest_path"] = str(p)
        out.append(manifest)
    return out


def golden_path(relative: str) -> pathlib.Path:
    return GOLDEN_DIR / relative


def schema_path(name: str) -> pathlib.Path:
    return SCHEMA_DIR / name


# ---------------------------------------------------------------------------------------
# CLI invocation helper
# ---------------------------------------------------------------------------------------


class CliResult:
    """Captured result of one in-process CLI invocation."""

    __slots__ = ("returncode", "stdout", "stderr", "exception")

    def __init__(self, returncode: int, stdout: str, stderr: str, exception: BaseException | None):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.exception = exception

    def __repr__(self) -> str:  # pragma: no cover - debug aid only
        return (
            f"CliResult(returncode={self.returncode!r}, "
            f"stdout={self.stdout[:200]!r}, stderr={self.stderr[:200]!r})"
        )


_CLI_MODULES = {
    "audit_config": "audit_config",
    "diff_config": "diff_config",
    "gen_baseline": "gen_baseline",
}


def run_cli(script: str, argv: Sequence[str], *, cwd: pathlib.Path | None = None) -> CliResult:
    """Invoke one of the shipped CLIs **in a subprocess**, never in-process.

    A subprocess, not an in-process `runpy`/`importlib` call, is what the filesystem and
    network oracle (AC16, test_runtime_invariant.py) can actually observe and sandbox: it is
    the only way to control the process's working directory and `TMPDIR`/`TEMP`/`TMP`
    without mutating this test runner's own environment, and it is the only way a patched
    `socket.socket` in the *test* process would fail to also patch the CLI (they are
    different processes, which is the point -- the CLI's own `sys.path` and import graph are
    exercised exactly as `python scripts/audit_config.py ...` would exercise them for a real
    user, not as this conftest's own environment happens to have set up `sys.path`).

    `script` is one of `"audit_config"`, `"diff_config"`, `"gen_baseline"`.
    """
    if script not in _CLI_MODULES:
        raise ValueError(f"unknown CLI script: {script!r}")
    script_path = SCRIPTS_DIR / f"{script}.py"
    env = dict(os.environ)
    env["PYTHONPATH"] = str(SCRIPTS_DIR)
    proc = subprocess.run(
        [sys.executable, str(script_path), *argv],
        cwd=str(cwd) if cwd is not None else None,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    return CliResult(proc.returncode, proc.stdout, proc.stderr, None)


# ---------------------------------------------------------------------------------------
# Scratch-root helper (AC16 / test_runtime_invariant.py)
# ---------------------------------------------------------------------------------------


class ScratchRoot:
    """A fresh temporary directory used as both the CLI's working directory and the target
    of `TMPDIR`/`TEMP`/`TMP`, so that every `tempfile` write a CLI makes lands inside the
    snapshotted tree and is attributable to the process under test."""

    def __init__(self, tmp_path: pathlib.Path):
        self.root = tmp_path / "scratch"
        self.root.mkdir(parents=True, exist_ok=True)
        self.tmp = self.root / "tmp"
        self.tmp.mkdir(parents=True, exist_ok=True)

    def copy_fixture_in(self, relative: str, *, as_name: str | None = None) -> pathlib.Path:
        data = fixture_bytes(relative)
        dest = self.root / (as_name or pathlib.Path(relative).name)
        dest.write_bytes(data)
        return dest

    def env(self) -> dict[str, str]:
        e = dict(os.environ)
        e["PYTHONPATH"] = str(SCRIPTS_DIR)
        e["TMPDIR"] = str(self.tmp)
        e["TEMP"] = str(self.tmp)
        e["TMP"] = str(self.tmp)
        return e

    def snapshot(self) -> set[str]:
        """The full relative path set of everything under the scratch root right now."""
        return {
            str(p.relative_to(self.root))
            for p in self.root.rglob("*")
        }

    def run(self, script: str, argv: Sequence[str]) -> CliResult:
        if script not in _CLI_MODULES:
            raise ValueError(f"unknown CLI script: {script!r}")
        script_path = SCRIPTS_DIR / f"{script}.py"
        proc = subprocess.run(
            [sys.executable, str(script_path), *argv],
            cwd=str(self.root),
            env=self.env(),
            capture_output=True,
            text=True,
            timeout=60,
        )
        return CliResult(proc.returncode, proc.stdout, proc.stderr, None)


@pytest.fixture
def scratch_root(tmp_path: pathlib.Path) -> ScratchRoot:
    return ScratchRoot(tmp_path)


# ---------------------------------------------------------------------------------------
# Skip-avoidance helper
# ---------------------------------------------------------------------------------------


def require_module_or_fail(name: str):
    """Import `name` and return it, or **fail** (never skip) with a message naming the
    reason. The rule for `tests/`: no test may skip except for the optional cross-check
    libraries (netutils, hier_config); a missing module must produce a FAILURE, not a SKIP,
    so an honest test run surfaces it (AC1). Use this instead of `pytest.importorskip` for
    anything under `ciscocheck` / `ciscobaseline`.
    """
    import importlib

    try:
        return importlib.import_module(name)
    except ImportError as exc:
        pytest.fail(f"{name} is not importable: {exc}", pytrace=False)


def optional_cross_check(name: str):
    """The ONE sanctioned use of `pytest.importorskip` in this suite: `netutils` and
    `hier_config` are dev-only cross-check libraries which a verifier is never required to
    install."""
    if name not in ("netutils", "hier_config"):
        raise ValueError(
            f"optional_cross_check is only for netutils/hier_config, not {name!r}; "
            "use require_module_or_fail for anything under ciscocheck/ciscobaseline"
        )
    return pytest.importorskip(name)
