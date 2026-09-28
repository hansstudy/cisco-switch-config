"""AC16: the filesystem and network runtime invariant, for each CLI x each fixture.

Every test imports/invokes lazily so a missing script produces a clean FAILURE, never a skip.
"""

from __future__ import annotations

import pathlib

import pytest

from conftest import FIXTURES_DIR, require_module_or_fail

SCRIPTS_DIR = (
    pathlib.Path(__file__).resolve().parent.parent
    / "skills" / "cisco-switch-config" / "scripts"
)

CLI_SCRIPTS = ("audit_config", "diff_config", "gen_baseline")

REPRESENTATIVE_FIXTURES = (
    "synthetic/minimal.cfg",
    "synthetic/hardened-reference.cfg",
    "synthetic/deliberately-bad.cfg",
    "synthetic/canary-secrets.cfg",
    "synthetic/canary-malformed.cfg",
)


def _require_scripts_exist(needed: tuple[str, ...] = CLI_SCRIPTS):
    """Only require the specific script(s) a given test actually invokes, so a missing
    script fails with a clear reason naming exactly what's missing. Gating per-script, not
    globally, keeps that distinction visible in the test results instead of masking it
    behind one blanket failure reason.
    """
    missing = [s for s in needed if not (SCRIPTS_DIR / f"{s}.py").exists()]
    if missing:
        pytest.fail(f"CLI script(s) not present yet: {missing}")


# ---------------------------------------------------------------------------------------
# Filesystem oracle: no CLI may write outside the path it was explicitly given.
# ---------------------------------------------------------------------------------------


@pytest.mark.parametrize("fixture_rel", REPRESENTATIVE_FIXTURES)
def test_audit_config_writes_only_the_named_out_path(scratch_root, fixture_rel):
    _require_scripts_exist(("audit_config",))
    require_module_or_fail("ciscocheck.mask")
    cfg_path = scratch_root.copy_fixture_in(fixture_rel, as_name="input.cfg")
    out_path = scratch_root.root / "report.json"

    before = scratch_root.snapshot()
    scratch_root.run("audit_config", [str(cfg_path), "--format", "json", "--out", str(out_path)])
    after = scratch_root.snapshot()

    new_or_changed = after - before
    allowed = {str(out_path.relative_to(scratch_root.root))}
    unexpected = new_or_changed - allowed
    assert not unexpected, f"unexpected filesystem writes: {unexpected}"


@pytest.mark.parametrize("fixture_rel", REPRESENTATIVE_FIXTURES)
def test_audit_config_without_out_writes_nothing_new(scratch_root, fixture_rel):
    _require_scripts_exist(("audit_config",))
    require_module_or_fail("ciscocheck.mask")
    cfg_path = scratch_root.copy_fixture_in(fixture_rel, as_name="input.cfg")

    before = scratch_root.snapshot()
    scratch_root.run("audit_config", [str(cfg_path), "--format", "table"])
    after = scratch_root.snapshot()

    assert after == before, f"a run with no --out modified the filesystem: {after - before}"


def test_diff_config_writes_only_the_named_out_path(scratch_root):
    _require_scripts_exist(("diff_config",))
    require_module_or_fail("ciscocheck.mask")
    old_path = scratch_root.copy_fixture_in("synthetic/canary-secrets.cfg", as_name="old.cfg")
    new_path = scratch_root.copy_fixture_in("synthetic/canary-secrets-rotated.cfg", as_name="new.cfg")
    out_path = scratch_root.root / "diff.json"

    before = scratch_root.snapshot()
    scratch_root.run("diff_config", [str(old_path), str(new_path), "--format", "json", "--out", str(out_path)])
    after = scratch_root.snapshot()

    unexpected = (after - before) - {str(out_path.relative_to(scratch_root.root))}
    assert not unexpected, f"unexpected filesystem writes: {unexpected}"


def test_gen_baseline_writes_only_the_named_out_path(scratch_root):
    _require_scripts_exist(("gen_baseline",))
    require_module_or_fail("ciscocheck.mask")
    spec_src = (
        pathlib.Path(__file__).resolve().parent.parent
        / "skills" / "cisco-switch-config" / "examples" / "specs" / "access-switch-basic.json"
    )
    spec_dest = scratch_root.root / "spec.json"
    spec_dest.write_bytes(spec_src.read_bytes())
    out_path = scratch_root.root / "baseline.cfg"

    before = scratch_root.snapshot()
    scratch_root.run("gen_baseline", [str(spec_dest), "--format", "cli", "--out", str(out_path)])
    after = scratch_root.snapshot()

    unexpected = (after - before) - {str(out_path.relative_to(scratch_root.root))}
    assert not unexpected, f"unexpected filesystem writes: {unexpected}"


# ---------------------------------------------------------------------------------------
# Network oracle: no CLI may trip socket.socket / socket.create_connection / getaddrinfo.
# Run IN-PROCESS with the patch installed, rather than via subprocess, because the patch
# must apply to the process actually under test.
# ---------------------------------------------------------------------------------------


def _install_network_trap(monkeypatch):
    import socket

    def _raise(*_args, **_kwargs):
        raise AssertionError("network access attempted -- forbidden under skills/ (AC8/AC16)")

    monkeypatch.setattr(socket, "socket", _raise)
    monkeypatch.setattr(socket, "create_connection", _raise)
    monkeypatch.setattr(socket, "getaddrinfo", _raise)


@pytest.mark.parametrize("fixture_rel", REPRESENTATIVE_FIXTURES)
def test_audit_config_never_touches_the_network(monkeypatch, tmp_path, fixture_rel):
    _require_scripts_exist(("audit_config",))
    audit_mod = require_module_or_fail("audit_config")
    _install_network_trap(monkeypatch)

    cfg_dest = tmp_path / "input.cfg"
    cfg_dest.write_bytes((FIXTURES_DIR / fixture_rel).read_bytes())
    out_dest = tmp_path / "report.json"

    argv = [str(cfg_dest), "--format", "json", "--out", str(out_dest)]
    try:
        audit_mod.main(argv)
    except SystemExit:
        pass
    except AssertionError as exc:
        pytest.fail(str(exc))


def test_diff_config_never_touches_the_network(monkeypatch, tmp_path):
    _require_scripts_exist(("diff_config",))
    diff_mod = require_module_or_fail("diff_config")
    _install_network_trap(monkeypatch)

    old_dest = tmp_path / "old.cfg"
    new_dest = tmp_path / "new.cfg"
    old_dest.write_bytes((FIXTURES_DIR / "synthetic/canary-secrets.cfg").read_bytes())
    new_dest.write_bytes((FIXTURES_DIR / "synthetic/canary-secrets-rotated.cfg").read_bytes())

    argv = [str(old_dest), str(new_dest), "--format", "json"]
    try:
        diff_mod.main(argv)
    except SystemExit:
        pass
    except AssertionError as exc:
        pytest.fail(str(exc))


def test_gen_baseline_never_touches_the_network(monkeypatch, tmp_path):
    _require_scripts_exist(("gen_baseline",))
    gen_mod = require_module_or_fail("gen_baseline")
    _install_network_trap(monkeypatch)

    spec_src = (
        pathlib.Path(__file__).resolve().parent.parent
        / "skills" / "cisco-switch-config" / "examples" / "specs" / "access-switch-basic.json"
    )
    spec_dest = tmp_path / "spec.json"
    spec_dest.write_bytes(spec_src.read_bytes())

    argv = [str(spec_dest), "--format", "cli"]
    try:
        gen_mod.main(argv)
    except SystemExit:
        pass
    except AssertionError as exc:
        pytest.fail(str(exc))
