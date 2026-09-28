"""audit_config.py / diff_config.py: exit codes 0-5, output routing, egress guard.

These tests inject an empty stand-in module for `ciscocheck.rules` and register stub rules,
so the "rules absent" path is simulated explicitly rather than depending on the real rules
package being importable.
"""
from __future__ import annotations

import io
import json
import sys
import types

import pytest

import audit_config
import diff_config
from ciscocheck import engine, mask, parser, registry, report
from ciscocheck.model import Catalogue, CatalogueError, Line

CANARY = "CANARY-COMMUNITY-01"


def stub_doc(remediation0=("no ip http server",)):
    return {"version": 1, "catalogue_version": "2026.09", "checks": [
        {"id": "CSC-TST-0001", "title": "HTTP server is enabled", "severity": "high",
         "category": "security", "confidence": "deterministic", "platforms": ["ios", "iosxe"],
         "profiles": ["campus", "stig"], "test_kind": "present", "subject": ["ip http server"],
         "rationale": "An enabled web server widens the management attack surface.",
         "params_required": [], "remediation": list(remediation0),
         "refs": [{"authority": "DISA-STIG", "id": "TEST-1", "version": "V1R1"}]},
        {"id": "CSC-TST-0002", "title": "Community string is configured", "severity": "medium",
         "category": "security", "confidence": "deterministic", "platforms": ["ios", "iosxe"],
         "profiles": ["campus", "stig"], "test_kind": "present",
         "subject": ["snmp-server community"],
         "rationale": "SNMP v1 and v2c carry the credential in clear text.",
         "params_required": [], "remediation": ["no snmp-server community <REPLACE-ME:snmp-community>"],
         "refs": [{"authority": "NIST", "id": "SP-800-53-IA-5"}]},
    ]}


CFG_TEXT = ("version 17.9\nhostname SW1\nip http server\n"
            f"snmp-server community {CANARY} RO 99\ninterface Gi1/0/1\n switchport mode access\nend\n")


def _register(leak_evidence: bool = False):
    registry.clear()

    @registry.rule("CSC-TST-0001")
    def http(cfg, ctx):
        node = cfg.find_one("ip http server")
        if node is not None:
            yield ctx.finding(line=node.line)

    @registry.rule("CSC-TST-0002")
    def comm(cfg, ctx):
        for node in cfg.find("snmp-server community"):
            line = node.line
            if leak_evidence:          # AC15 13(c) seeding: a raw value forced into Evidence.text
                line = Line(line.line_no, line.source_line_no,
                            f"snmp-server community {CANARY} RO 99", 0, "snmp-server",
                            (), "command", ())
            yield ctx.finding(line=line)


@pytest.fixture()
def wired(monkeypatch, tmp_path):
    _register()
    monkeypatch.setitem(sys.modules, "ciscocheck.rules", types.ModuleType("ciscocheck.rules"))
    cat = Catalogue.from_dict(stub_doc())
    monkeypatch.setattr(audit_config, "_load_catalogue", lambda: cat)
    monkeypatch.setattr(diff_config, "_load_catalogue", lambda: cat)
    cfg = tmp_path / "sw1.cfg"
    cfg.write_text(CFG_TEXT, encoding="utf-8")
    yield cfg
    registry.clear()


def run(capsys, argv, module=audit_config):
    code = module.main(argv)
    out, err = capsys.readouterr()
    assert CANARY not in out and CANARY not in err
    assert "Traceback" not in err and 'File "' not in err
    return code, out, err


@pytest.mark.parametrize("fmt", ["table", "json", "sarif"])
def test_formats_exit_zero(wired, capsys, fmt):
    code, out, err = run(capsys, [str(wired), "--format", fmt])
    assert code == 0 and err == ""
    assert "[REDACTED snmp-community, 19 chars]" in out
    if fmt != "table":
        json.loads(out)


def test_fail_on(wired, capsys):
    assert run(capsys, [str(wired), "--fail-on", "high"])[0] == 1
    assert run(capsys, [str(wired), "--fail-on", "critical"])[0] == 0
    assert run(capsys, [str(wired), "--fail-on", "none"])[0] == 0


def test_no_notes_and_filters(wired, capsys):
    code, out, _ = run(capsys, [str(wired), "--no-notes", "--severity-min", "high"])
    assert code == 0 and "notes:" not in out and "CSC-TST-0002" not in out
    assert "1 findings (1 high)" in out


def test_out_writes_only_that_file(wired, capsys, tmp_path):
    target = tmp_path / "report.json"
    code, out, err = run(capsys, [str(wired), "--format", "json", "--out", str(target)])
    assert code == 0 and out == "" and err == ""
    doc = json.loads(target.read_text(encoding="utf-8"))
    assert doc["counts"]["total"] == 2
    assert sorted(p.name for p in tmp_path.iterdir()) == ["report.json", "sw1.cfg"]


def test_stdin_input(wired, capsys, monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(CFG_TEXT.encode("utf-8"))))
    code, out, _ = run(capsys, ["-", "--format", "sarif"])
    assert code == 0 and json.loads(out)["runs"][0]["results"][0]["locations"][0][
        "physicalLocation"]["artifactLocation"]["uri"] == "stdin"


def test_rules_absent_is_exit_3(wired, capsys, monkeypatch):
    monkeypatch.setitem(sys.modules, "ciscocheck.rules", None)
    code, out, err = run(capsys, [str(wired)])
    assert code == 3 and out == ""
    assert err == "error: rule package not installed: this build is incomplete\n"


def test_broken_import_inside_rules_is_not_mistaken_for_absence(wired, capsys, monkeypatch):
    class Finder:
        def find_spec(self, name, path=None, target=None):
            if name == "ciscocheck.rules":
                raise ModuleNotFoundError("No module named 'yaml'", name="yaml")
            return None
    monkeypatch.delitem(sys.modules, "ciscocheck.rules", raising=False)
    monkeypatch.setattr(sys, "meta_path", [Finder()] + sys.meta_path)
    code, _, err = run(capsys, [str(wired)])
    assert code == 4 and err == "error: ModuleNotFoundError (internal)\n"


def test_catalogue_missing_is_exit_3(wired, capsys, monkeypatch):
    def boom():
        raise CatalogueError("data/catalogue.json is missing: this build is incomplete")
    monkeypatch.setattr(audit_config, "_load_catalogue", boom)
    code, _, err = run(capsys, [str(wired)])
    assert code == 3 and "catalogue.json is missing" in err


def test_real_catalogue_loader_failure_is_exit_3(wired, capsys, monkeypatch):
    monkeypatch.setattr(audit_config, "_load_catalogue",
                        lambda: Catalogue.load("no/such/catalogue.json"))
    assert run(capsys, [str(wired)])[0] == 3


def test_missing_input_file_is_exit_2_quoting_path_only(wired, capsys, tmp_path):
    missing = tmp_path / "nope.cfg"
    code, _, err = run(capsys, [str(missing)])
    assert code == 2 and err == f"error: cannot read input file: {missing}\n"


def test_non_cisco_input_is_exit_2_without_content(wired, capsys, tmp_path):
    p = tmp_path / "letter.txt"
    p.write_text("Dear team,\nplease find attached\nthe secret plan\nregards\n", encoding="utf-8")
    code, _, err = run(capsys, [str(p)])
    assert code == 2 and "Dear" not in err and "plan" not in err
    assert err.startswith("error: input is empty or is not a Cisco IOS/IOS-XE configuration")


def test_bad_role_map_is_exit_2_naming_key_and_value(wired, capsys, tmp_path):
    rm = tmp_path / "roles.json"
    rm.write_text(json.dumps({"version": 1, "roles": {"Gi1/0/1": "core"}}), encoding="utf-8")
    code, _, err = run(capsys, [str(wired), "--role-map", str(rm)])
    assert code == 2 and err == 'error: role-map key "Gi1/0/1" has invalid role "core"\n'


def test_role_map_applied(wired, capsys, tmp_path):
    rm = tmp_path / "roles.json"
    rm.write_text(json.dumps({"version": 1, "roles": {"Gi1/0/1": "uplink"}}), encoding="utf-8")
    code, out, _ = run(capsys, [str(wired), "--role-map", str(rm), "--format", "json"])
    doc = json.loads(out)
    assert code == 0 and doc["run"]["role_map_applied"] is True
    assert any(n["code"] == "CSC-SELF-0008" for n in doc["notes"])


def test_usage_error_is_exit_2(wired, capsys):
    code, out, err = run(capsys, [str(wired), "--format", "yaml"])
    assert code == 2 and "invalid choice" in err
    assert run(capsys, [])[0] == 2
    code, out, _ = run(capsys, ["--help"])
    assert code == 0 and "usage: audit_config.py" in out


@pytest.mark.parametrize("fmt", ["table", "json", "sarif"])
def test_egress_seed_in_evidence_is_exit_5(wired, capsys, fmt):
    _register(leak_evidence=True)
    code, out, err = run(capsys, [str(wired), "--format", fmt])
    assert code == 5 and out == ""
    assert err.startswith("error: egress guard: unmasked snmp-community detected at token")


@pytest.mark.parametrize("fmt", ["table", "json", "sarif"])
def test_egress_seed_in_remediation_is_exit_5(wired, capsys, monkeypatch, fmt):
    cat = Catalogue.from_dict(stub_doc(remediation0=(f"snmp-server community {CANARY} RO",)))
    monkeypatch.setattr(audit_config, "_load_catalogue", lambda: cat)
    code, out, err = run(capsys, [str(wired), "--format", fmt])
    assert code == 5 and out == "" and "egress guard" in err


def test_egress_seed_in_error_message_is_exit_5(wired, capsys, monkeypatch):
    def leaky(*a, **k):
        raise parser.RoleMapError(f"snmp-server community {CANARY} RO")
    monkeypatch.setattr(parser, "parse", leaky)
    code, out, err = run(capsys, [str(wired)])
    assert code == 5 and "egress guard" in err


def test_egress_seed_with_out_writes_no_file(wired, capsys, tmp_path):
    _register(leak_evidence=True)
    target = tmp_path / "r.txt"
    assert run(capsys, [str(wired), "--out", str(target)])[0] == 5
    assert not target.exists()


def test_internal_error_is_exit_4_class_name_only(wired, capsys, monkeypatch):
    def boom(*a, **k):
        raise ValueError("invalid literal for int() with base 10: 'S3cret'")
    monkeypatch.setattr(engine, "run", boom)
    code, out, err = run(capsys, [str(wired)])
    assert code == 4 and err == "error: ValueError (internal)\n" and "S3cret" not in err
    assert report.exit_code() == 4


def test_ingest_masker_alone_carries_the_invariant(wired, capsys, monkeypatch):
    monkeypatch.setattr(mask, "scrub", lambda text: ())
    for fmt in ("table", "json", "sarif"):
        code, out, _ = run(capsys, [str(wired), "--format", fmt])
        assert code == 0 and "[REDACTED snmp-community" in out


# --------------------------------------------------------------------------- diff_config

OLD = ("hostname SW1\ntacacs-server key 7 CANARY-TACACS-KEY-01\nip http server\n"
       "interface Gi1/0/1\n spanning-tree bpduguard enable\n description old\nend\n")
NEW = ("hostname SW1\ntacacs-server key 7 CANARY-TACACS-KEY-ROTATED-02\n"
       "interface Gi1/0/1\n description new\nend\n")


def _pair(tmp_path):
    a, b = tmp_path / "old.cfg", tmp_path / "new.cfg"
    a.write_text(OLD, encoding="utf-8")
    b.write_text(NEW, encoding="utf-8")
    return str(a), str(b)


def test_diff_cli_table_and_json(wired, capsys, tmp_path):
    a, b = _pair(tmp_path)
    code, out, err = run(capsys, [a, b], diff_config)
    assert code == 0 and err == ""
    assert "CANARY-TACACS" not in out
    assert "secret-rotated" in out and "[REDACTED tacacs-key, 28 chars, changed]" in out
    assert "crosses: CSC-TST-0001" in out
    code, out, _ = run(capsys, [a, b, "--format", "json", "--explain-checks"], diff_config)
    doc = json.loads(out)
    kinds = sorted(c["kind"] for c in doc["changes"])
    assert kinds == ["changed", "removed", "removed", "secret-rotated"]
    assert doc["tool"]["catalogue_version"] == "2026.09"
    assert "CSC-TST-0001" in doc["explain"]
    assert "CANARY-TACACS" not in out


def test_diff_cli_error_paths(wired, capsys, tmp_path, monkeypatch):
    a, b = _pair(tmp_path)
    assert run(capsys, [a, str(tmp_path / "missing.cfg")], diff_config)[0] == 2
    monkeypatch.setitem(sys.modules, "ciscocheck.rules", None)
    assert run(capsys, [a, b], diff_config)[0] == 3


# --------------------------------------------------------------------------- UTF-8 machine output
# JSON and SARIF on stdout are UTF-8 bytes whatever the console code page. The table stays in
# the console encoding. The egress guard scans exactly what is written.

import os as _os
import pathlib as _pathlib
import subprocess as _subprocess

_SCRIPTS = _pathlib.Path(audit_config.__file__).resolve().parent
_NON_ASCII = "ACL-ÉTÉ-ñ"


def _legacy_console_env() -> dict:
    """PYTHONIOENCODING unset, UTF-8 mode off, a non-UTF-8 locale: on Windows the child's
    piped stdout is the ANSI code page (cp1252 here); on POSIX, C-locale ASCII."""
    env = {k: v for k, v in _os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
    env.update(PYTHONUTF8="0", PYTHONPATH=str(_SCRIPTS), LANG="C", LC_ALL="C")
    return env


@pytest.mark.parametrize("fmt", ["json", "sarif"])
def test_machine_formats_are_utf8_on_a_legacy_console(tmp_path, fmt):
    env = _legacy_console_env()
    console = _subprocess.run([sys.executable, "-c", "import sys; print(sys.stdout.encoding)"],
                              env=env, capture_output=True).stdout.decode().strip().lower()
    assert console.replace("-", "") != "utf8", f"console not simulated as legacy: {console}"
    cfg = tmp_path / "sw.cfg"
    cfg.write_text(f"version 17.9\nhostname SW1\nline vty 0 4\n access-class {_NON_ASCII} in\n"
                   " transport input ssh\nend\n", encoding="utf-8")
    r = _subprocess.run([sys.executable, str(_SCRIPTS / "audit_config.py"), str(cfg),
                         "--format", fmt], env=env, capture_output=True)
    assert r.returncode == 0, r.stderr
    text = r.stdout.decode("utf-8")                   # raises if the bytes are not UTF-8
    assert _NON_ASCII in text
    assert json.loads(text)
    assert b"\r\n" not in r.stdout                    # LF, identical to --out


def test_table_stays_in_the_console_encoding(tmp_path):
    cfg = tmp_path / "sw.cfg"
    cfg.write_text(f"version 17.9\nhostname SW1\nline vty 0 4\n access-class {_NON_ASCII} in\n"
                   " transport input ssh\nend\n", encoding="utf-8")
    r = _subprocess.run([sys.executable, str(_SCRIPTS / "audit_config.py"), str(cfg)],
                        env=_legacy_console_env(), capture_output=True)
    assert r.returncode == 0
    console = _subprocess.run([sys.executable, "-c", "import sys; print(sys.stdout.encoding)"],
                              env=_legacy_console_env(), capture_output=True).stdout.decode().strip()
    assert r.stdout.decode(console, errors="strict")  # readable in the console's own code page


def _fake_console(encoding: str) -> io.TextIOWrapper:
    return io.TextIOWrapper(io.BytesIO(), encoding=encoding, newline="")


def test_emit_utf8_writes_exact_utf8_bytes(monkeypatch):
    out = _fake_console("cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    text = '{"x": "' + _NON_ASCII + ' 漢字"}\n'     # 漢字 is not in cp1252
    report.emit(text, utf8=True)
    assert out.buffer.getvalue() == text.encode("utf-8")


def test_emit_table_replaces_unencodable_and_guards_what_is_written(monkeypatch):
    out = _fake_console("cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    report.emit("title ÉTÉ 漢\n")
    out.flush()
    assert out.buffer.getvalue() == "title ÉTÉ ?\n".encode("cp1252")


def test_egress_guard_still_runs_on_the_utf8_path(monkeypatch):
    out = _fake_console("cp1252")
    monkeypatch.setattr(sys, "stdout", out)
    with pytest.raises(mask.EgressGuardError):
        report.emit('{"text": "snmp-server community CANARY-UTF8-01 RO"}\n', utf8=True)
    assert out.buffer.getvalue() == b""               # nothing written before the guard ran


# --------------------------------------------------------------------------- decoding, output-path safety, masked mode

import re as _re

import gen_baseline as _gen_baseline
from ciscocheck import parser as _cparser

_ROOT = _SCRIPTS.parent.parent.parent
_FIXTURES = _ROOT / "tests" / "fixtures"


@pytest.mark.parametrize("name,data,codec,secret", [
    ("cp1252_nbsp", b"hostname SW1\nsnmp-server community\xa0ZQXFAKE33 RO 99\n"
                    b"interface Gi1/0/1\n shutdown\nend\n", "cp1252", "ZQXFAKE33"),
    ("latin1_byte", b"hostname SW1\ninterface Gi1/0/1\n description caf\x81\n shutdown\n"
                    b"snmp-server community ZQXFAKE34 RO\nend\n", "latin-1", "ZQXFAKE34"),
    ("invalid_utf8", b"hostname SW1\ninterface Gi1/0/1\n description bad \xc3\x28 seq\n"
                     b"tacacs-server key 7 ZQXFAKE37\nend\n", "cp1252", "ZQXFAKE37"),
    ("utf16_bom", "hostname SW1\ninterface Gi1/0/1\n shutdown\nsnmp-server community ZQXFAKE38 RO\n"
                  "end\n".encode("utf-16"), "utf-16", "ZQXFAKE38"),
])
def test_decoding_never_replaces_with_replacement_character(name, data, codec, secret):
    text, used = _cparser.decode_input(data)
    assert used == codec
    assert "�" not in text
    cfg = _cparser.parse(text)
    assert all(secret not in l.text and "�" not in l.text for l in cfg.lines())
    assert any("[REDACTED" in l.text for l in cfg.lines())
    note = _cparser.decoding_note(used)
    assert note is not None and note.detail == f"input decoded as {codec}"


def test_cli_notes_the_decoding_codec(tmp_path, capsys):
    p = tmp_path / "ansi.cfg"
    p.write_bytes(b"hostname SW1\nsnmp-server community\xa0ZQXFAKE33 RO 99\ninterface Gi1/0/1\n"
                  b" shutdown\nend\n")
    code = audit_config.main([str(p), "--format", "masked"])
    out, err = capsys.readouterr()
    assert code == 0 and "ZQXFAKE33" not in out and "�" not in out
    assert "snmp-server community [REDACTED snmp-community, 9 chars] RO 99" in out


def test_role_map_is_strict_utf8(wired, tmp_path, capsys):
    rm = tmp_path / "roles.json"
    rm.write_bytes(b'{"version": 1, "roles": {"Gi1/0/1": "acc\xe9ss"}}')
    code = audit_config.main([str(wired), "--role-map", str(rm)])
    _, err = capsys.readouterr()
    assert code == 2 and "not valid UTF-8" in err


def _link_variants(tmp_path, real):
    """(label, path) aliases of `real`: itself, a hard link, and a symlink - or, where the
    host refuses unprivileged symlinks (Windows error 1314), a directory junction."""
    hard = tmp_path / ("hard-" + real.name)
    _os.link(real, hard)
    out = [("same", real), ("hardlink", hard)]
    link = tmp_path / ("sym-" + real.name)
    try:
        _os.symlink(real, link)
        out.append(("symlink", link))
    except OSError:
        junction = tmp_path / "junction"
        r = _subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(real.parent)],
                            capture_output=True)
        assert r.returncode == 0, "neither a symlink nor a junction could be created"
        out.append(("junction", junction / real.name))
    return out


def test_audit_out_never_overwrites_an_input(tmp_path, capsys):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    cfg = real_dir / "victim.cfg"
    cfg.write_text(CFG_TEXT, encoding="utf-8")
    before = cfg.read_bytes()
    for label, alias in _link_variants(tmp_path, cfg):
        code = audit_config.main([str(cfg), "--format", "json", "--out", str(alias)])
        _, err = capsys.readouterr()
        assert code == 2, label
        assert err == "error: --out names an input file; refusing to overwrite it\n", label
        assert cfg.read_bytes() == before, label


def test_diff_out_never_overwrites_either_input(tmp_path, capsys):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    a, b = real_dir / "old.cfg", real_dir / "new.cfg"
    a.write_text(OLD, encoding="utf-8")
    b.write_text(NEW, encoding="utf-8")
    snap = (a.read_bytes(), b.read_bytes())
    for label, alias in _link_variants(tmp_path, b):
        assert diff_config.main([str(a), str(b), "--out", str(alias)]) == 2, label
        capsys.readouterr()
    assert diff_config.main([str(a), str(b), "--out", str(a)]) == 2
    capsys.readouterr()
    assert (a.read_bytes(), b.read_bytes()) == snap


def test_gen_baseline_out_never_overwrites_the_spec(tmp_path, capsys):
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    spec = real_dir / "spec.json"
    spec.write_bytes((_ROOT / "skills" / "cisco-switch-config" / "examples" / "specs"
                      / "access-switch-basic.json").read_bytes())
    before = spec.read_bytes()
    for label, alias in _link_variants(tmp_path, spec):
        code = _gen_baseline.main([str(spec), "--out", str(alias)])
        _, err = capsys.readouterr()
        assert code == 2 and "--out names an input file" in err, label
        assert spec.read_bytes() == before, label


def test_out_to_a_new_file_still_works(tmp_path, capsys):
    cfg = tmp_path / "sw.cfg"
    cfg.write_text(CFG_TEXT, encoding="utf-8")
    target = tmp_path / "masked.txt"
    assert audit_config.main([str(cfg), "--format", "masked", "--out", str(target)]) == 0
    assert "CANARY" not in target.read_text(encoding="utf-8")


# ---- --format masked

_CANARY_FILES = sorted(p for p in (_FIXTURES / "synthetic").glob("canary-*.cfg"))


def _input_line_count(path) -> int:
    text, _ = _cparser.decode_input(path.read_bytes())
    return audit_config.count_input_lines(text)


@pytest.mark.parametrize("path", _CANARY_FILES, ids=[p.name for p in _CANARY_FILES])
def test_masked_mode_over_every_canary_fixture(path, capsys):
    code = audit_config.main([str(path), "--format", "masked"])
    out, err = capsys.readouterr()
    assert code == 0, err
    # the same canary-token definition as the independent masking-invariant oracle
    # (test_masking_invariant): the bare word in the fixture's prose ("`CANARY...`
    # derivative") is not a secret
    assert _re.findall(r"CANARY[A-Za-z0-9\-]{2,}", out) == []
    lines = out.rstrip("\n").split("\n")
    assert len(lines) == _input_line_count(path)
    assert [int(x.split()[0]) for x in lines] == list(range(1, len(lines) + 1))
    assert any("[REDACTED " in x for x in lines)
    for line in lines:
        assert mask.scrub(line) == ()


def test_masked_mode_shows_the_token_on_a_secret_line(tmp_path, capsys):
    p = tmp_path / "sw.cfg"
    p.write_text("Building configuration...\nhostname SW1\nsnmp-server community ZQXFAKE50 RO 99\n"
                 "interface Gi1/0/1\n shutdown\nend\n\n", encoding="utf-8")
    assert audit_config.main([str(p), "--format", "masked"]) == 0
    lines = capsys.readouterr()[0].rstrip("\n").split("\n")
    assert lines[0] == "    1  ! [pre-clean artefact: build-banner]"
    assert lines[2] == "    3  snmp-server community [REDACTED snmp-community, 9 chars] RO 99"
    assert len(lines) == 7 and lines[6] == "    7"


def test_masked_mode_is_listed_in_help(capsys):
    assert audit_config.main(["--help"]) == 0
    assert "masked" in capsys.readouterr()[0]


def test_masked_mode_is_utf8_on_a_legacy_console(tmp_path):
    cfg = tmp_path / "sw.cfg"
    # the non-ASCII sample sits in an ACL name (not free text); a non-ASCII description is
    # redacted whole (free-text fields fail closed on non-ASCII content)
    cfg.write_text(f"hostname SW1\nline vty 0 4\n access-class {_NON_ASCII} in\n"
                   f"interface Gi1/0/1\n description café ZQXFAKE52\n"
                   " snmp-server community ZQXFAKE51 RO\nend\n", encoding="utf-8")
    r = _subprocess.run([sys.executable, str(_SCRIPTS / "audit_config.py"), str(cfg),
                         "--format", "masked"], env=_legacy_console_env(), capture_output=True)
    assert r.returncode == 0, r.stderr
    text = r.stdout.decode("utf-8")
    assert _NON_ASCII in text and "ZQXFAKE51" not in text and "ZQXFAKE52" not in text
    assert "description [REDACTED free-text, " in text


# ---- comment-embedded secrets end to end: masked, table, json and diff show no fake value

_COMMENT_CFG = ("version 17.9\nhostname SW1\n! password: ZQXFAKEC01\n! db_password=ZQXFAKEC07\n"
                "! API_KEY=ZQXFAKEC08\n! the enable secret is ZQXFAKEC12\n"
                "! rotate the password quarterly\ninterface Gi1/0/1\n shutdown\nend\n")


@pytest.mark.parametrize("fmt", ["masked", "table", "json", "sarif"])
def test_comment_secrets_end_to_end(tmp_path, capsys, fmt):
    p = tmp_path / "sw.cfg"
    p.write_text(_COMMENT_CFG, encoding="utf-8")
    code = audit_config.main([str(p), "--format", fmt])
    out, err = capsys.readouterr()
    assert code == 0, err
    assert "ZQXFAKE" not in out + err
    if fmt == "masked":
        # comment lines fail closed (expected prose over-redaction)
        assert "    7  ! rotate the password [REDACTED comment, 10 chars]" in out
        assert "    3  ! password[REDACTED comment, 12 chars]" in out


def test_comment_secrets_through_diff(tmp_path, capsys):
    old, new = tmp_path / "old.cfg", tmp_path / "new.cfg"
    old.write_text("hostname SW1\ninterface Gi1/0/1\n shutdown\nend\n", encoding="utf-8")
    new.write_text(_COMMENT_CFG, encoding="utf-8")
    for fmt in ("table", "json"):
        code = diff_config.main([str(old), str(new), "--format", fmt])
        out, err = capsys.readouterr()
        assert code == 0, err
        assert "ZQXFAKE" not in out + err


_ALL_CFGS = sorted(list(_FIXTURES.rglob("*.cfg"))
                   + list((_ROOT / "skills" / "cisco-switch-config" / "examples").rglob("*.cfg")))


@pytest.mark.parametrize("path", _ALL_CFGS, ids=[p.name for p in _ALL_CFGS])
def test_masked_mode_is_usable_on_every_fixture_and_example(path, capsys):
    # every fixture and example comment stays readable enough that the egress guard passes
    code = audit_config.main([str(path), "--format", "masked"])
    out, err = capsys.readouterr()
    assert code == 0, err
    assert "ZQXFAKE" not in out
    if path.name.startswith("canary-"):
        # only the canary-* fixtures promise every CANARY token is a secret;
        # trap fixtures also use the prefix for plain banner text and key labels
        assert _re.findall(r"CANARY[A-Za-z0-9\-]{2,}", out) == []


# ---- non-ASCII comments and free-text fields end to end: all formats plus diff show no fake value

_ITEM12_CFG = ("version 17.9\nhostname SW1\n! pаssword: ZQXFAKEE01\n"
               "ip access-list extended MGMT\n 10 remark psk=ZQXFAKEE08\n"
               " remark café ZQXFAKEE09\n permit ip any any\n"
               "interface Gi1/0/1\n description password ZQXFAKEE07\n shutdown\n"
               "snmp-server location closet key ZQXFAKEE12\nend\n")


@pytest.mark.parametrize("fmt", ["masked", "table", "json", "sarif"])
def test_free_text_secrets_end_to_end(tmp_path, capsys, fmt):
    p = tmp_path / "sw.cfg"
    p.write_text(_ITEM12_CFG, encoding="utf-8")
    code = audit_config.main([str(p), "--format", fmt])
    out, err = capsys.readouterr()
    assert code == 0, err
    assert "ZQXFAKE" not in out + err and "pаssword" not in out


def test_free_text_secrets_through_diff(tmp_path, capsys):
    old, new = tmp_path / "old.cfg", tmp_path / "new.cfg"
    old.write_text("hostname SW1\ninterface Gi1/0/1\n shutdown\nend\n", encoding="utf-8")
    new.write_text(_ITEM12_CFG, encoding="utf-8")
    for fmt in ("table", "json"):
        code = diff_config.main([str(old), str(new), "--format", fmt])
        out, err = capsys.readouterr()
        assert code == 0, err
        assert "ZQXFAKE" not in out + err
