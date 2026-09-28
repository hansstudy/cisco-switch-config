"""Tests for the baseline generator (gen_baseline.py / ciscobaseline).

Covers `test_schema_rejects_secret_fields`, `test_determinism`,
`test_placeholders_listed`, `test_no_redaction_token_in_output`, `test_roundtrip` (AC9) and
`test_interface_range_survives_roundtrip`. The rest pin the generator's other promises:
its output passes `mask.scrub()` and the ingest masker untouched, spec errors never quote
a value, and a broken build is exit 3.
"""

from __future__ import annotations

import collections
import copy
import json
import pathlib
import re
import shutil

import pytest

from conftest import (SCRIPTS_DIR, SKILL_DIR, all_manifests, fixture_path,
                      require_module_or_fail, run_cli)

SPECS_DIR = SKILL_DIR / "examples" / "specs"
EXAMPLE_SPECS = ("access-switch-basic.json", "access-switch-multivlan.json",
                 "distribution-switch.json")
PLACEHOLDER_RE = re.compile(r"<REPLACE-ME:[a-z0-9-]+>")
CANARY = "CANARY-SPEC-VALUE-7Q"


def _example(name: str = "access-switch-basic.json") -> dict:
    return json.loads((SPECS_DIR / name).read_text(encoding="utf-8"))


def _variant() -> dict:
    """An ios spec that exercises the other branches: RADIUS and TACACS+, MST with a root
    priority, a port-channel, no voice VLAN, no unused VLAN, a /32 management source."""
    doc = _example()
    doc["platform"] = "ios"
    doc["role"] = "distribution"
    doc["vlans"] = [{"id": 10, "name": "DATA", "kind": "data"},
                    {"id": 99, "name": "MGMT", "kind": "mgmt"},
                    {"id": 900, "name": "NATIVE", "kind": "native"}]
    doc["uplinks"] = [
        {"interface": "GigabitEthernet1/0/47", "description": "po1 member a",
         "allowed_vlans": [10, 99], "channel_group": 1},
        {"interface": "GigabitEthernet1/0/48", "description": "po1 member b",
         "allowed_vlans": [10, 99], "channel_group": 1}]
    doc["access_ports"] = [{"range": "Gi1/0/1-4, Gi1/0/10-12", "vlan": 10,
                            "description": "lab benches"}]
    doc["unused_ports"] = ["GigabitEthernet1/0/20 - 30"]
    doc["stp"] = {"mode": "mst", "root_priority": 8192}
    doc["aaa"] = {"tacacs_hosts": ["198.51.100.10"], "radius_hosts": ["198.51.100.20"],
                  "group_name": "CORP"}
    doc["management"]["allowed_sources"] = ["192.0.2.200/32", "198.51.100.0/28"]
    doc["snmp"] = {"v3_user": None}
    doc.pop("banner", None)
    return doc


ALL_SPECS = [(n, _example(n)) for n in EXAMPLE_SPECS] + [("ios-variant", _variant())]


def _modules():
    spec_mod = require_module_or_fail("ciscobaseline.spec")
    render = require_module_or_fail("ciscobaseline.render")
    return spec_mod, render


def _write(tmp_path: pathlib.Path, doc: dict, name: str = "spec.json") -> str:
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return str(p)


def _render_text(doc: dict) -> tuple[object, tuple[str, ...]]:
    spec_mod, render = _modules()
    spec = spec_mod.from_doc(copy.deepcopy(doc))
    return spec, render.render(spec)


# ---------------------------------------------------------------------------------------
# test_schema_rejects_secret_fields: one case per row of the frozen forbidden-field table
# ---------------------------------------------------------------------------------------

def _inject(doc: dict, path: tuple[str, ...], value: object) -> dict:
    doc = copy.deepcopy(doc)
    node = doc
    for seg in path[:-1]:
        node = node.setdefault(seg, {})
    node[path[-1]] = value
    return doc


SECRET_ROWS = [
    # (injected key path, key named in the error, placeholder named or None)
    (("aaa", "tacacs_key"), "aaa.tacacs_key", "<REPLACE-ME:tacacs-key>"),
    (("tacacs", "key"), "tacacs.key", "<REPLACE-ME:tacacs-key>"),
    (("aaa", "radius_key"), "aaa.radius_key", "<REPLACE-ME:radius-key>"),
    (("radius", "key"), "radius.key", "<REPLACE-ME:radius-key>"),
    (("snmp", "snmp_auth_password"), "snmp.snmp_auth_password", "<REPLACE-ME:snmpv3-auth>"),
    (("snmp", "v3_auth"), "snmp.v3_auth", "<REPLACE-ME:snmpv3-auth>"),
    (("snmp", "snmp_priv_password"), "snmp.snmp_priv_password", "<REPLACE-ME:snmpv3-priv>"),
    (("snmp", "v3_priv"), "snmp.v3_priv", "<REPLACE-ME:snmpv3-priv>"),
    (("ntp", "ntp_key"), "ntp.ntp_key", "<REPLACE-ME:ntp-key-1>"),
    (("ntp", "key"), "ntp.key", "<REPLACE-ME:ntp-key-1>"),
    (("enable_secret",), "enable_secret", "<REPLACE-ME:enable-secret>"),
    (("local_password",), "local_password", "<REPLACE-ME:local-admin-secret>"),
    (("local_secret",), "local_secret", "<REPLACE-ME:local-admin-secret>"),
    (("vtp_password",), "vtp_password", "<REPLACE-ME:vtp-password>"),
    (("archive", "archive_password"), "archive.archive_password", None),
    # generic regex hits at depth, including inside an array element
    (("snmp", "community"), "snmp.community", None),
    (("aaa", "api_token"), "aaa.api_token", None),
]


@pytest.mark.parametrize("path,named,placeholder", SECRET_ROWS,
                         ids=[r[1] for r in SECRET_ROWS])
def test_schema_rejects_secret_fields(tmp_path, path, named, placeholder):
    doc = _inject(_example(), path, CANARY)
    result = run_cli("gen_baseline", [_write(tmp_path, doc), "--format", "cli"])
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert f'"{named}"' in result.stderr, result.stderr
    assert "is a secret field" in result.stderr
    if placeholder:
        assert placeholder in result.stderr
    assert CANARY not in combined
    assert result.stdout == ""


def test_schema_rejects_secret_field_inside_array_element(tmp_path):
    doc = _example()
    doc["uplinks"][0]["psk"] = CANARY
    result = run_cli("gen_baseline", [_write(tmp_path, doc)])
    assert result.returncode == 2
    assert '"uplinks[0].psk"' in result.stderr
    assert CANARY not in result.stdout + result.stderr


@pytest.mark.parametrize("url", [f"ftp://backup:{CANARY}@192.0.2.9/cfg",
                                 f"backup:{CANARY}@192.0.2.9:cfg",
                                 "scp://192.0.2.9/cfg"])
def test_archive_path_rejects_urls(tmp_path, url):
    doc = _example()
    doc["archive"] = {"path": url}
    result = run_cli("gen_baseline", [_write(tmp_path, doc)])
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert '"archive.path"' in result.stderr
    assert CANARY not in combined
    assert "192.0.2.9" not in combined


def test_url_credentials_rejected_in_any_string(tmp_path):
    doc = _example()
    doc["uplinks"][0]["description"] = f"see https://ops:{CANARY}@wiki.example.invalid/x"
    result = run_cli("gen_baseline", [_write(tmp_path, doc)])
    assert result.returncode == 2
    assert '"uplinks[0].description"' in result.stderr
    assert CANARY not in result.stdout + result.stderr


def test_json_schema_agrees_on_examples_and_secret_rows():
    import jsonschema                         # requirements-dev.txt; never skipped (AC1)
    schema = json.loads((SKILL_DIR / "data" / "schema" / "spec.schema.json")
                        .read_text(encoding="utf-8"))
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    for name in EXAMPLE_SPECS:
        errors = list(validator.iter_errors(_example(name)))
        assert not errors, (name, [e.message for e in errors])
    assert not list(validator.iter_errors(_variant()))
    for path, _named, _ph in SECRET_ROWS:
        assert list(validator.iter_errors(_inject(_example(), path, "x"))), path


# ---------------------------------------------------------------------------------------
# Spec errors: exit 2, the key named, never a value
# ---------------------------------------------------------------------------------------

def _bad(mutate):
    doc = _example()
    mutate(doc)
    return doc


BAD_SPECS = {
    "hostname-shape": (_bad(lambda d: d.update(hostname=f"{CANARY} x")), '"hostname"'),
    "description-newline": (_bad(lambda d: d["uplinks"][0].update(
        description=f"ok\n enable password {CANARY}")), '"uplinks[0].description"'),
    "banner-delimiter": (_bad(lambda d: d["banner"].update(motd=f"hi ^C {CANARY}")),
                         '"banner.motd"'),
    "unknown-key-elided": (_bad(lambda d: d.update({f"{CANARY}-x": 1})), "not a recognised"),
    "vlan-1-mgmt": (_bad(lambda d: d["management"].update(vlan=1)), '"management.vlan"'),
    "mgmt-kind-mismatch": (_bad(lambda d: d["management"].update(vlan=10)), '"vlans[0].kind"'),
    "access-vlan-not-data": (_bad(lambda d: d["access_ports"][0].update(vlan=20)),
                             '"access_ports[0].vlan"'),
    "voice-vlan-not-voice": (_bad(lambda d: d["access_ports"][0].update(voice_vlan=10)),
                             '"access_ports[0].voice_vlan"'),
    "range-overlap": (_bad(lambda d: d.update(unused_ports=["GigabitEthernet1/0/20 - 48"])),
                      '"unused_ports[0]"'),
    "undefined-allowed-vlan": (_bad(lambda d: d["uplinks"][0].update(allowed_vlans=[10, 77])),
                               '"uplinks[0].allowed_vlans[1]"'),
    "no-aaa-server": (_bad(lambda d: d.update(aaa={"group_name": "X"})), '"aaa"'),
    "dai-without-snooping": (_bad(lambda d: d["features"].update(dhcp_snooping=False)),
                             '"features.dai"'),
    "gateway-outside-subnet": (_bad(lambda d: d["management"].update(gateway="198.51.100.1")),
                               '"management.gateway"'),
    "root-priority-step": (_bad(lambda d: d.update(stp={"root_priority": 5000})),
                           '"stp.root_priority"'),
    "bool-as-string": (_bad(lambda d: d["features"].update(udld="yes")), '"features.udld"'),
    "version-2": (_bad(lambda d: d.update(version=2)), '"version"'),
}


@pytest.mark.parametrize("case", sorted(BAD_SPECS))
def test_invalid_spec_exits_2_naming_the_key_and_no_value(tmp_path, case):
    doc, expected = BAD_SPECS[case]
    result = run_cli("gen_baseline", [_write(tmp_path, doc)])
    combined = result.stdout + result.stderr
    assert result.returncode == 2, combined
    assert expected in result.stderr, result.stderr
    assert CANARY not in combined
    assert "Traceback" not in combined


# C1 controls, bidi controls, zero-width and every other Cc/Cf character
# are rejected in the banner and in every other free-text field, naming the field only.
BAD_CHARS = {
    "csi-sequence": "hi \x9b31m", "nel-control": "a\x85b", "rlo-override": "a‮b",
    "c1-first": "a\x80b", "c1-last": "a\x9fb",
    **{f"bidi-{c:04x}": f"a{chr(c)}b" for c in (*range(0x202A, 0x202F), *range(0x2066, 0x206A),
                                                0x200E, 0x200F)},
    **{f"zero-width-{c:04x}": f"a{chr(c)}b" for c in (0x200B, 0x200C, 0x200D, 0xFEFF)},
    "cf-soft-hyphen": "a­b", "cf-tag": "a\U000e0041b", "zl-line-sep": "a b",
    "c0-tab": "a\tb", "c0-escape": "a\x1b[2Jb", "del": "a\x7fb", "lone-cr": "a\rb",
    "private-use": "ab",
}


@pytest.mark.parametrize("case", sorted(BAD_CHARS))
def test_banner_rejects_control_bidi_and_invisible_characters(tmp_path, case):
    doc = _example()
    doc["banner"]["motd"] = f"Authorized use only {CANARY} " + BAD_CHARS[case]
    result = run_cli("gen_baseline", [_write(tmp_path, doc)])
    combined = result.stdout + result.stderr
    assert result.returncode == 2, (case, combined)
    assert '"banner.motd"' in result.stderr
    assert "bidirectional-override" in result.stderr
    assert CANARY not in combined and result.stdout == ""


FREE_TEXT_FIELDS = {
    "hostname": lambda d, v: d.update(hostname="SW" + v),
    "domain_name": lambda d, v: d.update(domain_name="ex" + v + ".invalid"),
    "uplinks[0].description": lambda d, v: d["uplinks"][0].update(description="up " + v),
    "access_ports[0].description": lambda d, v: d["access_ports"][0].update(description=v),
    "access_ports[0].range": lambda d, v: d["access_ports"][0].update(
        range="GigabitEthernet1/0/1" + v + " - 24"),
    "vlans[0].name": lambda d, v: d["vlans"][0].update(name="DATA" + v),
    "management.acl_name": lambda d, v: d["management"].update(acl_name="MGMT" + v),
    "snmp.v3_user": lambda d, v: d["snmp"].update(v3_user="mon" + v),
    "archive.path": lambda d, v: d["archive"].update(path="flash:arch" + v),
}


@pytest.mark.parametrize("field", sorted(FREE_TEXT_FIELDS))
@pytest.mark.parametrize("char", ["‮", "\x85", "​", "﻿", "\n"])
def test_free_text_fields_reject_hidden_characters(tmp_path, field, char):
    doc = _example()
    FREE_TEXT_FIELDS[field](doc, char)
    result = run_cli("gen_baseline", [_write(tmp_path, doc)])
    assert result.returncode == 2, (field, repr(char), result.stderr)
    assert f'"{field}"' in result.stderr, result.stderr
    assert result.stdout == ""


def test_banner_keeps_line_breaks_and_printable_unicode():
    doc = _example()
    doc["banner"]["motd"] = "Zutritt nur für Befugte.\r\nAll activity is monitored."
    _spec, lines = _render_text(doc)
    i = lines.index("banner motd ^C")
    assert lines[i + 1:i + 4] == ("Zutritt nur für Befugte.", "All activity is monitored.",
                                  "^C")


def test_schema_banner_pattern_agrees_with_the_validator():
    import jsonschema
    schema = json.loads((SKILL_DIR / "data" / "schema" / "spec.schema.json")
                        .read_text(encoding="utf-8"))
    validator = jsonschema.Draft202012Validator(schema)
    for case, text in BAD_CHARS.items():
        doc = _example()
        doc["banner"]["motd"] = text
        assert list(validator.iter_errors(doc)), case
    doc = _example()
    doc["banner"]["motd"] = "Zutritt nur für Befugte.\nAll activity is monitored."
    assert not list(validator.iter_errors(doc))


# An integer beyond the interpreter's digit limit is exit 2, not exit 4;
# every numeric field stays bounded.
BIG_INTS = {
    "version-5000-digits": ('"version"', "9" * 5000),
    "vlan-id-30-digits": ('"id"', "1" + "0" * 29),
    "negative-5000": ('"key_id"', "-" + "9" * 5000),
}


@pytest.mark.parametrize("case", sorted(BIG_INTS))
def test_huge_integer_is_exit_2(tmp_path, case):
    key, literal = BIG_INTS[case]
    text = json.dumps(_example())
    if key == '"version"':
        text = text.replace('"version": 1', f'"version": {literal}', 1)
    elif key == '"id"':
        text = text.replace('"id": 10', f'"id": {literal}', 1)
    else:
        text = text.replace('"key_id": 1', f'"key_id": {literal}', 1)
    assert literal in text
    p = tmp_path / "big.json"
    p.write_text(text, encoding="utf-8")
    result = run_cli("gen_baseline", [str(p)])
    assert result.returncode == 2, result.stderr
    assert "too large" in result.stderr
    assert "Traceback" not in result.stderr and "internal" not in result.stderr
    assert result.stdout == ""


NUMERIC_BOUNDS = {
    "management.vlan": (lambda d, v: d["management"].update(vlan=v), (1, 4095, 1003)),
    "vlans[0].id": (lambda d, v: d["vlans"][0].update(id=v), (0, 4095, 1002)),
    "uplinks[0].allowed_vlans[0]": (lambda d, v: d["uplinks"][0].update(allowed_vlans=[v]),
                                    (1, 4095, 1005)),
    "uplinks[0].channel_group": (lambda d, v: d["uplinks"][0].update(channel_group=v),
                                 (0, 129, 1.5)),
    "stp.root_priority": (lambda d, v: d["stp"].update(root_priority=v), (-4096, 65536, 4097)),
    "ntp.key_id": (lambda d, v: d["ntp"].update(key_id=v), (0, 65536, True)),
}


@pytest.mark.parametrize("field", sorted(NUMERIC_BOUNDS))
def test_numeric_fields_are_bounded(field):
    spec_mod, _render = _modules()
    mutate, bad_values = NUMERIC_BOUNDS[field]
    for v in bad_values:
        doc = _example()
        mutate(doc, v)
        with pytest.raises(spec_mod.SpecError) as ei:
            spec_mod.from_doc(doc)
        assert ei.value.key == field, (field, v, str(ei.value))


def test_invalid_json_and_unreadable_file_exit_2(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"version": 1, "hostname": "' + CANARY + '",', encoding="utf-8")
    r1 = run_cli("gen_baseline", [str(bad)])
    assert r1.returncode == 2 and "not valid JSON" in r1.stderr
    assert CANARY not in r1.stdout + r1.stderr
    dup = tmp_path / "dup.json"
    dup.write_text('{"version": 1, "version": 1}', encoding="utf-8")
    r2 = run_cli("gen_baseline", [str(dup)])
    assert r2.returncode == 2 and "appears twice" in r2.stderr
    r3 = run_cli("gen_baseline", [str(tmp_path / "missing.json")])
    assert r3.returncode == 2 and "cannot read spec file" in r3.stderr
    r4 = run_cli("gen_baseline", [str(bad), "--format", "yaml"])
    assert r4.returncode == 2


# ---------------------------------------------------------------------------------------
# test_determinism and the output contract
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,doc", ALL_SPECS, ids=[n for n, _ in ALL_SPECS])
def test_determinism(name, doc):
    _spec, first = _render_text(doc)
    _spec, second = _render_text(doc)
    assert first == second
    assert first and first[-1] == "end"


def test_determinism_across_processes_and_hash_seeds(monkeypatch):
    spec = str(SPECS_DIR / "access-switch-multivlan.json")
    outs = []
    for seed in ("0", "12345"):
        monkeypatch.setenv("PYTHONHASHSEED", seed)
        r = run_cli("gen_baseline", [spec, "--format", "json"])
        assert r.returncode == 0, r.stderr
        outs.append(r.stdout)
    assert outs[0] == outs[1]


@pytest.mark.parametrize("name,doc", ALL_SPECS, ids=[n for n, _ in ALL_SPECS])
def test_placeholders_listed(name, doc):
    spec_mod, render = _modules()
    spec = spec_mod.from_doc(copy.deepcopy(doc))
    lines = render.render(spec)
    out = json.loads(render.render_json(spec))
    assert out["lines"] == list(lines)
    emitted = []
    for line in lines:
        for m in PLACEHOLDER_RE.finditer(line):
            if m.group(0) not in emitted:
                emitted.append(m.group(0))
    assert out["placeholders"] == emitted
    assert "<REPLACE-ME:enable-secret>" in emitted
    assert "<REPLACE-ME:local-admin-secret>" in emitted
    assert re.fullmatch(r"[0-9a-f]{64}", out["spec_digest"])
    # the footer lists every placeholder, before `end`
    footer = lines[lines.index("! vault, before this configuration is used:") + 1:]
    assert [ln[4:] for ln in footer if ln.startswith("!   <")] == emitted
    # nothing that looks like a placeholder but is malformed
    assert not re.search(r"<REPLACE-ME:(?![a-z0-9-]+>)", "\n".join(lines))


def test_no_value_is_emitted_into_a_secret_slot():
    """Every secret-bearing line ends in a placeholder: nothing is generated for it."""
    for _name, doc in ALL_SPECS:
        _spec, lines = _render_text(doc)
        for line in lines:
            s = line.strip()
            if re.match(r"(enable .*secret|username .*secret| ?key |ntp authentication-key|"
                        r"snmp-server user)", s):
                assert PLACEHOLDER_RE.search(s), line
                tail = s.split()[-1]
                assert PLACEHOLDER_RE.fullmatch(tail), line


def test_digest_is_of_the_defaults_applied_spec():
    spec_mod, _render = _modules()
    a = _example()
    b = copy.deepcopy(a)
    b["stp"] = {}                              # same meaning once defaults are applied
    b["stp"]["mode"] = "rapid-pvst"
    assert spec_mod.from_doc(a).digest() == spec_mod.from_doc(b).digest()


# ---------------------------------------------------------------------------------------
# test_no_redaction_token_in_output, both halves
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", EXAMPLE_SPECS)
@pytest.mark.parametrize("fmt", ("cli", "json"))
def test_no_redaction_token_in_output(name, fmt):
    r = run_cli("gen_baseline", [str(SPECS_DIR / name), "--format", fmt])
    assert r.returncode == 0, r.stderr
    assert r.stderr == ""
    assert "[REDACTED" not in r.stdout
    if fmt == "json":
        json.loads(r.stdout)


def _manifest_ids():
    return [m["fixture"] for m in all_manifests()]


@pytest.mark.parametrize("fixture_rel", _manifest_ids())
def test_no_redaction_token_in_audit_remediation(fixture_rel):
    require_module_or_fail("ciscocheck.rules")
    r = run_cli("audit_config", [str(fixture_path(fixture_rel)), "--format", "json"])
    assert r.returncode in (0, 1), f"exit {r.returncode}: {r.stderr[:500]}"
    doc = json.loads(r.stdout)
    for f in doc["findings"]:
        for line in f["remediation"]:
            assert "[REDACTED" not in line, (fixture_rel, f["check_id"])


# ---------------------------------------------------------------------------------------
# The generator's product passes both masking layers untouched
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("name,doc", ALL_SPECS, ids=[n for n, _ in ALL_SPECS])
def test_output_passes_egress_scrub(name, doc):
    mask = require_module_or_fail("ciscocheck.mask")
    spec_mod, render = _modules()
    spec = spec_mod.from_doc(copy.deepcopy(doc))
    for line in render.render(spec):
        assert mask.scrub(line) == (), line
    for line in render.render_json(spec).split("\n"):
        assert mask.scrub(line) == (), line


@pytest.mark.parametrize("name,doc", ALL_SPECS, ids=[n for n, _ in ALL_SPECS])
def test_ingest_masker_redacts_nothing_in_the_output(name, doc):
    parser = require_module_or_fail("ciscocheck.parser")
    spec, lines = _render_text(doc)
    cfg = parser.parse("\n".join(lines) + "\n", platform=spec.platform)
    redacted = [ln.text for ln in cfg.lines() if ln.redactions or "[REDACTED" in ln.text]
    assert not redacted
    codes = collections.Counter(n.code for n in cfg.notes)
    assert codes["CSC-SELF-0003"] == 0          # no paste artefact, nothing after `end`
    assert codes["CSC-SELF-0004"] == 0          # no construct the parser did not recognise
    assert codes["CSC-SELF-0005"] == 0          # the banner closes
    assert "CSC-SELF-0009" in codes and any(n.detail == "nesting=indent" for n in cfg.notes)


# ---------------------------------------------------------------------------------------
# test_roundtrip (AC9) and test_interface_range_survives_roundtrip
# ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("name", EXAMPLE_SPECS)
def test_roundtrip(name):
    parser = require_module_or_fail("ciscocheck.parser")
    engine = require_module_or_fail("ciscocheck.engine")
    model = require_module_or_fail("ciscocheck.model")
    require_module_or_fail("ciscocheck.rules")
    spec, lines = _render_text(_example(name))
    cfg = parser.parse("\n".join(lines) + "\n", platform=spec.platform)
    rep = engine.run(cfg, model.Catalogue.load(None))
    unbound = [n.detail for n in rep.notes if n.code == "CSC-SELF-0004"
               and n.detail.startswith(("no rule for", "rule error in"))]
    assert not unbound, f"round trip is vacuous while rules are missing or failing: {unbound}"
    bad = [(f.severity, f.check_id, f.evidence.source_line_no) for f in rep.findings
           if f.severity in ("critical", "high")]
    assert not bad, bad
    # every placeholder slot surfaces as a CSC-SELF-0007 note on its own line
    noted = collections.defaultdict(list)
    for n in rep.notes:
        if n.code == "CSC-SELF-0007":
            noted[n.line_no].append(n.detail)
    for i, line in enumerate(lines, start=1):
        for m in PLACEHOLDER_RE.finditer(line):
            name_ = m.group(0)[len("<REPLACE-ME:"):-1]
            assert f"unfilled placeholder {name_}" in noted.get(i, []), (i, line)


@pytest.mark.parametrize("name,doc", ALL_SPECS, ids=[n for n, _ in ALL_SPECS])
def test_interface_range_survives_roundtrip(name, doc):
    parser = require_module_or_fail("ciscocheck.parser")
    spec, lines = _render_text(doc)
    has_ranges = bool(spec.access_ports or spec.unused_ports)
    # a spec with no access or unused ranges (distribution-switch.json: trunks only) must
    # emit no `interface range` at all; every other spec must emit one per range
    assert any(ln.startswith("interface range ") for ln in lines) == has_ranges
    assert sum(ln.startswith("interface range ") for ln in lines) == \
        len(spec.access_ports) + len(spec.unused_ports)
    cfg = parser.parse("\n".join(lines) + "\n", platform=spec.platform)
    got = {i.name: i for i in cfg.interfaces()}
    for ap in spec.access_ports:
        members = parser.expand_range(ap.range)
        assert members
        for mbr in members:
            assert mbr in got, mbr
            assert got[mbr].from_range
            assert got[mbr].role == ("voice-access" if ap.voice_vlan else "access"), mbr
            assert got[mbr].evidence_line.text.startswith("interface range ")
    for rng in spec.unused_ports:
        for mbr in parser.expand_range(rng):
            assert got[mbr].from_range and got[mbr].role == "unused", mbr
    for up in spec.uplinks:
        assert got[parser.canonical_interface(up.interface)].role in ("uplink", "trunk")


def test_range_roundtrip_coverage_is_kept():
    """At least one example spec must exercise access and unused ranges, so the
    parametrised range test above can never become vacuous."""
    spec_mod, _render = _modules()
    specs = [spec_mod.from_doc(_example(n)) for n in EXAMPLE_SPECS]
    assert any(s.access_ports for s in specs)
    assert any(s.unused_ports for s in specs)
    assert any(len(s.access_ports) > 1 for s in specs)


def test_empty_access_ports_renders_cleanly():
    """No access or unused ranges: sections 60/65 are omitted, not rendered empty."""
    doc = _example()
    doc["access_ports"], doc["unused_ports"] = [], []
    doc["vlans"] = [v for v in doc["vlans"] if v["kind"] != "unused"]
    _spec, lines = _render_text(doc)
    assert not any(ln.startswith("interface range") for ln in lines)
    assert " name PARKING" not in lines                       # no parking VLAN needed
    assert not any(ln.startswith((" switchport port-security", " storm-control"))
                   for ln in lines)
    assert not any(a == b == "!" for a, b in zip(lines, lines[1:]))   # no empty section


# ---------------------------------------------------------------------------------------
# Rendering details that the round trip relies on
# ---------------------------------------------------------------------------------------

def test_banner_is_multiline_and_children_indent_one_space():
    _spec, lines = _render_text(_example())
    i = lines.index("banner motd ^C")
    j = lines.index("^C", i + 1)
    assert j > i + 1
    for line in lines:
        if line.startswith(" "):
            assert not line.startswith("   "), line          # at most two levels (archive)


def test_variant_branches_render():
    _spec, lines = _render_text(_variant())
    text = "\n".join(lines)
    assert "no cdp run" in lines                               # no voice VLAN anywhere
    assert "ntp authentication-key 1 md5 <REPLACE-ME:ntp-key-1>" in lines
    assert "boot system flash:<REPLACE-ME:image-file>" in lines
    assert "redundancy" not in lines
    assert "spanning-tree mst 0 priority 8192" in lines
    assert "aaa group server radius CORP-RADIUS" in lines
    assert "aaa authentication login default group CORP group CORP-RADIUS local" in lines
    assert "interface Port-channel1" in lines and text.count("channel-group 1 mode active") == 2
    assert " switchport trunk native vlan 900" in lines
    assert " permit host 192.0.2.200" in lines
    assert "ip routing" in lines and "ip route 0.0.0.0 0.0.0.0 192.0.2.1" in lines
    assert "vlan 999" in lines and " name PARKING" in lines   # parking VLAN added
    assert not any(ln.startswith("snmp-server user") for ln in lines)


@pytest.mark.parametrize("name,doc", ALL_SPECS, ids=[n for n, _ in ALL_SPECS])
def test_stack_priority_is_an_operator_note_not_config(name, doc):
    """`switch N priority P` is privileged EXEC, never config;
    `stack-mac persistent timer` IS config and stays."""
    spec_mod, render = _modules()
    spec = spec_mod.from_doc(copy.deepcopy(doc))
    lines = render.render(spec)
    note = "Run in privileged EXEC on the stack: switch 1 priority 15"
    assert not any(re.match(r"\s*switch \d+ priority", ln) for ln in lines)
    assert "stack-mac persistent timer 0" in lines
    assert f"!   {note}" in lines                                  # CLI: a comment only
    out = json.loads(render.render_json(spec))
    assert out["operator_notes"] == [note]
    assert list(out) == ["lines", "placeholders", "operator_notes", "spec_digest"]


def test_native_vlan_added_and_kept_off_the_allowed_list():
    _spec, lines = _render_text(_example())
    assert "vlan 998" in lines and " name NATIVE-UNUSED" in lines
    assert " switchport trunk native vlan 998" in lines
    allowed = [ln for ln in lines if ln.startswith(" switchport trunk allowed vlan ")]
    assert allowed and all("998" not in ln.split()[-1].split(",") for ln in allowed)


# ---------------------------------------------------------------------------------------
# CLI surface: stdin, --out, exit 3
# ---------------------------------------------------------------------------------------

def test_stdin_and_out(tmp_path):
    import subprocess
    import sys
    import os
    spec_path = SPECS_DIR / "access-switch-basic.json"
    ref = run_cli("gen_baseline", [str(spec_path)])
    env = dict(os.environ, PYTHONPATH=str(SCRIPTS_DIR))
    proc = subprocess.run([sys.executable, str(SCRIPTS_DIR / "gen_baseline.py"), "-"],
                          input=spec_path.read_bytes(), capture_output=True, env=env,
                          timeout=60)
    assert proc.returncode == 0
    assert proc.stdout.decode("utf-8").replace("\r\n", "\n") == ref.stdout
    out = tmp_path / "baseline.cfg"
    r = run_cli("gen_baseline", [str(spec_path), "--out", str(out)])
    assert r.returncode == 0 and r.stdout == ""
    assert out.read_bytes().decode("utf-8") == ref.stdout


def test_json_is_utf8_on_a_legacy_console(tmp_path):
    """--format json is UTF-8 on stdout whatever the console code page (report.emit utf8=True);
    same technique as test_engine_cli.py::test_machine_formats_are_utf8_on_a_legacy_console."""
    import os
    import subprocess
    import sys
    env = {k: v for k, v in os.environ.items() if k not in ("PYTHONIOENCODING", "PYTHONUTF8")}
    env.update(PYTHONUTF8="0", PYTHONPATH=str(SCRIPTS_DIR), LANG="C", LC_ALL="C")
    console = subprocess.run([sys.executable, "-c", "import sys; print(sys.stdout.encoding)"],
                             env=env, capture_output=True).stdout.decode().strip().lower()
    assert console.replace("-", "") != "utf8", f"console not simulated as legacy: {console}"
    doc = _example()
    doc["banner"]["motd"] = "Zutritt nur für Befugte. All activity is monitored."
    r = subprocess.run([sys.executable, str(SCRIPTS_DIR / "gen_baseline.py"),
                        _write(tmp_path, doc), "--format", "json"],
                       env=env, capture_output=True, timeout=60)
    assert r.returncode == 0, r.stderr
    text = r.stdout.decode("utf-8")                    # raises if the bytes are not UTF-8
    assert "für" in text
    assert "Zutritt nur für Befugte. All activity is monitored." in json.loads(text)["lines"]
    assert b"\r\n" not in r.stdout                     # LF, identical to --out


# The spec is decoded as strict UTF-8 (a BOM is allowed); invalid bytes
# are exit 2 with a named error, and U+FFFD is never produced.
@pytest.mark.parametrize("bad", [b"\xff", b"\xc3\x28", b"\xed\xa0\x80", b"f\xfcr"],
                         ids=["ff", "bad-continuation", "surrogate", "latin1-u-umlaut"])
def test_spec_must_be_strict_utf8(tmp_path, bad):
    text = json.dumps(_example()).encode("utf-8")
    raw = text.replace(b"Authorized use only.", b"Authorized " + bad + b" use only.", 1)
    assert raw != text
    p = tmp_path / "spec.json"
    p.write_bytes(raw)
    r = run_cli("gen_baseline", [str(p)])
    assert r.returncode == 2, r.stderr
    assert "not valid UTF-8" in r.stderr and "offset" in r.stderr
    assert "�" not in r.stdout + r.stderr and r.stdout == ""
    spec_mod = require_module_or_fail("ciscobaseline.spec")
    with pytest.raises(spec_mod.SpecError):
        spec_mod.load(str(p))


def test_spec_utf8_bom_is_accepted(tmp_path):
    p = tmp_path / "spec.json"
    p.write_bytes(b"\xef\xbb\xbf" + json.dumps(_example()).encode("utf-8"))
    r = run_cli("gen_baseline", [str(p)])
    ref = run_cli("gen_baseline", [str(SPECS_DIR / "access-switch-basic.json")])
    assert r.returncode == 0 and r.stdout == ref.stdout


def test_spec_strict_utf8_on_stdin():
    import os
    import subprocess
    import sys
    raw = json.dumps(_example()).encode("utf-8").replace(b"Authorized", b"Author\xffized", 1)
    env = dict(os.environ, PYTHONPATH=str(SCRIPTS_DIR))
    proc = subprocess.run([sys.executable, str(SCRIPTS_DIR / "gen_baseline.py"), "-"],
                          input=raw, capture_output=True, env=env, timeout=60)
    assert proc.returncode == 2
    assert b"not valid UTF-8" in proc.stderr and proc.stdout == b""


# archive.path is on the switch's own file
# system; a scheme-less remote form is exit 2.
@pytest.mark.parametrize("path", ["ftp:192.0.2.1/archive", "tftp:192.0.2.1/cfg", "http:h/x",
                                  "scp:host/archive", "nvram:archive", "Flash:archive",
                                  "rcp:backup/archive"])
def test_archive_path_rejects_remote_schemes(tmp_path, path):
    doc = _example()
    doc["archive"] = {"path": path}
    r = run_cli("gen_baseline", [_write(tmp_path, doc)])
    assert r.returncode == 2, r.stderr
    assert '"archive.path"' in r.stderr and "own file system" in r.stderr
    assert path not in r.stdout + r.stderr


@pytest.mark.parametrize("path", ["flash:archive", "flash:/archive/cfg", "bootflash:archive",
                                  "usbflash0:arch", "flash-2:archive", "crashinfo:a",
                                  "disk0:archive"])
def test_archive_path_accepts_local_file_systems(path):
    spec_mod, _render = _modules()
    doc = _example()
    doc["archive"] = {"path": path}
    _spec, lines = _render_text(doc)
    assert f" path {path}" in lines


# --out may not name
# the spec it reads (same path, hard link or symlink); exit 2, nothing written or emitted.
@pytest.mark.parametrize("how", ["same", "hardlink", "symlink-or-junction"])
def test_out_must_not_overwrite_the_spec(tmp_path, how):
    import os
    import subprocess
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    spec_path = pathlib.Path(_write(real_dir, _example()))
    before = spec_path.read_bytes()
    if how == "same":
        out = spec_path
    elif how == "hardlink":
        out = tmp_path / "hard.json"
        os.link(spec_path, out)
    else:
        # the same fallback as test_engine_cli.py::_link_variants: where the host refuses
        # unprivileged symlinks (Windows error 1314), a directory junction aliases the file
        out = tmp_path / "sym.json"
        try:
            os.symlink(spec_path, out)
        except OSError:
            junction = tmp_path / "junction"
            r = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(real_dir)],
                               capture_output=True)
            assert r.returncode == 0, "neither a symlink nor a junction could be created"
            out = junction / spec_path.name
    r = run_cli("gen_baseline", [str(spec_path), "--out", str(out)])
    assert r.returncode == 2, r.stderr
    assert "--out names an input file" in r.stderr and r.stdout == ""
    assert spec_path.read_bytes() == before


def _copy_build(tmp_path: pathlib.Path) -> pathlib.Path:
    dest = tmp_path / "baseline"
    shutil.copytree(SKILL_DIR / "data" / "baseline", dest)
    return dest


def test_missing_template_is_a_build_error(tmp_path):
    sections = require_module_or_fail("ciscobaseline.sections")
    spec_mod, render = _modules()
    spec = spec_mod.from_doc(_example())
    base = _copy_build(tmp_path)
    (base / "30-ntp.server.tmpl").unlink()
    with pytest.raises(sections.BaselineBuildError) as ei:
        render.render(spec, base=str(base))
    assert "30-ntp.server.tmpl" in str(ei.value)


def test_dropped_section_is_a_build_error(tmp_path):
    sections = require_module_or_fail("ciscobaseline.sections")
    spec_mod, render = _modules()
    base = _copy_build(tmp_path)
    doc = json.loads((base / "sections.json").read_text(encoding="utf-8"))
    doc["sections"] = [s for s in doc["sections"] if s["name"] != "10-users-aaa"]
    (base / "sections.json").write_text(json.dumps(doc), encoding="utf-8")
    with pytest.raises(sections.BaselineBuildError):
        render.render(spec_mod.from_doc(_example()), base=str(base))


def test_unknown_template_field_is_a_build_error(tmp_path):
    sections = require_module_or_fail("ciscobaseline.sections")
    spec_mod, render = _modules()
    base = _copy_build(tmp_path)
    (base / "20-ssh.tmpl").write_text("!\nip ssh version $no_such_field\n", encoding="utf-8")
    with pytest.raises(sections.BaselineBuildError):
        render.render(spec_mod.from_doc(_example()), base=str(base))


def test_cli_build_error_exits_3(tmp_path, monkeypatch, capsys):
    gen = require_module_or_fail("gen_baseline")
    render = require_module_or_fail("ciscobaseline.render")
    base = _copy_build(tmp_path)
    (base / "platforms.json").unlink()
    monkeypatch.setattr(render, "data_dir", lambda: base)
    rc = gen.main([str(SPECS_DIR / "access-switch-basic.json")])
    captured = capsys.readouterr()
    assert rc == 3
    assert "platforms.json" in captured.err and captured.out == ""
