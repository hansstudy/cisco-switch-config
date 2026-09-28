"""SARIF 2.1.0 output.

Validates against the vendored schema tests/schema/sarif-2.1.0.json when it exists; when it
does not, the structural assertions still run and the schema assertion FAILS rather than
skips, giving an honest failure naming the reason (AC1).
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from ciscocheck import engine, mask, parser, registry, sarif
from ciscocheck.model import Catalogue

SCHEMA = pathlib.Path(__file__).resolve().parent / "schema" / "sarif-2.1.0.json"

CAT = Catalogue.from_dict({"version": 1, "catalogue_version": "2026.09", "checks": [
    {"id": "CSC-TST-0001", "title": "Login banner is absent", "severity": "medium",
     "category": "security", "confidence": "deterministic", "platforms": ["ios", "iosxe"],
     "profiles": ["campus", "stig"], "test_kind": "absent", "subject": ["banner login"],
     "rationale": "A banner states the terms of authorised use.", "params_required": [],
     "remediation": ["banner login ^C", "Authorized access only.", "^C"],
     "refs": [{"authority": "DISA-STIG", "id": "TEST-1", "version": "V1R1"}]},
    {"id": "CSC-TST-0002", "title": "Community string is read-write", "severity": "critical",
     "category": "security", "confidence": "deterministic", "platforms": ["ios", "iosxe"],
     "profiles": ["campus", "stig"], "test_kind": "present", "subject": ["snmp-server community"],
     "rationale": "A writable community lets anyone holding it reconfigure the switch.",
     "params_required": [], "remediation": ["no snmp-server community <REPLACE-ME:snmp-community>"],
     "refs": [{"authority": "NIST", "id": "SP-800-53-IA-5"}]},
    {"id": "CSC-TST-0003", "title": "Port security maximum is high", "severity": "low",
     "category": "reliability", "confidence": "heuristic", "platforms": ["ios", "iosxe"],
     "profiles": ["campus", "stig"], "test_kind": "value", "subject": [],
     "rationale": "r", "params_required": [], "remediation": [],
     "refs": [{"authority": "NIST", "id": "X"}]},
]})

CFG = ("hostname SW1\nsnmp-server community CANARY-COMMUNITY-01 RW\n"
       "interface Gi1/0/1\n switchport port-security maximum 10\nend\n")


@pytest.fixture(scope="module")
def doc():
    registry.clear()

    @registry.rule("CSC-TST-0001")
    def banner(cfg, ctx):
        if not cfg.has("banner login"):
            yield ctx.finding()

    @registry.rule("CSC-TST-0002")
    def rw(cfg, ctx):
        for n in cfg.find("snmp-server community"):
            yield ctx.finding(line=n.line)

    @registry.rule("CSC-TST-0003")
    def ps(cfg, ctx):
        for n in cfg.find("switchport port-security maximum"):
            yield ctx.finding(line=n.line)

    try:
        rep = engine.run(parser.parse(CFG), CAT)
        yield sarif.to_sarif(rep, artifact_uri="configs/sw1.cfg", catalogue=CAT)
    finally:
        registry.clear()


def test_document_shape(doc):
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-schema-2.1.0.json")
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "cisco-switch-config"
    assert driver["semanticVersion"] == "1.0.0" and driver["version"] == "2026.09"
    assert driver["informationUri"] == "https://hans.study/tools/cisco-switch-config/"
    ids = [r["id"] for r in driver["rules"]]
    assert ids[:3] == ["CSC-TST-0002", "CSC-TST-0001", "CSC-TST-0003"]
    assert "CSC-SELF-0001" in ids                         # synthesised note rule
    r2 = driver["rules"][0]
    assert r2["properties"]["security-severity"] == "9.5"
    assert r2["properties"]["tags"][:2] == ["security", "deterministic"]
    assert r2["help"]["text"] == "no snmp-server community <REPLACE-ME:snmp-community>"


def test_level_mapping(doc):
    levels = {r["ruleId"]: r["level"] for r in doc["runs"][0]["results"]}
    assert levels["CSC-TST-0002"] == "error"      # critical
    assert levels["CSC-TST-0001"] == "warning"    # medium
    assert levels["CSC-TST-0003"] == "warning"    # low
    assert levels["CSC-SELF-0001"] == "note"
    mapping = {"critical": "error", "high": "error", "medium": "warning", "low": "warning",
               "info": "note"}
    assert sarif._LEVEL == mapping


def test_absence_finding_anchors_at_line_1(doc):
    res = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "CSC-TST-0001")
    assert res["message"]["text"].startswith("Not configured: ")
    region = res["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1 and region["snippet"]["text"] == ""


def test_fingerprints_recompute_from_emitted_snippet(doc):
    text = json.dumps(doc)
    assert "CANARY" not in text
    for res in doc["runs"][0]["results"]:
        snippet = res["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
        expect = hashlib.sha256((res["ruleId"] + "\n" + snippet).encode("utf-8")).hexdigest()
        assert res["partialFingerprints"]["primaryLocationLineHash"] == expect
    rw = next(r for r in doc["runs"][0]["results"] if r["ruleId"] == "CSC-TST-0002")
    assert rw["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] == \
        "snmp-server community [REDACTED snmp-community, 19 chars] RW"
    assert rw["locations"][0]["physicalLocation"]["region"]["startLine"] == 2
    for line in json.dumps(doc, indent=2).split("\n"):
        assert mask.scrub(line) == ()


def test_validates_against_vendored_schema(doc):
    if not SCHEMA.exists():
        pytest.fail("tests/schema/sarif-2.1.0.json is absent: this assertion requires that "
                    "file to be present")
    try:
        import jsonschema
    except ImportError:
        pytest.fail("jsonschema is a required dev dependency (requirements-dev.txt)")
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    cls = jsonschema.validators.validator_for(schema)
    errors = [e.message for e in cls(schema).iter_errors(doc)]
    assert errors == [], errors[:5]


def test_multiline_remediation_survives_egress_in_sarif_and_json():
    """A two-line remediation like CSC-AAA-0011's is joined with `\\n` into help.text and
    JSON-escaped; it must pass the egress guard in SARIF and JSON."""
    from ciscocheck import report
    cat = Catalogue.from_dict({"version": 1, "catalogue_version": "2026.09", "checks": [
        {"id": "CSC-TST-0011", "title": "Weak enable credential", "severity": "high",
         "category": "security", "confidence": "deterministic", "platforms": ["ios", "iosxe"],
         "profiles": ["campus", "stig"], "test_kind": "present", "subject": ["enable password"],
         "rationale": "r", "params_required": [],
         "remediation": ["no enable password",
                         "enable algorithm-type sha256 secret <REPLACE-ME:enable-secret>"],
         "refs": [{"authority": "NIST", "id": "X"}]}]})
    registry.clear()
    try:
        @registry.rule("CSC-TST-0011")
        def weak(cfg, ctx):
            for n in cfg.find("enable password"):
                yield ctx.finding(line=n.line)

        rep = engine.run(parser.parse("hostname SW1\nenable password 7 CANARY7-0822455D0A16\n"
                                      "interface Gi1/0/1\n shutdown\nend\n"), cat)
        assert rep.counts["total"] == 1
        out = json.dumps(sarif.to_sarif(rep, artifact_uri="sw1.cfg", catalogue=cat), indent=2)
        report._guard(out)                         # raises EgressGuardError on any hit
        report._guard(report.render_json(rep))
        report._guard(report.render_table(rep))
        assert "CANARY7" not in out
    finally:
        registry.clear()
