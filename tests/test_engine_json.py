"""--format json shape against a two-entry stub catalogue.

The schema assertion against data/schema/finding.schema.json is written fail-not-skip: if
the file is absent the test FAILS naming the reason (AC1).
"""
from __future__ import annotations

import json
import pathlib

import pytest

from ciscocheck import engine, mask, parser, registry, report
from ciscocheck.model import Catalogue

ROOT = pathlib.Path(__file__).resolve().parent.parent
FINDING_SCHEMA = ROOT / "skills" / "cisco-switch-config" / "data" / "schema" / "finding.schema.json"

STUB = {"version": 1, "catalogue_version": "2026.09", "checks": [
    {"id": "CSC-TST-0001", "title": "HTTP server is enabled", "severity": "high",
     "category": "security", "confidence": "deterministic", "platforms": ["ios", "iosxe"],
     "profiles": ["campus", "stig"], "test_kind": "not-effectively-set",
     "defaults_key": "ip.http.server", "subject": ["ip http server"],
     "rationale": "An enabled web server widens the management attack surface.",
     "params_required": [], "remediation": ["no ip http server"],
     "refs": [{"authority": "DISA-STIG", "id": "TEST-000001", "version": "V1R1",
               "url": "https://public.cyber.mil/stigs/"},
              {"authority": "CIS", "id": "1.1.1", "version": "v1.0.0"}]},
    {"id": "CSC-TST-0002", "title": "Community string is configured", "severity": "medium",
     "category": "reliability", "confidence": "heuristic", "platforms": ["ios", "iosxe"],
     "profiles": ["campus", "stig"], "test_kind": "present",
     "subject": ["snmp-server community"],
     "rationale": "SNMP v1 and v2c carry the credential in clear text.",
     "params_required": [], "remediation": ["no snmp-server community <REPLACE-ME:snmp-community>"],
     "refs": [{"authority": "NIST", "id": "SP-800-53-IA-5"}]},
]}

CFG_TEXT = ("version 17.9\nhostname SW1\nsnmp-server community CANARY-COMMUNITY-01 RO 99\n"
            "interface Gi1/0/1\n switchport mode access\nend\n")


def _rules():
    registry.clear()

    @registry.rule("CSC-TST-0001")
    def http(cfg, ctx):
        eff = ctx.defaults.effective(cfg, ctx.platform, "ip.http.server")
        if eff.state == "on":
            node = cfg.find_one("ip http server")
            yield ctx.finding(line=node.line if node else None)

    @registry.rule("CSC-TST-0002")
    def comm(cfg, ctx):
        for node in cfg.find("snmp-server community"):
            yield ctx.finding(line=node.line)


@pytest.fixture()
def rep():
    _rules()
    try:
        yield engine.run(parser.parse(CFG_TEXT), Catalogue.from_dict(STUB))
    finally:
        registry.clear()


def test_json_shape(rep):
    doc = json.loads(report.render_json(rep))
    assert list(doc) == ["schema_version", "tool", "run", "counts", "findings", "notes"]
    assert doc["schema_version"] == 1
    assert doc["tool"] == {"name": "cisco-switch-config", "skill_version": "1.0.0",
                           "catalogue_version": "2026.09"}
    assert doc["run"] == {"platform": "iosxe", "platform_source": "inferred-version",
                          "profile": "campus", "severity_min": "info", "category": "all",
                          "role_map_applied": False, "checks_evaluated": 2}
    assert doc["counts"] == {"critical": 0, "high": 1, "medium": 1, "low": 0, "info": 0, "total": 2}
    f0, f1 = doc["findings"]
    assert list(f0) == ["check_id", "severity", "category", "confidence", "catalogue_confidence",
                        "title", "rationale", "evidence", "remediation", "refs", "params",
                        "platform", "platform_source", "profile", "skill_version",
                        "catalogue_version"]
    assert f0["evidence"] == {"line_no": None, "source_line_no": None, "text": "", "masked": False,
                              "redactions": 0, "anchor": "absent"}
    assert f1["evidence"]["masked"] is True and f1["evidence"]["redactions"] == 1
    assert "CANARY" not in json.dumps(doc)
    assert doc["notes"][0] == {"code": "CSC-SELF-0001", "line_no": None,
                               "detail": "platform=iosxe source=inferred-version"}


def test_json_output_passes_egress_guard(rep):
    for line in report.render_json(rep).split("\n"):
        assert mask.scrub(line) == ()
    for line in report.render_table(rep).split("\n"):
        assert mask.scrub(line) == ()


def test_findings_validate_against_finding_schema(rep):
    if not FINDING_SCHEMA.exists():
        pytest.fail("data/schema/finding.schema.json is absent: this assertion requires that "
                    "file to be present")
    try:
        import jsonschema
    except ImportError:
        pytest.fail("jsonschema is a required dev dependency (requirements-dev.txt)")
    schema = json.loads(FINDING_SCHEMA.read_text(encoding="utf-8"))
    doc = json.loads(report.render_json(rep))
    cls = jsonschema.validators.validator_for(schema)
    validator = cls(schema)
    for f in doc["findings"]:
        errors = [e.message for e in validator.iter_errors(f)]
        assert errors == [], errors
