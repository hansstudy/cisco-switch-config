"""The ctx.finding() contract."""
from __future__ import annotations

import pytest

from ciscocheck import engine, parser, registry
from ciscocheck.model import Catalogue, Context

CFG = parser.parse("hostname SW1\nsnmp-server community CANARY-COMMUNITY-01 RO 99\n"
                   "interface Gi1/0/1\n switchport mode access\nend\n")


def make_entry(**kw):
    d = {"id": "CSC-TST-0001", "title": "Community string is configured", "severity": "high",
         "category": "security", "confidence": "deterministic", "platforms": ["ios", "iosxe"],
         "profiles": ["campus", "stig"], "test_kind": "present", "subject": [],
         "rationale": "Test rationale.", "params_required": ["interface"],
         "refs": [{"authority": "DISA-STIG", "id": "TEST-1", "version": "V1R1"}],
         "remediation": ["interface {interface}", " no shutdown {{literal}}"]}
    d.update(kw)
    return Catalogue.from_dict({"version": 1, "catalogue_version": "2026.09", "checks": [d]})


def ctx_for(cat, sink=None, profile="campus"):
    return Context(platform="iosxe", platform_source="given", profile=profile, role_map={},
                   defaults=CFG.defaults, dialect=CFG.dialect, refs_index=CFG.refs,
                   entry=cat.entries[0], skill_version="1.0.0", catalogue_version="2026.09",
                   note_sink=sink)


def test_masked_and_redactions_are_computed_from_the_line():
    line = CFG.find_one("snmp-server community").line
    f = ctx_for(make_entry()).finding(line=line, params={"interface": "Gi1"})
    assert f.evidence.masked is True and f.evidence.redactions == 1
    assert f.evidence.text == line.text and "CANARY" not in f.evidence.text
    assert f.evidence.anchor == "line"
    plain = CFG.find_one("hostname SW1").line
    f = ctx_for(make_entry()).finding(line=plain, params={"interface": "Gi1"})
    assert f.evidence.masked is False and f.evidence.redactions == 0


@pytest.mark.parametrize("kw", ["masked", "redactions", "evidence", "check_id", "title",
                                "rationale", "refs", "confidence", "catalogue_confidence"])
def test_refused_kwargs_raise_type_error(kw):
    with pytest.raises(TypeError):
        ctx_for(make_entry()).finding(**{kw: True})


def test_total_substitution_renders_todo_and_records_self_0002():
    sink = []
    f = ctx_for(make_entry(), sink).finding()
    assert f.remediation == ("interface <TODO:interface>", " no shutdown {literal}")
    assert [(n.code, n.detail) for n in sink] == [("CSC-SELF-0002", "check=CSC-TST-0001 var=interface")]


def test_engine_surfaces_self_0002_note():
    registry.clear()
    try:
        registry.register("CSC-TST-0001", lambda cfg, ctx: iter([ctx.finding()]))
        rep = engine.run(CFG, make_entry())
        assert any(n.code == "CSC-SELF-0002" for n in rep.notes)
    finally:
        registry.clear()


def test_confidence_promotion_only_with_role_map():
    cat = make_entry(confidence="heuristic")
    f = ctx_for(cat).finding(role_source="role-map", params={"interface": "x"})
    assert f.confidence == "deterministic" and f.catalogue_confidence == "heuristic"
    for src in ("inferred-access", "default", None):
        f = ctx_for(cat).finding(role_source=src, params={"interface": "x"})
        assert f.confidence == "heuristic"
    f = ctx_for(make_entry(confidence="manual-review")).finding(role_source="role-map")
    assert f.confidence == "manual-review"


def test_severity_rules():
    assert ctx_for(make_entry(severity_by_profile={"stig": "critical"}), profile="stig") \
        .finding().severity == "critical"
    with pytest.raises(ValueError):
        ctx_for(make_entry()).finding(severity="low")
    f = ctx_for(make_entry(severity_allowed_overrides=["low"])).finding(severity="low")
    assert f.severity == "low"


def test_absence_finding_shape_and_stamping():
    f = ctx_for(make_entry()).finding(params={"interface": "Gi1"}, title_suffix="Gi1")
    ev = f.evidence
    assert (ev.line_no, ev.source_line_no, ev.text, ev.masked, ev.redactions, ev.anchor) == (
        None, None, "", False, 0, "absent")
    assert f.title == "Community string is configured - Gi1"
    assert (f.platform, f.platform_source, f.profile, f.skill_version, f.catalogue_version) == (
        "iosxe", "given", "campus", "1.0.0", "2026.09")
    assert dict(f.params) == {"interface": "Gi1"}
    assert f.refs[0].id == "TEST-1"


def test_remediation_intent_resolves_through_dialect():
    cat = make_entry(remediation=None, remediation_intent="stp.bpduguard.default",
                     params_required=[])
    assert ctx_for(cat).finding().remediation == ("spanning-tree portfast edge bpduguard default",)


def test_substitution_never_evaluates_attributes():
    cat = make_entry(remediation=["{interface.__class__}", "{0}", "{interface}"])
    f = ctx_for(cat).finding(params={"interface": "Gi1"})
    assert f.remediation == ("{interface.__class__}", "{0}", "Gi1")
