"""Registry and end-to-end engine run, using stub rules defined here.

This exercises the engine independently of the `ciscocheck.rules` package, using local
stub rules instead.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from ciscocheck import engine, parser, registry
from ciscocheck.model import Catalogue

PKG = pathlib.Path(registry.__file__).resolve().parent

BASE = {"platforms": ["ios", "iosxe"], "profiles": ["campus", "stig"], "subject": [],
        "params_required": [], "refs": [{"authority": "NIST", "id": "SP-800-53-CM-7"}]}


def entry(cid, **kw):
    d = dict(BASE, id=cid, title=f"Test check {cid[-4:]}", severity="medium",
             category="security", confidence="deterministic", test_kind="present",
             rationale="Test rationale.", remediation=["no ip http server"])
    d.update(kw)
    return d


def catalogue(*entries):
    return Catalogue.from_dict({"version": 1, "catalogue_version": "2026.09",
                                "checks": list(entries)})


CFG = parser.parse("version 17.9\nhostname SW1\nip http server\ninterface Gi1/0/1\n"
                   " switchport mode access\ninterface Gi1/0/2\n switchport mode access\nend\n")


@pytest.fixture(autouse=True)
def isolated_registry():
    registry.clear()
    yield
    registry.clear()


def rule_http(cfg, ctx):
    node = cfg.find_one("ip http server")
    if node is not None:
        yield ctx.finding(line=node.line)


def rule_ports(cfg, ctx):
    for i in cfg.interfaces(role="access"):
        yield ctx.finding(line=i.evidence_line, params={"interface": i.name},
                          role_source=i.role_source, title_suffix=i.name)


def rule_boom(cfg, ctx):
    raise ValueError("invalid literal for int() with base 10: 'S3cret'")
    yield  # pragma: no cover


def test_register_and_rules_yield_stub_rules():
    registry.register("CSC-TST-0001", rule_http, supplies=())
    registry.register("CSC-TST-0002", rule_ports, supplies=("interface",))
    assert [cid for cid, _ in registry.rules()] == ["CSC-TST-0001", "CSC-TST-0002"]
    assert registry.supplies_of("CSC-TST-0002") == ("interface",)
    assert registry.lookup("CSC-TST-0001") is rule_http


def test_decorators_and_extractors():
    @registry.rule("CSC-TST-0003", supplies=("vlan",))
    def r(cfg, ctx):
        yield from ()

    @registry.extractor("CSC-TST-0004")
    def x(cfg, ctx):
        yield from ()

    assert registry.rules() == (("CSC-TST-0003", r),)
    assert registry.extractors() == (("CSC-TST-0004", x),)
    assert registry.supplies_of("CSC-TST-0003") == ("vlan",)


def test_duplicate_registration_raises():
    registry.register("CSC-TST-0001", rule_http)
    with pytest.raises(ValueError):
        registry.register("CSC-TST-0001", rule_ports)
    with pytest.raises(ValueError):
        registry.register_extractor("CSC-TST-0001", rule_ports)


def test_clear_isolates():
    registry.register("CSC-TST-0001", rule_http)
    registry.clear()
    assert registry.rules() == () and registry.extractors() == ()
    registry.register("CSC-TST-0001", rule_http)     # no duplicate after clear


def test_registry_imports_nothing_from_rules():
    tree = ast.parse((PKG / "registry.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert "rules" not in (node.module or "")
        if isinstance(node, ast.Import):
            assert all("rules" not in a.name for a in node.names)


def test_run_end_to_end_with_stub_rules():
    registry.register("CSC-TST-0001", rule_http)
    registry.register("CSC-TST-0002", rule_ports, supplies=("interface",))
    cat = catalogue(entry("CSC-TST-0001", severity="high"),
                    entry("CSC-TST-0002", severity="low", category="reliability",
                          confidence="heuristic", remediation=["interface {interface}",
                                                                " spanning-tree bpduguard enable"],
                          params_required=["interface"]))
    rep = engine.run(CFG, cat)
    assert [f.check_id for f in rep.findings] == ["CSC-TST-0001", "CSC-TST-0002", "CSC-TST-0002"]
    assert rep.counts["total"] == 3 and rep.counts["high"] == 1 and rep.counts["low"] == 2
    assert rep.checks_evaluated == 2
    assert rep.findings[1].remediation == ("interface GigabitEthernet1/0/1",
                                           " spanning-tree bpduguard enable")
    assert rep.platform == "iosxe" and rep.platform_source == "inferred-version"
    # filters
    assert engine.run(CFG, cat, severity_min="high").counts["total"] == 1
    assert engine.run(CFG, cat, category="reliability").counts["total"] == 2
    assert engine.run(CFG, cat, category="reliability").checks_evaluated == 1


def test_sorting_by_severity_then_id_then_line():
    registry.register("CSC-TST-0001", rule_ports)
    registry.register("CSC-TST-0002", rule_http)
    cat = catalogue(entry("CSC-TST-0001", severity="low", remediation=["x {interface}"],
                          params_required=["interface"]),
                    entry("CSC-TST-0002", severity="critical"))
    rep = engine.run(CFG, cat)
    assert [(f.severity, f.check_id, f.evidence.line_no) for f in rep.findings] == [
        ("critical", "CSC-TST-0002", 3), ("low", "CSC-TST-0001", 4), ("low", "CSC-TST-0001", 6)]


def test_platform_and_profile_skip_silently():
    registry.register("CSC-TST-0001", rule_http)
    registry.register("CSC-TST-0002", rule_http)
    cat = catalogue(entry("CSC-TST-0001", platforms=["ios"]),
                    entry("CSC-TST-0002", profiles=["stig"]))
    rep = engine.run(CFG, cat, profile="campus")
    assert rep.findings == () and rep.checks_evaluated == 0
    assert engine.run(CFG, cat, profile="stig").counts["total"] == 1


def test_a_rule_that_raises_becomes_a_content_free_note_and_others_run():
    registry.register("CSC-TST-0001", rule_boom)
    registry.register("CSC-TST-0002", rule_http)
    cat = catalogue(entry("CSC-TST-0001"), entry("CSC-TST-0002"))
    rep = engine.run(CFG, cat)
    assert [f.check_id for f in rep.findings] == ["CSC-TST-0002"]
    note = next(n for n in rep.notes if n.code == "CSC-SELF-0004")
    assert note.detail == "rule error in CSC-TST-0001"
    assert "S3cret" not in note.detail


def test_entry_without_rule_emits_note_and_continues():
    registry.register("CSC-TST-0002", rule_http)
    rep = engine.run(CFG, catalogue(entry("CSC-TST-0001"), entry("CSC-TST-0002")))
    assert any(n.detail == "no rule for CSC-TST-0001" for n in rep.notes)
    assert rep.counts["total"] == 1


def test_generic_reference_check_excludes_pairs_already_reported():
    def generic(cfg, ctx):
        yield ctx.finding(params={"acl_name": "10"})
        yield ctx.finding(params={"acl_name": "20"})

    def specific(cfg, ctx):
        yield ctx.finding(params={"acl_name": "10"})

    registry.register("CSC-MGT-0014", generic)
    registry.register("CSC-VTY-0003", specific)
    rep = engine.run(CFG, catalogue(entry("CSC-MGT-0014"), entry("CSC-VTY-0003")))
    assert sorted((f.check_id, dict(f.params)["acl_name"]) for f in rep.findings) == [
        ("CSC-MGT-0014", "20"), ("CSC-VTY-0003", "10")]


def test_catalogue_loader_rejects_bad_documents():
    from ciscocheck.model import CatalogueError
    with pytest.raises(CatalogueError):
        catalogue(entry("CSC-SELF-0001"))
    with pytest.raises(CatalogueError):
        catalogue(entry("CSC-TST-0001", severity="urgent"))
    with pytest.raises(CatalogueError):
        catalogue(entry("CSC-TST-0001", remediation_intent="x"))       # both remediation forms
    with pytest.raises(CatalogueError):
        catalogue(entry("CSC-TST-0001"), entry("CSC-TST-0001"))
    with pytest.raises(CatalogueError):
        Catalogue.load("does/not/exist.json")


def test_real_catalogue_loads_through_catalogue_load():
    # the shipped data/catalogue.json must load: CSC-L2-* ids carry a digit in the family
    real = Catalogue.load()
    assert len(real) == 121
    assert any(e.id.startswith("CSC-L2-") for e in real)
    assert [e.id for e in real.entries] == sorted(e.id for e in real.entries)


def test_catalogue_id_pattern():
    from ciscocheck.model import CatalogueError
    catalogue(entry("CSC-L2-0001"))                          # digit in the family: accepted
    for bad in ("CSC-L2-000\u0661", "CSC-l2-0001", "CSC-L-0001", "CSC-TOOLONG-0001"):
        with pytest.raises(CatalogueError):
            catalogue(entry(bad))
