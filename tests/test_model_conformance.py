"""Conformance tests for the parsed-config object model, `Context`, and the `Finding`
factory.

This file is a contract test: it pins the object model's expected behaviour independent of
its implementation. If a future reading of the contract disagrees with an assertion here,
that calls for a deliberate specification change, not a local edit to make the test agree
with a particular implementation.

Every test below imports `ciscocheck.*` **inside the test function**, via
`conftest.require_module_or_fail`, never at module scope, so a missing module fails with a
message naming the reason rather than silently skipping or passing (AC1 forbids skipping).

The thirteen assertions below are numbered and transcribed in order from this file's own
contract list.
"""

from __future__ import annotations

import pathlib

import pytest

from conftest import require_module_or_fail


# ---------------------------------------------------------------------------------------
# Construction helpers
#
# These centralise every guess this file has to make about exact field names on
# `ciscocheck.model.CatalogueEntry` and `Context`. If the real field names differ from this
# reading of the contract, only these two helpers need to change -- not the thirteen
# assertions below.
# ---------------------------------------------------------------------------------------


# Padding prepended to every inline test config so the exit-2 "not a Cisco configuration"
# heuristic (fewer than 3 non-blank non-comment lines, or fewer than 2% of non-blank lines
# matching the cisco_heads vocabulary) never fires on a deliberately tiny,
# single-purpose inline fixture. Every line here is an unconditional, content-neutral IOS
# line that cannot affect any assertion below (in particular: no `hostname` line, so
# test_04b's "hostname absent" case still holds).
_PAD = "version 17.9\nservice timestamps log datetime msec\nno ip domain-lookup\n!\n"


def _parse(text: str, **kwargs):
    parser = require_module_or_fail("ciscocheck.parser")
    return parser.parse(_PAD + text, **kwargs)


def _make_entry(model, **overrides):
    """Build a minimal, schema-conformant `CatalogueEntry` for exercising `Context.finding()`
    without a real `data/catalogue.json` or engine."""
    from ciscocheck.model import Ref  # noqa: F401  (imported for type clarity in overrides)

    fields = dict(
        id="CSC-TEST-0001",
        title="Test entry for conformance checking",
        severity="high",
        category="security",
        confidence="heuristic",
        platforms=("ios", "iosxe"),
        profiles=("campus", "stig"),
        test_kind="present",
        defaults_key=None,
        subject=("test subject",),
        rationale="Independently written test rationale.",
        remediation_intent=None,
        remediation=("no test {interface}",),
        params_required=("interface",),
        severity_by_profile={},
        severity_allowed_overrides=(),
        refs=(model.Ref(authority="Cisco", id="TEST-0001", version=None, url=None),),
        min_release=None,
        notes=None,
    )
    fields.update(overrides)
    return model.CatalogueEntry(**fields)


def _make_context(model, defaults, dialect, refs, *, entry=None, role_map=None, profile="campus"):
    return model.Context(
        platform="iosxe",
        platform_source="given",
        profile=profile,
        role_map=role_map or {},
        defaults=defaults,
        dialect=dialect,
        refs_index=refs,
        entry=entry if entry is not None else _make_entry(model),
        skill_version="0.0.0-test",
        catalogue_version="0000.00-test",
    )


def _empty_tables():
    defaults_mod = require_module_or_fail("ciscocheck.defaults")
    dialect_mod = require_module_or_fail("ciscocheck.dialect")
    refs_mod = require_module_or_fail("ciscocheck.refs")
    defaults = defaults_mod.DefaultsTable.load(None, dialect_mod.DialectTable.load(None))
    dialect = dialect_mod.DialectTable.load(None)
    refs = refs_mod.ReferenceIndex()
    return defaults, dialect, refs


# ---------------------------------------------------------------------------------------
# 1. Config.find("no such command") returns (), not None; type is tuple.
# ---------------------------------------------------------------------------------------


def test_01_find_absent_returns_empty_tuple():
    cfg = _parse("hostname CONFORM01\n!\nend\n")
    result = cfg.find("no such command")
    assert isinstance(result, tuple)
    assert result == ()


# ---------------------------------------------------------------------------------------
# 2. find(scope=node) searches the subtree at every depth and excludes the node itself.
# ---------------------------------------------------------------------------------------


def test_02_find_scope_searches_subtree_excludes_self():
    cfg = _parse(
        "hostname CONFORM02\n"
        "!\n"
        "interface GigabitEthernet1/0/1\n"
        " switchport mode access\n"
        " switchport access vlan 10\n"
        "!\n"
        "end\n"
    )
    iface_node = cfg.find_one("interface GigabitEthernet1/0/1")
    assert iface_node is not None
    # The node's own line must not be returned by a scoped search of itself.
    self_hits = cfg.find("interface GigabitEthernet1/0/1", scope=iface_node)
    assert iface_node not in self_hits
    # A child several levels down (its direct child here) must be found.
    child_hits = cfg.find("switchport access vlan 10", scope=iface_node)
    assert len(child_hits) == 1


# ---------------------------------------------------------------------------------------
# 3. children_of(node) returns direct children only; children_of(node, recurse=True)
#    returns the whole subtree.
# ---------------------------------------------------------------------------------------


def test_03_children_of_recurse():
    # Deliberately no `exit-af-interface` / `exit-address-family` lines: those render at the
    # SAME indent as `address-family`/`af-interface` in real IOS output, which correctly
    # makes them siblings (not children) under indent-stack parsing ("structural parse") --
    # exercising that is test_parser_structure.py's job, not this children_of()/recurse
    # test's. Here we want an unambiguous, strictly-nested tree.
    cfg = _parse(
        "hostname CONFORM03\n"
        "!\n"
        "router eigrp CONFORM\n"
        " address-family ipv4 unicast autonomous-system 1\n"
        "  af-interface default\n"
        "   authentication mode hmac-sha-256 0 placeholder\n"
        "!\n"
        "end\n"
    )
    router_node = cfg.find_one("router eigrp CONFORM")
    assert router_node is not None
    direct = cfg.children_of(router_node)
    assert len(direct) == 1  # only the address-family node directly
    deep = cfg.children_of(router_node, recurse=True)
    assert len(deep) > len(direct)


# ---------------------------------------------------------------------------------------
# 4. find_one / value_of / interface / hostname return None when absent.
# ---------------------------------------------------------------------------------------


def test_04_absent_lookups_return_none():
    cfg = _parse("hostname CONFORM04\n!\nend\n")
    assert cfg.find_one("no such command") is None
    assert cfg.value_of(r"no-such-key (\S+)") is None
    assert cfg.interface("GigabitEthernet9/9/9") is None


def test_04b_hostname_present_and_absent():
    cfg = _parse("hostname CONFORM04B\n!\nend\n")
    assert cfg.hostname() == "CONFORM04B"
    cfg_no_hostname = _parse("interface Loopback0\n no ip address\n!\nend\n")
    assert cfg_no_hostname.hostname() is None


# ---------------------------------------------------------------------------------------
# 5. interfaces() expands a 24-member range into 24 records, each from_range=True with
#    evidence_line equal to the range line; a member with its own block appears once.
# ---------------------------------------------------------------------------------------


def test_05_interface_range_expansion_pure():
    """A 24-member range with no overlapping standalone block: 24 records, every one
    from_range=True, every one's evidence_line equal to the range line."""
    cfg = _parse(
        "hostname CONFORM05\n"
        "!\n"
        "interface range GigabitEthernet1/0/1 - 24\n"
        " switchport mode access\n"
        " switchport access vlan 10\n"
        "!\n"
        "end\n"
    )
    ifaces = cfg.interfaces()
    range_members = [i for i in ifaces if i.from_range]
    assert len(range_members) == 24
    range_line = cfg.find_one("interface range GigabitEthernet1/0/1 - 24").line
    for member in range_members:
        assert member.evidence_line == range_line


def test_05b_interface_range_member_with_own_block_appears_once():
    """A member that also has its own standalone block appears exactly once overall (the
    dedup half of the interfaces()/range rule)."""
    cfg = _parse(
        "hostname CONFORM05B\n"
        "!\n"
        "interface range GigabitEthernet1/0/1 - 4\n"
        " switchport mode access\n"
        " switchport access vlan 10\n"
        "!\n"
        "interface GigabitEthernet1/0/2\n"
        " description standalone override\n"
        "!\n"
        "end\n"
    )
    ifaces = cfg.interfaces()
    total_1_to_4 = [i for i in ifaces if i.name in (
        "GigabitEthernet1/0/1", "GigabitEthernet1/0/2",
        "GigabitEthernet1/0/3", "GigabitEthernet1/0/4",
    )]
    assert len(total_1_to_4) == 4, f"expected exactly 4 unique members, got {[i.name for i in total_1_to_4]}"
    named = [i for i in ifaces if i.name == "GigabitEthernet1/0/2"]
    assert len(named) == 1
    # The standalone block's own description must be visible from the merged record's node.
    assert "description standalone override" in named[0].node.line.text or any(
        "description standalone override" in child.line.text for child in named[0].node.children
    )


# ---------------------------------------------------------------------------------------
# 6. interfaces(role="unused") filters on the resolved role.
# ---------------------------------------------------------------------------------------


def test_06_interfaces_filter_by_resolved_role():
    cfg = _parse(
        "hostname CONFORM06\n"
        "!\n"
        "interface GigabitEthernet1/0/1\n"
        " shutdown\n"
        "!\n"
        "interface GigabitEthernet1/0/2\n"
        " switchport mode access\n"
        " switchport access vlan 10\n"
        "!\n"
        "end\n"
    )
    unused = cfg.interfaces(role="unused")
    assert all(i.role == "unused" for i in unused)
    assert any(i.name == "GigabitEthernet1/0/1" for i in unused)
    assert not any(i.name == "GigabitEthernet1/0/2" for i in unused)


# ---------------------------------------------------------------------------------------
# 7. line_ranges("vty") over a config showing only `line vty 0 4` returns two ranges, the
#    second with observed=False and node=None.
# ---------------------------------------------------------------------------------------


def test_07_line_ranges_full_universe():
    cfg = _parse(
        "hostname CONFORM07\n"
        "!\n"
        "line vty 0 4\n"
        " transport input ssh\n"
        "!\n"
        "end\n"
    )
    ranges = cfg.line_ranges("vty")
    assert len(ranges) == 2
    observed = [r for r in ranges if r.observed]
    assumed = [r for r in ranges if not r.observed]
    assert len(observed) == 1
    assert len(assumed) == 1
    assert assumed[0].node is None


# ---------------------------------------------------------------------------------------
# 8. Context exposes every field named in section 3.2 with the stated types.
# ---------------------------------------------------------------------------------------


def test_08_context_exposes_every_field():
    model = require_module_or_fail("ciscocheck.model")
    defaults, dialect, refs = _empty_tables()
    ctx = _make_context(model, defaults, dialect, refs)
    for field_name in (
        "platform", "platform_source", "profile", "role_map", "defaults", "dialect",
        "refs_index", "entry", "skill_version", "catalogue_version",
    ):
        assert hasattr(ctx, field_name), f"Context missing field {field_name!r}"
    assert ctx.platform == "iosxe"
    assert ctx.platform_source == "given"
    assert ctx.profile == "campus"
    assert isinstance(ctx.role_map, dict)
    assert ctx.skill_version == "0.0.0-test"
    assert ctx.catalogue_version == "0000.00-test"


# ---------------------------------------------------------------------------------------
# 9. ctx.finding(masked=True) raises TypeError; so does each other refused kwarg.
# ---------------------------------------------------------------------------------------


REFUSED_KWARGS = ("masked", "redactions", "evidence", "check_id", "title", "rationale",
                   "refs", "confidence", "catalogue_confidence")


@pytest.mark.parametrize("kwarg", REFUSED_KWARGS)
def test_09_finding_refuses_forbidden_kwargs(kwarg):
    model = require_module_or_fail("ciscocheck.model")
    defaults, dialect, refs = _empty_tables()
    ctx = _make_context(model, defaults, dialect, refs)
    with pytest.raises(TypeError):
        ctx.finding(**{kwarg: object()})


# ---------------------------------------------------------------------------------------
# 10. ctx.finding(line=L) computes masked and redactions from L.redactions.
# ---------------------------------------------------------------------------------------


def test_10_finding_computes_masked_and_redactions_from_line():
    model = require_module_or_fail("ciscocheck.model")
    defaults, dialect, refs = _empty_tables()
    ctx = _make_context(model, defaults, dialect, refs)

    cfg_clean = _parse("hostname CONFORM10\n!\nend\n")
    clean_line = cfg_clean.find_one("hostname CONFORM10").line
    finding_clean = ctx.finding(line=clean_line)
    assert finding_clean.evidence.masked is False
    assert finding_clean.evidence.redactions == 0

    cfg_secret = _parse(
        "hostname CONFORM10\n!\ntacacs-server key 7 CANARY-CONFORM10-01\n!\nend\n"
    )
    secret_line = cfg_secret.find_one("tacacs-server key", regex=False)
    assert secret_line is not None
    line_obj = secret_line.line
    assert len(line_obj.redactions) >= 1, "expected the canary line to carry a Redaction"
    finding_secret = ctx.finding(line=line_obj)
    assert finding_secret.evidence.masked is True
    assert finding_secret.evidence.redactions == len(line_obj.redactions)


def test_10b_finding_absence_shape():
    model = require_module_or_fail("ciscocheck.model")
    defaults, dialect, refs = _empty_tables()
    ctx = _make_context(model, defaults, dialect, refs)
    finding = ctx.finding(line=None)
    assert finding.evidence.line_no is None
    assert finding.evidence.source_line_no is None
    assert finding.evidence.text == ""
    assert finding.evidence.masked is False
    assert finding.evidence.redactions == 0
    assert finding.evidence.anchor == "absent"


# ---------------------------------------------------------------------------------------
# 11. ctx.finding() with a template variable the rule did not supply renders <TODO:name>
#     and does not raise.
# ---------------------------------------------------------------------------------------


def test_11_unsupplied_template_variable_renders_todo():
    model = require_module_or_fail("ciscocheck.model")
    defaults, dialect, refs = _empty_tables()
    entry = _make_entry(
        model,
        remediation=("no ip address on {interface}",),
        params_required=("interface",),
    )
    ctx = _make_context(model, defaults, dialect, refs, entry=entry)
    finding = ctx.finding(params={})  # `interface` deliberately not supplied
    assert any("<TODO:interface>" in line for line in finding.remediation), finding.remediation


# ---------------------------------------------------------------------------------------
# 12. ctx.finding(role_source="role-map") on a heuristic entry yields
#     confidence == "deterministic" and catalogue_confidence == "heuristic".
# ---------------------------------------------------------------------------------------


def test_12_role_map_promotes_heuristic_to_deterministic():
    model = require_module_or_fail("ciscocheck.model")
    defaults, dialect, refs = _empty_tables()
    entry = _make_entry(model, confidence="heuristic")
    ctx = _make_context(model, defaults, dialect, refs, entry=entry)

    promoted = ctx.finding(role_source="role-map")
    assert promoted.confidence == "deterministic"
    assert promoted.catalogue_confidence == "heuristic"

    not_promoted = ctx.finding(role_source="inferred-access")
    assert not_promoted.confidence == "heuristic"
    assert not_promoted.catalogue_confidence == "heuristic"


# ---------------------------------------------------------------------------------------
# 13. No object in model.py has a field named raw, plaintext, cleartext, secret, password,
#     unmasked or digests (reflection over __dataclass_fields__).
# ---------------------------------------------------------------------------------------


FORBIDDEN_FIELD_NAMES = frozenset(
    {"raw", "plaintext", "cleartext", "secret", "password", "unmasked", "digests"}
)


def test_13_no_forbidden_field_names_anywhere_in_model():
    import dataclasses
    import inspect

    model = require_module_or_fail("ciscocheck.model")
    checked_any = False
    for _name, obj in vars(model).items():
        if inspect.isclass(obj) and dataclasses.is_dataclass(obj):
            checked_any = True
            field_names = {f.name for f in dataclasses.fields(obj)}
            offending = field_names & FORBIDDEN_FIELD_NAMES
            assert not offending, (
                f"{obj.__name__} carries forbidden field name(s): {sorted(offending)}"
            )
    assert checked_any, "no dataclasses found in ciscocheck.model -- nothing was actually checked"
