"""Tests for ciscocheck.rules.l2 (L2 family, 14 checks)."""
from __future__ import annotations

import re

import pytest

from ciscocheck import registry
from ciscocheck.model import Catalogue, Context
from ciscocheck.parser import parse
import ciscocheck.rules  # noqa: F401

CATALOGUE = Catalogue.load()
BASE = "hostname TESTSW\ninterface Loopback0\n ip address 198.51.100.1 255.255.255.255\n"

_FAMILY_MODULES = ("mgt", "aaa", "vty", "snmp", "log", "ntp", "ssh", "stp", "l2", "dhcp", "ifc", "res")


@pytest.fixture(autouse=True)
def _ensure_rules_registered():
    """Defensive against another test module's `registry.clear()` (DESIGN r1 N11): see
    tests/test_rules_mgt.py for the full explanation."""
    import ciscocheck.rules  # noqa: F401  (ensures the submodules are in sys.modules)
    if registry.lookup("CSC-MGT-0001") is None:
        import importlib
        import sys
        for name in _FAMILY_MODULES:
            importlib.reload(sys.modules[f"ciscocheck.rules.{name}"])
    yield


def _ctx(check_id, cfg, *, profile="campus"):
    entry = CATALOGUE.get(check_id)
    assert entry is not None, f"{check_id} missing from data/catalogue.json"
    return Context(platform=cfg.platform, platform_source=cfg.platform_source, profile=profile,
                   role_map=cfg.role_map, defaults=cfg.defaults, dialect=cfg.dialect,
                   refs_index=cfg.refs, entry=entry, skill_version="test",
                   catalogue_version=CATALOGUE.catalogue_version)


def _fire(check_id, extra, *, platform="iosxe", role_map=None):
    cfg = parse(BASE + extra, platform=platform, role_map=role_map)
    fn = registry.lookup(check_id)
    assert fn is not None, f"{check_id} has no registered rule or extractor"
    return list(fn(cfg, _ctx(check_id, cfg)))


CASES = {
    "CSC-L2-0001": ("interface TenGigabitEthernet1/1/1\n switchport mode trunk\n",
                    "interface TenGigabitEthernet1/1/1\n switchport mode trunk\n"
                    " switchport trunk native vlan 99\n"),
    "CSC-L2-0002": ("interface GigabitEthernet1/0/1\n switchport mode access\n"
                    " switchport access vlan 10\n"
                    "interface TenGigabitEthernet1/1/1\n switchport mode trunk\n"
                    " switchport trunk native vlan 10\n",
                    "interface GigabitEthernet1/0/1\n switchport mode access\n"
                    " switchport access vlan 10\n"
                    "interface TenGigabitEthernet1/1/1\n switchport mode trunk\n"
                    " switchport trunk native vlan 99\n"),
    "CSC-L2-0003": ("interface GigabitEthernet1/0/1\n switchport access vlan 1\n",
                    "interface GigabitEthernet1/0/1\n switchport access vlan 10\n"),
    "CSC-L2-0004": ("interface Vlan1\n ip address 192.0.2.1 255.255.255.0\n",
                    "interface Vlan1\n shutdown\n no ip address\n"),
    "CSC-L2-0005": ("interface TenGigabitEthernet1/1/1\n switchport mode trunk\n"
                    " switchport trunk allowed vlan all\n",
                    "interface TenGigabitEthernet1/1/1\n switchport mode trunk\n"
                    " switchport trunk allowed vlan 10,20\n"),
    "CSC-L2-0006": ("interface TenGigabitEthernet1/1/1\n switchport mode trunk\n",
                    "interface TenGigabitEthernet1/1/1\n switchport mode trunk\n"
                    " switchport nonegotiate\n"),
    "CSC-L2-0007": ("interface GigabitEthernet1/0/1\n switchport access vlan 10\n",
                    "interface GigabitEthernet1/0/1\n switchport mode access\n"
                    " switchport access vlan 10\n"),
    "CSC-L2-0008": ("interface GigabitEthernet1/0/3\n", "interface GigabitEthernet1/0/3\n shutdown\n"),
    "CSC-L2-0009": ("interface GigabitEthernet1/0/3\n shutdown\n switchport access vlan 1\n",
                    "interface GigabitEthernet1/0/3\n shutdown\n switchport access vlan 999\n"),
    "CSC-L2-0010": ("interface GigabitEthernet1/0/1\n switchport mode access\n"
                    " switchport access vlan 10\n",
                    "interface GigabitEthernet1/0/1\n switchport mode access\n"
                    " switchport access vlan 10\n switchport port-security\n"),
    "CSC-L2-0011": ("interface GigabitEthernet1/0/1\n switchport port-security\n"
                    " switchport port-security maximum 10\n",
                    "interface GigabitEthernet1/0/1\n switchport port-security\n"
                    " switchport port-security maximum 2\n"
                    " switchport port-security violation restrict\n"),
    "CSC-L2-0012": ("interface GigabitEthernet1/0/1\n switchport mode access\n"
                    " switchport access vlan 10\n",
                    "interface GigabitEthernet1/0/1\n switchport mode access\n"
                    " switchport access vlan 10\n storm-control broadcast level 20.00\n"),
    "CSC-L2-0013": ("vtp mode server\n", "vtp mode transparent\n"),
    "CSC-L2-0014": ("vtp domain CORP\n", "vtp domain CORP\nvtp password CANARYPW\n"),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-L2-")}


@pytest.mark.parametrize("check_id", sorted(CASES))
def test_must_fire(check_id):
    fire_text, _ = CASES[check_id]
    findings = _fire(check_id, fire_text)
    assert findings, f"{check_id} expected to fire on {fire_text!r}"
    assert all(f.check_id == check_id for f in findings)


@pytest.mark.parametrize("check_id", sorted(CASES))
def test_must_not_fire(check_id):
    _, no_fire_text = CASES[check_id]
    findings = _fire(check_id, no_fire_text)
    assert not findings, f"{check_id} unexpectedly fired on {no_fire_text!r}: {findings}"


def test_l2_0009_excludes_svis():
    """L2-0009 is about physical unused ports; a shut, address-less SVI is not one."""
    findings = _fire("CSC-L2-0009", "interface Vlan1\n shutdown\n no ip address\n")
    assert not findings


# CSC-L2-0002 (native VLAN collides with an access VLAN), CSC-L2-0003 (access port on
# VLAN 1) and CSC-L2-0009 (unused port parked on VLAN 1 or a live VLAN) all fire *because*
# a VLAN is already at a bad value. The engine cannot know a genuinely unused VLAN from the
# config alone, so the fix must never restate that bad value (and must never say `vlan 1`,
# the single worst possible destination): it must hand the operator an explicit
# `<REPLACE-ME:...>` placeholder to fill in, the same convention CSC-L2-0001 already uses.
_VLAN_1_DESTINATION_RE = re.compile(r"\bvlan 1\b", re.IGNORECASE)


@pytest.mark.parametrize("check_id", ("CSC-L2-0002", "CSC-L2-0003", "CSC-L2-0009"))
def test_vlan_destination_checks_never_suggest_vlan_1(check_id):
    fire_text, _ = CASES[check_id]
    findings = _fire(check_id, fire_text)
    assert findings, f"{check_id} expected to fire on {fire_text!r}"
    for f in findings:
        rendered = "\n".join(f.remediation)
        assert not _VLAN_1_DESTINATION_RE.search(rendered), (
            f"{check_id} remediation suggests VLAN 1 as a destination: {f.remediation!r}")
        assert "<REPLACE-ME:vlan-id>" in rendered, (
            f"{check_id} remediation should carry an explicit vlan placeholder: "
            f"{f.remediation!r}")


@pytest.mark.parametrize("check_id", ("CSC-L2-0002", "CSC-L2-0003", "CSC-L2-0009"))
def test_vlan_destination_checks_never_echo_the_observed_vlan(check_id):
    """Regression guard: these checks must never bind `vlan` to the VLAN they just flagged
    as bad (the original bug -- see CHANGELOG). Firing against a config whose offending
    VLAN is a distinctive, non-1 number still must not leak that number into the fix."""
    fire_text = {
        "CSC-L2-0002": ("interface GigabitEthernet1/0/1\n switchport mode access\n"
                        " switchport access vlan 77\n"
                        "interface TenGigabitEthernet1/1/1\n switchport mode trunk\n"
                        " switchport trunk native vlan 77\n"),
        "CSC-L2-0003": "interface GigabitEthernet1/0/1\n switchport access vlan 1\n",
        "CSC-L2-0009": "interface GigabitEthernet1/0/3\n shutdown\n switchport access vlan 1\n",
    }[check_id]
    findings = _fire(check_id, fire_text)
    assert findings, f"{check_id} expected to fire on {fire_text!r}"
    for f in findings:
        assert f.params.get("vlan") == "<REPLACE-ME:vlan-id>", (
            f"{check_id} bound `vlan` to {f.params.get('vlan')!r} instead of a placeholder")
        assert "vlan 77" not in "\n".join(f.remediation)


def test_module_ids_exist_in_catalogue():
    for check_id, _ in registry.rules():
        if check_id.startswith("CSC-L2-"):
            assert CATALOGUE.get(check_id) is not None
