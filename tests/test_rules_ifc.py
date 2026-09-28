"""Tests for ciscocheck.rules.ifc (IFC family, 8 checks)."""
from __future__ import annotations

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
    "CSC-IFC-0001": ("interface GigabitEthernet1/0/1\n switchport mode access\n"
                     " switchport access vlan 10\n speed 100\n",
                     "interface GigabitEthernet1/0/1\n switchport mode access\n"
                     " switchport access vlan 10\n speed auto\n duplex auto\n"),
    "CSC-IFC-0002": ("interface TenGigabitEthernet1/1/1\n switchport mode trunk\n",
                     "interface TenGigabitEthernet1/1/1\n switchport mode trunk\n"
                     " description uplink to core\n"),
    "CSC-IFC-0003": ("interface Vlan10\n ip address 192.0.2.1 255.255.255.0\n",
                     "interface Vlan10\n ip address 192.0.2.1 255.255.255.0\n no ip proxy-arp\n"),
    "CSC-IFC-0004": ("interface Vlan10\n ip address 192.0.2.1 255.255.255.0\n",
                     "interface Vlan10\n ip address 192.0.2.1 255.255.255.0\n"
                     " no ip redirects\n no ip unreachables\n"),
    "CSC-IFC-0005": ("interface Vlan10\n ip address 192.0.2.1 255.255.255.0\n"
                     " ip directed-broadcast\n",
                     "interface Vlan10\n ip address 192.0.2.1 255.255.255.0\n"),
    "CSC-IFC-0006": ("interface Vlan10\n ip address 192.0.2.1 255.255.255.0\n",
                     "interface Vlan10\n ip address 192.0.2.1 255.255.255.0\n"
                     " ip verify unicast source reachable-via rx\n"),
    "CSC-IFC-0007": ("", "no cdp run\n"),
    "CSC-IFC-0008": ("interface GigabitEthernet1/0/1\n switchport voice vlan 20\n no cdp run\n",
                     "interface GigabitEthernet1/0/1\n switchport voice vlan 20\n"),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-IFC-")}


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


def test_ifc0007_and_ifc0008_are_mutually_exclusive():
    voice = "interface GigabitEthernet1/0/1\n switchport voice vlan 20\n"
    assert not _fire("CSC-IFC-0007", voice)
    assert not _fire("CSC-IFC-0008", "")


def test_module_ids_exist_in_catalogue():
    for check_id, _ in registry.rules():
        if check_id.startswith("CSC-IFC-"):
            assert CATALOGUE.get(check_id) is not None
