"""Tests for ciscocheck.rules.stp (STP family, 10 checks)."""
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
    """Defensive against another test module's `registry.clear()`: see
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
    "CSC-STP-0001": ("spanning-tree mode pvst\n", "spanning-tree mode rapid-pvst\n"),
    "CSC-STP-0002": ("interface GigabitEthernet1/0/1\n switchport mode access\n"
                     " switchport access vlan 10\n",
                     "interface GigabitEthernet1/0/1\n switchport mode access\n"
                     " switchport access vlan 10\n spanning-tree portfast edge\n"),
    "CSC-STP-0003": ("", "spanning-tree portfast edge bpduguard default\n"),
    "CSC-STP-0004": ("interface GigabitEthernet1/0/1\n switchport mode access\n"
                     " switchport access vlan 10\n",
                     "spanning-tree portfast edge bpduguard default\n"
                     "interface GigabitEthernet1/0/1\n switchport mode access\n"
                     " switchport access vlan 10\n"),
    "CSC-STP-0005": ("interface GigabitEthernet1/0/24\n switchport mode trunk\n"
                     "interface GigabitEthernet1/0/25\n switchport mode trunk\n",
                     "interface GigabitEthernet1/0/24\n switchport mode trunk\n"
                     " spanning-tree guard root\n"
                     "interface GigabitEthernet1/0/25\n switchport mode trunk\n"
                     " spanning-tree guard root\n"),
    "CSC-STP-0006": ("", "spanning-tree loopguard default\n"),
    "CSC-STP-0007": ("spanning-tree bpdufilter default\n", ""),
    "CSC-STP-0008": ("vlan 10\n", "vlan 10\nspanning-tree vlan 10 priority 4096\n"),
    "CSC-STP-0009": ("spanning-tree vlan 10 priority 4096\n", ""),
    "CSC-STP-0010": ("", "udld enable\n"),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-STP-")}


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


def test_root_guard_excludes_a_single_uplink():
    """A switch with exactly one trunk/uplink-role interface is not asked to Root Guard its
    own sole path to the root (STP-0005's topology half)."""
    findings = _fire("CSC-STP-0005",
                     "interface TenGigabitEthernet1/1/1\n description UPLINK-TO-CORE\n"
                     " switchport mode trunk\n")
    assert not findings


def test_multiple_downlinks_described_to_a_neighbour_still_require_root_guard():
    """F15: a distribution switch with several downstream trunks -- each description
    matching the parser's generic uplink-by-description heuristic ("... to ACC-SW-0N") --
    must still be flagged when none of them has Root Guard. With >1 candidate, STP-0005 no
    longer trusts role alone and checks every one."""
    cfg_text = "".join(
        f"interface TenGigabitEthernet1/1/{n}\n description downlink to ACC-SW-0{n}\n"
        f" switchport mode trunk\n"
        for n in range(1, 7)
    )
    findings = _fire("CSC-STP-0005", cfg_text)
    assert len(findings) == 6


def test_global_portfast_bpdufilter_default_forms():
    """F7: both switch-wide default spellings must fire, not only the bare
    `spanning-tree bpdufilter ...` prefix."""
    assert _fire("CSC-STP-0007", "spanning-tree portfast bpdufilter default\n")
    assert _fire("CSC-STP-0007", "spanning-tree portfast edge bpdufilter default\n")


def test_stp0008_mst_priority_covers_every_vlan():
    findings = _fire("CSC-STP-0008", "vlan 10\nspanning-tree mst 0 priority 4096\n")
    assert not findings


def test_module_ids_exist_in_catalogue():
    for check_id, _ in registry.rules():
        if check_id.startswith("CSC-STP-"):
            assert CATALOGUE.get(check_id) is not None
    for check_id, _ in registry.extractors():
        if check_id.startswith("CSC-STP-"):
            assert CATALOGUE.get(check_id) is not None
