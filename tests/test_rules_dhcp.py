"""Tests for ciscocheck.rules.dhcp (DHCP family, 9 checks)."""
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
    "CSC-DHCP-0001": ("", "ip dhcp snooping\n"),
    "CSC-DHCP-0002": ("ip dhcp snooping\n", "ip dhcp snooping\nip dhcp snooping vlan 10\n"),
    "CSC-DHCP-0003": ("ip dhcp snooping\nip dhcp snooping vlan 20\n"
                      "interface GigabitEthernet1/0/1\n switchport mode access\n"
                      " switchport access vlan 10\n",
                      "ip dhcp snooping\nip dhcp snooping vlan 10\n"
                      "interface GigabitEthernet1/0/1\n switchport mode access\n"
                      " switchport access vlan 10\n"),
    "CSC-DHCP-0004": ("ip dhcp snooping\ninterface TenGigabitEthernet1/1/1\n"
                      " description UPLINK-TO-CORE\n switchport mode trunk\n",
                      "ip dhcp snooping\ninterface TenGigabitEthernet1/1/1\n"
                      " description UPLINK-TO-CORE\n switchport mode trunk\n"
                      " ip dhcp snooping trust\n"),
    "CSC-DHCP-0005": ("ip dhcp snooping\ninterface GigabitEthernet1/0/1\n"
                      " switchport mode access\n switchport access vlan 10\n",
                      "ip dhcp snooping\ninterface GigabitEthernet1/0/1\n"
                      " switchport mode access\n switchport access vlan 10\n"
                      " ip dhcp snooping limit rate 15\n"),
    "CSC-DHCP-0006": ("", "ip dhcp snooping database flash:dhcp-snooping.db\n"),
    "CSC-DHCP-0007": ("", "no ip dhcp snooping information option\n"),
    "CSC-DHCP-0008": ("ip dhcp snooping vlan 10\nip arp inspection vlan 20\n",
                      "ip dhcp snooping vlan 10\nip arp inspection vlan 10\n"),
    "CSC-DHCP-0009": ("", "ip arp inspection validate src-mac dst-mac ip\n"),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-DHCP-")}


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


def test_module_ids_exist_in_catalogue():
    for check_id, _ in registry.rules():
        if check_id.startswith("CSC-DHCP-"):
            assert CATALOGUE.get(check_id) is not None


# ---------------------------------------------------------------------------------------
# Regression repros (rule half; the value_slots() half is defaults.py)
# ---------------------------------------------------------------------------------------


def test_vlan_subcommand_alone_is_not_global_enable():
    """A `ip dhcp snooping vlan 10` sub-command with no exact global line must still read as
    globally disabled -- the false-negative half of this check."""
    findings = _fire("CSC-DHCP-0001", "ip dhcp snooping vlan 10\n")
    assert findings


def test_database_subcommand_alone_is_not_global_enable():
    findings = _fire("CSC-DHCP-0001", "ip dhcp snooping database flash:x\n")
    assert findings


def test_exact_global_with_subcommands_is_not_overridden():
    """The false-positive half of this check: a later `no ip dhcp snooping information
    option` sub-command must not read back as disabling the earlier exact global enable."""
    findings = _fire(
        "CSC-DHCP-0001",
        "ip dhcp snooping\nip dhcp snooping vlan 10\nno ip dhcp snooping information option\n",
    )
    assert not findings
