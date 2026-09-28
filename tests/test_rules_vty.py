"""Tests for ciscocheck.rules.vty (VTY family, 11 checks)."""
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
    "CSC-VTY-0001": ("line vty 0 15\n transport input telnet\n",
                     "line vty 0 15\n transport input ssh\n"),
    "CSC-VTY-0002": ("line vty 0 15\n transport input ssh\n",
                     "line vty 0 15\n transport input ssh\n access-class MGMT in\n"),
    "CSC-VTY-0003": ("line vty 0 15\n access-class UNDEF-ACL in\n",
                     "ip access-list standard MGMT\n permit any\n"
                     "line vty 0 15\n access-class MGMT in\n"),
    "CSC-VTY-0004": ("line vty 0 15\n exec-timeout 0 0\n",
                     "line vty 0 15\n exec-timeout 10 0\n"),
    "CSC-VTY-0005": ("line vty 0 15\n password 7 CANARYPW\n",
                     "line vty 0 15\n login authentication default\n"),
    "CSC-VTY-0006": ("line aux 0\n", "line aux 0\n no exec\n transport input none\n"),
    "CSC-VTY-0007": ("line con 0\n", "line con 0\n exec-timeout 10 0\n logging synchronous\n"),
    "CSC-VTY-0008": ("line vty 0 15\n transport output telnet\n",
                     "line vty 0 15\n transport output ssh\n"),
    "CSC-VTY-0009": ("", "login block-for 120 attempts 5 within 60\n"),
    "CSC-VTY-0010": ("", "banner login ^CAuthorized use only^C\n"),
    "CSC-VTY-0011": ("banner login ^CHello^C\n",
                     "banner login ^CAuthorized users only. All activity is monitored and "
                     "unauthorized use will be prosecuted. You consent by continuing.^C\n"),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-VTY-")}


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


def test_vty0001_evidence_shows_transport_line():
    findings = _fire("CSC-VTY-0001", "line vty 0 15\n transport input telnet\n")
    assert any("transport input telnet" in f.evidence.text for f in findings)


def test_module_ids_exist_in_catalogue():
    for check_id, _ in registry.rules():
        if check_id.startswith("CSC-VTY-"):
            assert CATALOGUE.get(check_id) is not None


# ---------------------------------------------------------------------------------------
# Regression repros
# ---------------------------------------------------------------------------------------


def test_transport_input_none_is_compliant():
    findings = _fire("CSC-VTY-0001", "line vty 0 15\n transport input none\n")
    assert not findings


def test_transport_output_none_is_compliant():
    findings = _fire("CSC-VTY-0008", "line vty 0 15\n transport output none\n")
    assert not findings


def test_outbound_only_access_class_does_not_restrict_inbound():
    findings = _fire("CSC-VTY-0002",
                     "ip access-list standard MGMT\n permit any\n"
                     "line vty 0 15\n access-class MGMT out\n")
    assert findings


def test_ipv6_only_access_class_does_not_restrict_ipv4():
    findings = _fire("CSC-VTY-0002",
                     "ipv6 access-list V6ACL\n permit any any\n"
                     "line vty 0 15\n access-class ipv6 V6ACL in\n")
    assert findings


def test_inbound_access_class_with_vrf_also_restricts():
    """`access-class MGMT in vrf-also` is valid IOS syntax and does restrict inbound access --
    the trailing `vrf-also` keyword must not be mistaken for the direction token."""
    findings = _fire("CSC-VTY-0002",
                     "ip access-list standard MGMT\n permit any\n"
                     "line vty 0 15\n access-class MGMT in vrf-also\n")
    assert not findings


def test_outbound_access_class_with_vrf_also_does_not_restrict():
    findings = _fire("CSC-VTY-0002",
                     "ip access-list standard MGMT\n permit any\n"
                     "line vty 0 15\n access-class MGMT out vrf-also\n")
    assert findings


def test_con0_local_password_fires():
    findings = _fire("CSC-VTY-0005", "line con 0\n password 7 FAKEPW01\n")
    assert findings


def test_unfilled_access_class_placeholder_still_fires():
    findings = _fire("CSC-VTY-0002", "line vty 0 15\n access-class <REPLACE-ME:acl-name> in\n")
    assert findings
