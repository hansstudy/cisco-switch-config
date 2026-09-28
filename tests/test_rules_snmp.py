"""Tests for ciscocheck.rules.snmp (SNMP family, 10 checks)."""
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
    "CSC-SNMP-0001": ("snmp-server community CANARYCOMM RO 99\n", ""),
    "CSC-SNMP-0002": ("snmp-server community CANARYCOMM RW\n", "snmp-server community CANARYCOMM RO\n"),
    "CSC-SNMP-0003": ("snmp-server community public RO\n", "snmp-server community CANARYCOMM RO\n"),
    "CSC-SNMP-0004": ("snmp-server community CANARYCOMM RO\n", "snmp-server community CANARYCOMM RO 99\n"),
    "CSC-SNMP-0005": ("snmp-server community CANARYCOMM RO UNDEF-ACL\n",
                     "ip access-list standard MGMT\n permit any\n"
                     "snmp-server community CANARYCOMM RO MGMT\n"),
    "CSC-SNMP-0006": ("snmp-server group MYGRP v3 auth\n", "snmp-server group MYGRP v3 priv\n"),
    "CSC-SNMP-0007": ("snmp-server host 192.0.2.1 version 2c CANARYCOMM\n",
                     "snmp-server host 192.0.2.1 version 3 priv MYUSER\n"),
    "CSC-SNMP-0008": ("", "snmp-server enable traps snmp linkup linkdown\n"
                     "snmp-server enable traps config\nsnmp-server enable traps aaa server\n"),
    "CSC-SNMP-0009": ("", "snmp ifmib ifindex persist\n"),
    "CSC-SNMP-0010": ("snmp-server group MYGRP v3 priv\n", ""),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-SNMP-")}


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


def test_snmp0003_never_reads_the_raw_value():
    """CSC-SNMP-0003 must decide from `Redaction.cls`, never from evidence text."""
    findings = _fire("CSC-SNMP-0003", "snmp-server community public RO\n")
    assert findings and "public" not in findings[0].evidence.text
    assert "[REDACTED" in findings[0].evidence.text


# ---------------------------------------------------------------------------------------
# Regression repros
# ---------------------------------------------------------------------------------------


def test_ipv6_only_acl_does_not_restrict_ipv4_community():
    findings = _fire("CSC-SNMP-0004", "snmp-server community FAKECOMM RO ipv6 V6ACL\n")
    assert findings


def test_unfilled_community_acl_placeholder_still_fires():
    findings = _fire("CSC-SNMP-0004", "snmp-server community FAKECOMM RO <REPLACE-ME:acl-name>\n")
    assert findings


def test_module_ids_exist_in_catalogue():
    for check_id, fn in registry.rules():
        if check_id.startswith("CSC-SNMP-"):
            assert CATALOGUE.get(check_id) is not None
    for check_id, fn in registry.extractors():
        if check_id.startswith("CSC-SNMP-"):
            assert CATALOGUE.get(check_id) is not None
