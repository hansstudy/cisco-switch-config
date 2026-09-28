"""Tests for ciscocheck.rules.ntp (NTP family, 7 checks)."""
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
    "CSC-NTP-0001": ("", "ntp server 192.0.2.123\n"),
    "CSC-NTP-0002": ("ntp server 192.0.2.123\n",
                    "ntp server 192.0.2.123\nntp server 198.51.100.123\n"),
    "CSC-NTP-0003": ("", "ntp authenticate\n"),
    "CSC-NTP-0004": ("ntp server 192.0.2.123\n", "ntp server 192.0.2.123 key 1\n"),
    "CSC-NTP-0005": ("ntp server 192.0.2.123 key 5\n",
                    "ntp server 192.0.2.123 key 5\nntp trusted-key 5\n"),
    "CSC-NTP-0006": ("ntp authentication-key 1 md5 CANARYKEY\n",
                    "ntp authentication-key 1 sha1 CANARYKEY\n"),
    "CSC-NTP-0007": ("", "ntp source Loopback0\n"),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-NTP-")}


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
        if check_id.startswith("CSC-NTP-"):
            assert CATALOGUE.get(check_id) is not None


# ---------------------------------------------------------------------------------------
# Regression repros
# ---------------------------------------------------------------------------------------


def test_trusted_key_range_covers_the_middle_key():
    findings = _fire("CSC-NTP-0005", "ntp server 192.0.2.1 key 2\nntp trusted-key 1 - 3\n")
    assert not findings


def test_vrf_qualified_server_host_is_not_the_word_vrf():
    findings = _fire("CSC-NTP-0004", "ntp server vrf MGMT 192.0.2.1\n")
    assert findings and findings[0].params.get("host") == "192.0.2.1"
