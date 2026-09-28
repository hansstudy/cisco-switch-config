"""Tests for ciscocheck.rules.ssh (SSH family, 9 checks)."""
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
    "CSC-SSH-0001": ("ip ssh version 1\n", "ip ssh version 2\n"),
    "CSC-SSH-0002": ("", "ip domain-name example.invalid\n"),
    "CSC-SSH-0003": ("ip ssh dh min size 1024\n", "ip ssh dh min size 2048\n"),
    "CSC-SSH-0004": ("ip ssh server algorithm encryption aes256-ctr 3des-cbc\n",
                     "ip ssh server algorithm encryption aes256-ctr aes128-ctr\n"),
    "CSC-SSH-0005": ("ip ssh server algorithm mac hmac-sha1\n",
                     "ip ssh server algorithm mac hmac-sha2-256\n"),
    "CSC-SSH-0006": ("ip ssh server algorithm kex diffie-hellman-group14-sha1\n",
                     "ip ssh server algorithm kex diffie-hellman-group14-sha256\n"),
    "CSC-SSH-0007": ("ip ssh authentication-retries 5\n", "ip ssh authentication-retries 3\n"),
    "CSC-SSH-0008": ("ip ssh time-out 120\n", "ip ssh time-out 60\n"),
    "CSC-SSH-0009": ("crypto pki trustpoint TP1\n", ""),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-SSH-")}


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
        if check_id.startswith("CSC-SSH-"):
            assert CATALOGUE.get(check_id) is not None


def test_space_separated_domain_name_form():
    """F4: `ip domain name example.com` (no hyphen) is IOS-XE 16/17's own running-config
    spelling and must not be a literal-match false positive."""
    findings = _fire("CSC-SSH-0002", "ip domain name example.invalid\n")
    assert not findings
    for check_id, _ in registry.extractors():
        if check_id.startswith("CSC-SSH-"):
            assert CATALOGUE.get(check_id) is not None
