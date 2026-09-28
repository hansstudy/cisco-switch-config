"""Tests for ciscocheck.rules.log (LOG family, 9 checks)."""
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
    "CSC-LOG-0001": ("", "logging host 192.0.2.30\n"),
    "CSC-LOG-0002": ("logging host 192.0.2.30\n",
                    "logging host 192.0.2.30\nlogging host 192.0.2.31\n"),
    "CSC-LOG-0003": ("logging trap warnings\n", "logging trap informational\n"),
    "CSC-LOG-0004": ("", "service timestamps log datetime msec localtime show-timezone\n"),
    "CSC-LOG-0005": ("logging buffered 4096\n", "logging buffered 16384\n"),
    "CSC-LOG-0006": ("", "logging source-interface Loopback0\n"),
    "CSC-LOG-0007": ("", "archive\n log config\n  logging enable\n"),
    "CSC-LOG-0008": ("archive\n log config\n  logging enable\n",
                    "archive\n log config\n  logging enable\n  hidekeys\n"),
    "CSC-LOG-0009": ("logging console debugging\n", "logging console critical\n"),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-LOG-")}


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
        if check_id.startswith("CSC-LOG-"):
            assert CATALOGUE.get(check_id) is not None


# ---------------------------------------------------------------------------------------
# Regression repros
# ---------------------------------------------------------------------------------------


def test_legacy_logging_form_counts_as_a_destination():
    assert not _fire("CSC-LOG-0001", "logging 192.0.2.10\n")


def test_legacy_and_modern_forms_together_satisfy_two_destinations():
    assert not _fire("CSC-LOG-0002", "logging 192.0.2.10\nlogging host 192.0.2.11\n")


def test_logging_on_is_not_mistaken_for_a_destination():
    """`logging on` is the global on/off switch, not a syslog server address."""
    assert _fire("CSC-LOG-0001", "logging on\n")
