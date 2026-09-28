"""Tests for ciscocheck.rules.res (RES family, 8 checks)."""
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
    "CSC-RES-0001": ("", "boot system flash:cat9k_iosxe.bin\n"),
    "CSC-RES-0002": ("boot system tftp://192.0.2.1/image.bin\n", "boot system flash:cat9k_iosxe.bin\n"),
    "CSC-RES-0003": ("", "errdisable recovery cause bpduguard\nerrdisable recovery cause udld\n"
                     "errdisable recovery cause psecure-violation\n"),
    "CSC-RES-0004": ("errdisable recovery interval 30\n", "errdisable recovery interval 300\n"),
    "CSC-RES-0005": ("switch 1 priority 15\n", ""),
    "CSC-RES-0006": ("switch 1 priority 15\nswitch 2 priority 14\n",
                     "switch 1 priority 15\nswitch 2 priority 14\n"
                     "stack-mac persistent timer 0\n"),
    "CSC-RES-0007": ("", "redundancy\n mode sso\n"),
    "CSC-RES-0008": ("ip device tracking\n",
                     "ip device tracking\nip device tracking probe delay 10\n"
                     "ip device tracking probe interval 30\n"),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-RES-")}


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
        if check_id.startswith("CSC-RES-"):
            assert CATALOGUE.get(check_id) is not None
    for check_id, _ in registry.extractors():
        if check_id.startswith("CSC-RES-"):
            assert CATALOGUE.get(check_id) is not None


# ---------------------------------------------------------------------------------------
# Regression cases
# ---------------------------------------------------------------------------------------


def test_cat9k_stack_form_url_anywhere_in_the_line():
    findings = _fire("CSC-RES-0002", "boot system switch all tftp://192.0.2.1/image.bin\n")
    assert findings


def test_legacy_space_separated_tftp_form():
    findings = _fire("CSC-RES-0002", "boot system tftp image.bin 192.0.2.1\n")
    assert findings


def test_psecure_violation_satisfies_the_port_security_cause():
    """`psecure-violation` is the real Catalyst errdisable cause for a port-security
    violation shutdown; the old, unrelated `security-violation` (802.1x) keyword is never
    emitted by a port-security-only baseline and must no longer be required."""
    findings = _fire(
        "CSC-RES-0003",
        "errdisable recovery cause bpduguard\nerrdisable recovery cause udld\n"
        "errdisable recovery cause psecure-violation\n",
    )
    assert not findings


def test_missing_cause_still_fires():
    findings = _fire("CSC-RES-0003", "errdisable recovery cause bpduguard\n")
    assert findings


# ---------------------------------------------------------------------------------------
# Stack member priority / stack-mac persistence checks
# ---------------------------------------------------------------------------------------


def test_res0006_fires_on_stack_with_no_persistent_timer():
    findings = _fire("CSC-RES-0006", "switch 1 priority 15\nswitch 2 priority 14\n")
    assert findings


def test_res0006_does_not_fire_on_stack_mac_persistent_timer_0():
    """The must-not-fire case: `stack-mac persistent timer 0`,
    the real Cat9300 17.x global command -- not the old `switch stack-mac persistent-mac`
    form."""
    findings = _fire("CSC-RES-0006",
                     "switch 1 priority 15\nswitch 2 priority 14\n"
                     "stack-mac persistent timer 0\n")
    assert not findings


def test_res0006_does_not_apply_to_a_non_stacked_switch():
    """No `switch <N> ...` evidence at all means no stack, so RES-0006 has nothing to check --
    it must not fire on a lone, unstacked switch that has never mentioned `stack-mac` either
    way."""
    findings = _fire("CSC-RES-0006", "")
    assert not findings


def test_res0006_ignores_the_old_switch_stack_mac_form():
    """The old `switch stack-mac persistent-mac` line is not the real command and
    must not be read as satisfying the check."""
    findings = _fire("CSC-RES-0006",
                     "switch 1 priority 15\nswitch 2 priority 14\n"
                     "switch stack-mac persistent-mac\n")
    assert findings


def test_res0005_is_an_extractor_reporting_member_numbers():
    assert registry.lookup("CSC-RES-0005") in dict(registry.extractors()).values()
    findings = _fire("CSC-RES-0005", "switch 1 priority 15\nswitch 2 provision c9300-24t\n")
    assert findings
    assert "1" in findings[0].title and "2" in findings[0].title


def test_res0005_does_not_fire_with_no_stack_evidence():
    assert not _fire("CSC-RES-0005", "")
