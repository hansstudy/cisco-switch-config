"""Tests for ciscocheck.rules.aaa (AAA family, 12 checks)."""
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
    "CSC-AAA-0001": ("", "aaa new-model\n"),
    "CSC-AAA-0002": ("aaa new-model\n", "aaa new-model\naaa authentication login default group TACGRP local\n"),
    "CSC-AAA-0003": ("aaa authentication login default group TACGRP\n",
                    "aaa authentication login default group TACGRP local\n"),
    "CSC-AAA-0004": ("", "aaa authentication enable default group TACGRP enable\n"),
    "CSC-AAA-0005": ("", "aaa authorization exec default group TACGRP local\n"),
    "CSC-AAA-0006": ("", "aaa authorization console\n"),
    "CSC-AAA-0007": ("", "aaa accounting commands 15 default start-stop group TACGRP\n"),
    "CSC-AAA-0008": ("tacacs server TAC1\n address ipv4 192.0.2.1\n",
                    "tacacs server TAC1\n address ipv4 192.0.2.1\n"
                    "tacacs server TAC2\n address ipv4 192.0.2.2\n"),
    "CSC-AAA-0009": ("aaa authentication login default group UNDEF-GRP local\n",
                    "aaa group server tacacs+ DEF-GRP\n server name TAC1\n"
                    "aaa authentication login default group DEF-GRP local\n"),
    "CSC-AAA-0010": ("username bob privilege 15 password 7 CANARYPW\n",
                    "username bob privilege 15 secret 9 $9$CANARYHASH\n"),
    "CSC-AAA-0011": ("enable password 7 CANARYPW\n", "enable secret 9 $9$CANARYHASH\n"),
    "CSC-AAA-0012": ("", "service password-encryption\n"),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-AAA-")}


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
        if check_id.startswith("CSC-AAA-"):
            assert CATALOGUE.get(check_id) is not None


# ---------------------------------------------------------------------------------------
# Regression repros
# ---------------------------------------------------------------------------------------


def test_implicit_type0_password_fires():
    findings = _fire("CSC-AAA-0010", "username admin privilege 15 password FAKEPW123\n")
    assert findings


def test_placeholder_password_does_not_fire():
    findings = _fire("CSC-AAA-0010", "username admin privilege 15 password <REPLACE-ME:local-user-secret>\n")
    assert not findings


def test_algorithm_type_md5_fires():
    findings = _fire("CSC-AAA-0011", "enable algorithm-type md5 secret FAKEPW\n")
    assert findings


def test_secret_level_15_type9_does_not_fire():
    findings = _fire("CSC-AAA-0011", "enable secret level 15 9 $9$FAKEHASH\n")
    assert not findings


def test_unfilled_secret_placeholder_does_not_fire():
    findings = _fire("CSC-AAA-0011", "enable secret <REPLACE-ME:enable-secret>\n")
    assert not findings


def test_accounting_commands_none_still_fires():
    findings = _fire("CSC-AAA-0007", "aaa accounting commands 15 default none\n")
    assert findings


def test_authorization_exec_none_still_fires():
    findings = _fire("CSC-AAA-0005", "aaa authorization exec default none\n")
    assert findings


def test_server_private_counts_toward_two_servers():
    findings = _fire(
        "CSC-AAA-0008",
        "aaa group server tacacs+ TACGRP\n"
        " server-private 192.0.2.1 key 7 FAKEKEY01\n"
        " server-private 192.0.2.2 key 7 FAKEKEY02\n",
    )
    assert not findings
