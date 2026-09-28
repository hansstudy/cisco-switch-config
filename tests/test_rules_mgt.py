"""Tests for ciscocheck.rules.mgt (MGT family, 14 checks)."""
from __future__ import annotations

import pytest

from ciscocheck import registry
from ciscocheck.model import Catalogue, Context
from ciscocheck.parser import parse
import ciscocheck.rules  # noqa: F401  (registration side effect)

CATALOGUE = Catalogue.load()
BASE = "hostname TESTSW\ninterface Loopback0\n ip address 198.51.100.1 255.255.255.255\n"

_FAMILY_MODULES = ("mgt", "aaa", "vty", "snmp", "log", "ntp", "ssh", "stp", "l2", "dhcp", "ifc", "res")


@pytest.fixture(autouse=True)
def _ensure_rules_registered():
    """Defensive against another test module's `registry.clear()`: a
    cleared registry does not repopulate on a bare `import ciscocheck.rules`, because the
    twelve family submodules are already cached in `sys.modules` and `from . import mgt`
    is then a no-op. Reloading the twelve submodules by name re-runs their `@rule`/
    `@extractor` decorators, regardless of what already ran earlier in this pytest session.
    """
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


def _fire(check_id, extra, *, platform="iosxe", role_map=None, text=None):
    cfg = parse(text if text is not None else BASE + extra, platform=platform, role_map=role_map)
    fn = registry.lookup(check_id)
    assert fn is not None, f"{check_id} has no registered rule or extractor"
    return list(fn(cfg, _ctx(check_id, cfg)))


CASES = {
    "CSC-MGT-0001": ("ip http server\n", "no ip http server\n"),
    "CSC-MGT-0002": ("ip http server\n", "ip http server\nip http access-class 10\n"),
    "CSC-MGT-0003": ("ip http server\nno ip http secure-server\n",
                    "ip http server\nip http secure-server\n"),
    "CSC-MGT-0004": ("service pad\n", "no service pad\n"),
    "CSC-MGT-0005": ("service tcp-small-servers\n",
                    "no service tcp-small-servers\nno service udp-small-servers\n"),
    "CSC-MGT-0006": ("ip bootp server\n", "no ip bootp server\n"),
    "CSC-MGT-0007": ("ip finger\n", "no ip finger\nno service finger\n"),
    "CSC-MGT-0008": ("ip source-route\n", "no ip source-route\n"),
    "CSC-MGT-0009": ("service config\n", "no service config\n"),
    "CSC-MGT-0010": ("vstack\n", "no vstack\n"),
    "CSC-MGT-0011": ("service call-home\n", "no service call-home\n"),
    "CSC-MGT-0012": ("netconf-yang\n", "netconf-yang ssh ipv4 access-list MGMT\n"),
    "CSC-MGT-0013": ("ip domain-lookup\n", "ip domain-lookup\nip name-server 192.0.2.1\n"),
    "CSC-MGT-0014": ("policy-map PM1\n class UNDEF-CLASS\n",
                    "class-map UNDEF-CLASS\npolicy-map PM1\n class UNDEF-CLASS\n"),
}


def test_every_case_covers_a_catalogue_entry():
    assert set(CASES) == {e.id for e in CATALOGUE if e.id.startswith("CSC-MGT-")}


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
    from ciscocheck.rules import mgt as module
    for check_id, _ in registry.rules():
        if check_id.startswith("CSC-MGT-"):
            assert CATALOGUE.get(check_id) is not None
    for check_id, _ in registry.extractors():
        if check_id.startswith("CSC-MGT-"):
            assert CATALOGUE.get(check_id) is not None


# ---------------------------------------------------------------------------------------
# Regression repros
# ---------------------------------------------------------------------------------------


def test_http_access_class_does_not_restrict_netconf():
    """F5: `ip http access-class` governs HTTP/RESTCONF only; NETCONF still fires."""
    findings = _fire("CSC-MGT-0012", "netconf-yang\nip http access-class ipv4 MGMT\n")
    assert findings and findings[0].title.endswith("netconf-yang")


def test_restconf_is_restricted_by_http_access_class():
    findings = _fire("CSC-MGT-0012", "restconf\nip http access-class ipv4 MGMT\n")
    assert not findings


def test_restconf_without_http_access_class_fires():
    findings = _fire("CSC-MGT-0012", "restconf\n")
    assert findings and findings[0].title.endswith("restconf")


def test_domain_lookup_space_form():
    """F4 (MGT-0013 half): `no ip domain lookup` (space, IOS-XE running-config spelling)
    must be read as compliant, not as the hyphenated key's literal-only fallback form."""
    findings = _fire("CSC-MGT-0013", "ip domain-lookup\nno ip domain lookup\nip name-server 192.0.2.1\n")
    assert not findings
