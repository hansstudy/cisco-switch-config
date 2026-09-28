"""parse_pair() and the structural differ."""
from __future__ import annotations

from ciscocheck import engine, mask, parser, report
from ciscocheck.model import Catalogue

CAT = Catalogue.from_dict({"version": 1, "catalogue_version": "2026.09", "checks": [
    {"id": "CSC-STP-0004", "title": "BPDU Guard missing on an individual access port",
     "severity": "high", "category": "security", "confidence": "heuristic",
     "platforms": ["ios", "iosxe"], "profiles": ["campus", "stig"], "test_kind": "absent",
     "subject": ["spanning-tree bpduguard enable"], "rationale": "r", "params_required": [],
     "remediation": [" spanning-tree bpduguard enable"],
     "refs": [{"authority": "DISA-STIG", "id": "TEST", "version": "V1"}]}]})

BASE = ("hostname SW1\ntacacs-server key 7 {tk}\nusername alice secret 9 {a}\n"
        "username bob secret 9 {b}\nsnmp-server community {c} RO 99\n"
        "interface Gi1/0/1\n spanning-tree bpduguard enable\n description {d}\nend\n")


def test_rotation_of_any_length_is_one_change_with_changed_token():
    old = BASE.format(tk="CANARY-TACACS-KEY-01", a="$9$ALICE1", b="$9$BOB1", c="CANARY-C-01", d="x")
    new = BASE.format(tk="CANARY-TACACS-KEY-ROTATED", a="$9$ALICE1", b="$9$BOB2", c="CANARY-C-01",
                      d="x")
    o, n = parser.parse_pair(old, new)
    tk_old = o.find_one("tacacs-server key").line
    tk_new = n.find_one("tacacs-server key").line
    assert tk_old.redactions[0].changed is True and tk_new.redactions[0].changed is True
    assert tk_new.text == "tacacs-server key 7 [REDACTED tacacs-key, 25 chars, changed]"
    assert tk_old.text == "tacacs-server key 7 [REDACTED tacacs-key, 20 chars, changed]"
    # the skeleton key tells alice from bob, so `changed` lands on bob only
    alice = n.find_one("username alice").line.redactions[0]
    bob = n.find_one("username bob").line.redactions[0]
    assert alice.changed is False and bob.changed is True
    assert n.find_one("snmp-server community").line.redactions[0].changed is False
    d = engine.diff(o, n, CAT)
    assert sorted(c.kind for c in d.changes) == ["secret-rotated", "secret-rotated"]
    everything = report.render_diff_table(d) + report.render_diff_json(d)
    for raw in ("CANARY-TACACS", "ALICE1", "BOB1", "BOB2"):
        assert raw not in everything
    for line in everything.split("\n"):
        assert mask.scrub(line) == ()


def test_key_present_on_one_side_only_has_changed_none():
    o, n = parser.parse_pair("hostname SW1\ninterface Gi1/0/1\n shutdown\nend\n",
                             "hostname SW1\ntacacs-server key CANARY-T\ninterface Gi1/0/1\n"
                             " shutdown\nend\n")
    assert n.find_one("tacacs-server key").line.redactions[0].changed is None
    d = engine.diff(o, n, CAT)
    assert [c.kind for c in d.changes] == ["added"]


def test_reordering_within_a_block_is_not_a_change():
    o, n = parser.parse_pair("hostname SW1\ninterface Gi1/0/1\n description a\n shutdown\nend\n",
                             "hostname SW1\ninterface Gi1/0/1\n shutdown\n description a\nend\n")
    assert engine.diff(o, n, CAT).changes == ()


def test_removed_changed_and_crosses_checks():
    o, n = parser.parse_pair(BASE.format(tk="K1", a="A", b="B", c="C", d="old"),
                             BASE.format(tk="K1", a="A", b="B", c="C", d="new")
                             .replace(" spanning-tree bpduguard enable\n", ""))
    d = engine.diff(o, n, CAT)
    kinds = {c.kind: c for c in d.changes}
    assert kinds["removed"].crosses_checks == ("CSC-STP-0004",)
    assert kinds["removed"].mode_path == ("interface GigabitEthernet1/0/1",)
    assert kinds["changed"].old.text == " description old"
    assert kinds["changed"].new.text == " description new"


def test_parse_pair_holds_no_digest_or_value():
    o, n = parser.parse_pair("hostname SW1\nsnmp-server community CANARY-A RO\nend\n",
                             "hostname SW1\nsnmp-server community CANARY-B RO\nend\n")
    for cfg in (o, n):
        for line in cfg.lines():
            assert "CANARY" not in line.text
            assert not any(len(t) == 64 and all(ch in "0123456789abcdef" for ch in t)
                           for t in line.tokens)
