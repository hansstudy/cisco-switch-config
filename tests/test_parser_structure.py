"""Structural parse through mask.mask_lines()."""
from __future__ import annotations

import dataclasses

import pytest

from ciscocheck import mask, parser


def _doc(text: str) -> mask.MaskedDocument:
    return mask.mask_lines(text.split("\n"))


def test_indent_stack_parents_and_mode_path():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n description x\n switchport mode access\n"
                       "router bgp 65000\n address-family ipv4\n  neighbor 10.0.0.2 activate\n"
                       " exit-address-family\nend\n")
    nb = cfg.find_one("neighbor 10.0.0.2 activate")
    assert nb.mode_path == ("router bgp 65000", "address-family ipv4")
    assert nb.parent.line.text == " address-family ipv4"
    assert nb.parent.parent.line.text == "router bgp 65000"
    assert nb.parent.parent.parent is None
    sw = cfg.find_one("switchport mode access")
    assert sw.mode_path == ("interface GigabitEthernet1/0/1",)      # canonical in mode_path
    assert sw.parent.line.text == "interface Gi1/0/1"                # text never rewritten
    assert [n.line.text for n in cfg.nodes][:3] == ["hostname SW1", "interface Gi1/0/1",
                                                     "router bgp 65000"]


def test_bang_closes_nothing():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n description a\n!\n shutdown\n"
                       "interface Gi1/0/2\n description b\nend\n")
    sh = cfg.find_one("shutdown")
    assert sh.parent.line.text == "interface Gi1/0/1"
    bang = next(n for n in cfg.walk() if n.line.kind == "comment")
    assert bang.line.head == "" and not bang.children


def test_tab_counts_as_eight_columns():
    doc = _doc("interface Gi1/0/1\n\tdescription tabbed\nhostname SW1")
    assert doc.lines[1].indent == 8
    assert doc.lines[1].mode_path == ("interface Gi1/0/1",)


def test_end_closes_everything_and_is_retained():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n shutdown\nend\n")
    end = cfg.find_one("end")
    assert end is not None and end.parent is None and end.line.kind == "command"


def test_exit_in_indent_mode_is_a_leaf():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n shutdown\n exit\ninterface Gi1/0/2\n"
                       " description y\nend\n")
    ex = cfg.find_one("exit")
    assert ex.parent.line.text == "interface Gi1/0/1" and not ex.children
    assert cfg.find_one("description y").parent.line.text == "interface Gi1/0/2"


MULTIWORD = [
    ("key chain CHAIN1", " key 1", ("key chain CHAIN1",)),
    ("aaa group server tacacs+ ISE", " server name ISE-1", ("aaa group server tacacs+ ISE",)),
    ("crypto ikev2 keyring KR1", " peer P1", ("crypto ikev2 keyring KR1",)),
    ("aaa server radius dynamic-author", " client 10.0.0.7", ("aaa server radius dynamic-author",)),
    ("event manager applet A1", " event none", ("event manager applet A1",)),
    ("crypto pki certificate chain TP1", " certificate ca 01", ("crypto pki certificate chain TP1",)),
    ("ip ssh pubkey-chain", " username bob", ("ip ssh pubkey-chain",)),
    ("wireless mobility group name G", " member ip 10.0.0.9", ("wireless mobility group name G",)),
]


@pytest.mark.parametrize("opener,child,mp", MULTIWORD, ids=[m[0] for m in MULTIWORD])
def test_mode_path_multiword_heads(opener, child, mp):
    doc = _doc(f"{opener}\n{child}")
    assert doc.lines[1].mode_path == mp


def test_mode_path_head_lowercased_remainder_preserved():
    doc = _doc("KEY CHAIN MixedCase\n key 1\n  key-string 7 CANARY-KC-9")
    assert doc.lines[1].mode_path == ("key chain MixedCase",)
    assert doc.lines[2].mode_path == ("key chain MixedCase", "key 1")
    assert "CANARY" not in doc.lines[2].result.text


def test_nesting_note_indent():
    doc = _doc("hostname SW1\ninterface Gi1/0/1\n shutdown")
    assert doc.nesting == "indent"
    assert mask.Note("CSC-SELF-0009", None, "nesting=indent") in doc.notes


def test_flat_input_uses_exit_driven_nesting():
    text = ("hostname SW1\ninterface Gi1/0/1\nswitchport mode access\nshutdown\nexit\n"
            "router bgp 65000\naddress-family ipv4\nneighbor 10.0.0.2 activate\nexit\n"
            "bgp log-neighbor-changes\nexit\nline vty 0 4\ntransport input ssh\nend\n")
    cfg = parser.parse(text)
    assert cfg.nesting == "exit-driven"
    assert any(n.detail == "nesting=exit-driven" for n in cfg.notes)
    assert cfg.find_one("shutdown").mode_path == ("interface GigabitEthernet1/0/1",)
    assert cfg.find_one("neighbor 10.0.0.2 activate").mode_path == (
        "router bgp 65000", "address-family ipv4")
    assert cfg.find_one("bgp log-neighbor-changes").mode_path == ("router bgp 65000",)
    assert cfg.find_one("transport input ssh").mode_path == ("line vty 0 4",)
    iface = cfg.interface("Gi1/0/1")
    assert iface.role == "unused"


def test_flat_sibling_interface_range_stays_separate():
    text = ("hostname SW1\ninterface range Gi1/0/1 - 4\nswitchport mode access\n"
            "interface Gi1/0/10\nswitchport mode trunk\nexit\nend\n")
    cfg = parser.parse(text)
    assert cfg.nesting == "exit-driven"
    solo = cfg.find_one("interface Gi1/0/10")
    assert solo.parent is None                      # a sibling, not a child of the range
    assert cfg.find_one("switchport mode trunk").parent is solo
    assert cfg.interface("Gi1/0/10").role == "trunk"
    assert cfg.interface("Gi1/0/2").role == "access"


def test_flat_address_family_pops_to_router_not_global():
    text = ("hostname SW1\nrouter bgp 1\naddress-family ipv4\nneighbor 10.0.0.1 activate\n"
            "address-family ipv6\nneighbor 10.0.0.2 activate\nexit\nexit\nend\n")
    cfg = parser.parse(text)
    af6 = cfg.find_one("address-family ipv6")
    assert af6.mode_path == ("router bgp 1",)
    assert cfg.find_one("neighbor 10.0.0.2 activate").mode_path == ("router bgp 1", "address-family ipv6")


def _all_strings(obj, seen=None):
    """Every str reachable from a dataclass / tuple tree."""
    if seen is None:
        seen = set()
    if id(obj) in seen:
        return
    seen.add(id(obj))
    if isinstance(obj, str):
        yield obj
    elif dataclasses.is_dataclass(obj):
        for f in dataclasses.fields(obj):
            yield from _all_strings(getattr(obj, f.name), seen)
    elif isinstance(obj, (tuple, list)):
        for x in obj:
            yield from _all_strings(x, seen)


CANARY_CONFIG = """hostname SW1
enable secret 5 $1$CA$CANARY0003
username admin privilege 15 secret 9 $9$CANARY0001
snmp-server community CANARY-COMMUNITY-01 RO 99
tacacs server TS1
 key 7 CANARY-TACACS-KEY-01
key chain CANARY-NOT-SECRET-NAME
 key 1
  key-string 7 CANARY-KC-01
crypto isakmp key CANARY-PSK-01 address 10.0.0.1
banner motd ^C
enable password CANARY-BANNER-01
^C
macro name M1
 snmp-server community CANARY-MACRO-01 RO
@
crypto pki certificate chain TP1
 certificate ca 01
  3082CANARY-CERT-01
  quit
foo-server key 7 CANARY-UNKNOWN-01 extra
end"""

SECRETS = ["$1$CA$CANARY0003", "$9$CANARY0001", "CANARY-COMMUNITY-01", "CANARY-TACACS-KEY-01",
           "CANARY-KC-01", "CANARY-PSK-01", "CANARY-BANNER-01", "CANARY-MACRO-01",
           "3082CANARY-CERT-01", "CANARY-UNKNOWN-01"]


def test_mask_lines_document_holds_no_raw_secret_strings():
    doc = mask.mask_lines(CANARY_CONFIG.split("\n"))
    strings = list(_all_strings(doc))
    assert strings, "document holds no strings at all"
    for s in strings:
        for secret in SECRETS:
            assert secret not in s, (secret, s)
    # every head is the lowercased first token of the masked text, or ""/"!"
    for ml in doc.lines:
        toks = mask.tokenize(ml.result.text)
        assert ml.head == (toks[0].lower() if toks else "")
        for el in ml.mode_path:
            assert not any(sec in el for sec in SECRETS)


def test_parse_holds_no_raw_and_no_digests():
    cfg = parser.parse(CANARY_CONFIG)
    for line in cfg.lines():
        for secret in SECRETS:
            assert secret not in line.text
    assert not hasattr(cfg.lines()[0], "raw")
    for rec in (cfg.lines()[0],):
        assert "digests" not in getattr(rec, "__dataclass_fields__", {})


def test_line_numbers_track_pre_clean_and_source():
    cfg = parser.parse("Building configuration...\n\nCurrent configuration : 99 bytes\n"
                       "hostname SW1\ninterface Gi1/0/1\n shutdown\nend\n")
    host = cfg.find_one("hostname SW1").line
    assert host.source_line_no == 4 and host.line_no == 2
