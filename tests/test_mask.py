"""mask.py - the security-critical module.

Inline synthetic canaries only. No fixture files shared with other test modules.
"""
from __future__ import annotations

import ast
import pathlib
import re

import pytest

from ciscocheck import mask
from ciscocheck.mask import (CONSTRUCTS, REDACTION_RE, TRIGGER_KEYWORDS, EgressGuardError,
                             is_placeholder, redact_line, scrub, token, tokenize)

PKG = pathlib.Path(mask.__file__).resolve().parent


def red(text: str, mp: tuple[str, ...] = ()) -> mask.RedactResult:
    return redact_line(text, mode_path=mp, line_no=1)


# --------------------------------------------------------------------------- 3.4.3 worked rows

WORKED = [
    ("snmp-server community S3cretRO RO 99", (),
     "snmp-server community [REDACTED snmp-community, 8 chars] RO 99"),
    ("snmp-server host 10.0.0.1 traps version 2c S3cretRO", (),
     "snmp-server host 10.0.0.1 traps version 2c [REDACTED snmp-community, 8 chars]"),
    ("crypto isakmp key MyPsk address 10.0.0.1", (),
     "crypto isakmp key [REDACTED isakmp-psk, 5 chars] address 10.0.0.1"),
    ("ntp authentication-key 1 md5 S3cret 7", (),
     "ntp authentication-key 1 md5 [REDACTED ntp-key, 6 chars] 7"),
    ("ip ospf message-digest-key 1 md5 7 0822455D0A16", ("interface GigabitEthernet1/0/1",),
     "ip ospf message-digest-key 1 md5 7 [REDACTED ospf-md-key, 12 chars]"),
    ("snmp-server user u1 grp v3 auth sha AuthPw priv aes 128 PrivPw", (),
     "snmp-server user u1 grp v3 auth sha [REDACTED snmpv3-auth, 6 chars] priv aes 128 "
     "[REDACTED snmpv3-priv, 6 chars]"),
    ("snmp-server user mon RO-GRP v3 auth sha AuthPw access 99", (),
     "snmp-server user mon RO-GRP v3 auth sha [REDACTED snmpv3-auth, 6 chars] access 99"),
    ("snmp-server user u2 grp remote 10.0.0.9 v3 auth md5 AuthPw", (),
     "snmp-server user u2 grp remote 10.0.0.9 v3 auth md5 [REDACTED snmpv3-auth, 6 chars]"),
    ("snmp-server host 192.0.2.10 version 2c MyComm config envmon", (),
     "snmp-server host 192.0.2.10 version 2c [REDACTED snmp-community, 6 chars] config envmon"),
    ("snmp-server host 192.0.2.10 vrf MGMT informs version 2c MyComm", (),
     "snmp-server host 192.0.2.10 vrf MGMT informs version 2c [REDACTED snmp-community, 6 chars]"),
    ("snmp-server host 192.0.2.10 version 3 priv monuser", (),
     "snmp-server host 192.0.2.10 version 3 priv monuser"),
    ("username admin privilege 15 secret 9 $9$CANARY0001abcdefghijk", (),
     "username admin privilege 15 secret 9 [REDACTED local-user-secret, 24 chars]"),
    (' action 1.0 cli command "snmp-server community S3cret RO"', ("event manager applet A1",),
     " action 1.0 cli command [REDACTED eem-cli-secret, 33 chars]"),
    ("standby 1 authentication md5 key-string 7 070C285F4D06", ("interface Vlan10",),
     "standby 1 authentication md5 key-string 7 [REDACTED hsrp-key, 12 chars]"),
    (" security wpa psk set-key ascii 0 MyWifiPsk", ("wlan CORP 1 CORP",),
     " security wpa psk set-key ascii 0 [REDACTED wlan-psk, 9 chars]"),
    (" path ftp://svc:P4ssw0rd@10.0.0.9/cfg", ("archive",),
     " path ftp://svc:[REDACTED url-password, 8 chars]@10.0.0.9/cfg"),
    ("foo-server key 7 CANARY-UNKNOWN-01 extra", (),
     "foo-server key [REDACTED unknown-secret, span]"),
    ("ntp server 10.0.0.1 key 1", (), "ntp server 10.0.0.1 key 1"),
    ("enable password level 15 7 0822455D0A16", (),
     "enable password level 15 7 [REDACTED enable-password, 12 chars]"),
    ("ntp authentication-key 1 hmac-sha2-256 S3cret 7", (),
     "ntp authentication-key 1 hmac-sha2-256 [REDACTED ntp-key, 6 chars] 7"),
    ("ntp authentication-key 1 hmac-sha1 S3cret 7", (),
     "ntp authentication-key 1 hmac-sha1 [REDACTED ntp-key, 6 chars] 7"),
    ("ntp authentication-key 1 cmac-aes-128 S3cret 7", (),
     "ntp authentication-key 1 cmac-aes-128 [REDACTED ntp-key, 6 chars] 7"),
    ("ipv6 ospf authentication ipsec spi 500 md5 7 0123ABCD", ("interface GigabitEthernet1/0/1",),
     "ipv6 ospf authentication ipsec spi 500 md5 7 [REDACTED ospfv3-ipsec-key, 8 chars]"),
    (" area 0 authentication ipsec spi 500 sha1 0123ABCD", ("router ospfv3 1",),
     " area 0 authentication ipsec spi 500 sha1 [REDACTED ospfv3-ipsec-key, 8 chars]"),
    (" area 0 encryption ipsec spi 500 esp aes-cbc 128 K1K1 sha1 K2K2", ("router ospfv3 1",),
     " area 0 encryption ipsec spi 500 esp aes-cbc 128 [REDACTED ospfv3-ipsec-key, 4 chars] "
     "sha1 [REDACTED ospfv3-ipsec-key, 4 chars]"),
    ("event manager environment _snmp_community S3cret", (),
     "event manager environment _snmp_community [REDACTED eem-env-secret, 6 chars]"),
    (" enrollment url http://svc:P4ss@ca.example.invalid/certsrv", ("crypto pki trustpoint TP1",),
     " enrollment url http://svc:[REDACTED url-password, 4 chars]@ca.example.invalid/certsrv"),
    ("boot system flash:cat9k_iosxe.17.09.04a.SPA.bin", (),
     "boot system flash:cat9k_iosxe.17.09.04a.SPA.bin"),
    ("standby 1 authentication md5 key-chain HSRP-KC", ("interface Vlan10",),
     "standby 1 authentication md5 key-chain HSRP-KC"),
]


@pytest.mark.parametrize("raw,mp,masked", WORKED, ids=[w[0].strip()[:40] for w in WORKED])
def test_every_worked_row_of_3_4_3(raw, mp, masked):
    r = red(raw, mp)
    assert r.text == masked
    # every raw value token that was redacted is absent; the masked line is egress-clean
    assert scrub(r.text) == ()
    assert len(r.digests) == len(r.redactions)


def test_worked_row_span_length_is_none():
    r = red("foo-server key 7 CANARY-UNKNOWN-01 extra")
    assert [(x.cls, x.length, x.extent) for x in r.redactions] == [("unknown-secret", None, "span")]
    assert "CANARY-UNKNOWN-01" not in r.text and "extra" not in r.text


# --------------------------------------------------------------------------- one case per row

ROW_CASES = [
    # (line, mode_path, expected class) - every CONSTRUCTS row must be the deciding row once
    ("enable password level 15 0 CANARYEP1", (), "enable-password"),
    ("enable password 7 CANARYEP2", (), "enable-password"),
    ("enable secret level 15 5 CANARYES1", (), "enable-secret"),
    ("enable secret 9 CANARYES2", (), "enable-secret"),
    ("enable algorithm-type scrypt secret CANARYES3", (), "enable-secret"),
    ("username bob privilege 15 password 0 CANARYUP1", (), "local-user-password"),
    ("username bob privilege 15 secret 9 CANARYUS1", (), "local-user-secret"),
    ("username bob algorithm-type sha256 secret CANARYUS2", (), "local-user-secret"),
    ("username bob one-time secret 0 CANARYUS3", (), "local-user-secret"),
    (" password 7 CANARYLP1", ("line vty 0 4",), "line-password"),
    (" secret 5 CANARYPV1", ("parser view NOC",), "parser-view-secret"),
    ("key config-key password-encrypt CANARYMK1", (), "master-key"),
    ("snmp-server community CANARYSC1 RO", (), "snmp-community"),
    ("snmp-server community-map CANARYSC2 context C", (), "snmp-community"),
    ("snmp-server host 10.0.0.1 CANARYSC3", (), "snmp-community"),
    ("snmp-server user u g v3 auth sha CANARYA1 priv aes 256 CANARYP1", (), "snmpv3-auth"),
    ("snmp-server user u g v3 priv aes CANARYP2", (), "snmpv3-priv"),
    ("tacacs-server key 7 CANARYTK1", (), "tacacs-key"),
    ("tacacs-server host 10.0.0.5 timeout 5 key CANARYTK2", (), "tacacs-key"),
    (" key 7 CANARYTK3", ("tacacs server TS1",), "tacacs-key"),
    ("radius-server key 7 CANARYRK1", (), "radius-key"),
    ("radius-server host 10.0.0.6 auth-port 1812 key CANARYRK2", (), "radius-key"),
    (" key 7 CANARYRK3", ("radius server RS1",), "radius-key"),
    (" pac key 7 CANARYRK4", ("radius server RS1",), "radius-pac-key"),
    (" server-private 10.0.0.5 timeout 3 key 7 CANARYSK1", ("aaa group server tacacs+ G1",),
     "aaa-server-key"),
    (" client 10.0.0.7 vrf V server-key 7 CANARYCOA", ("aaa server radius dynamic-author",),
     "coa-server-key"),
    ("ntp authentication-key 2 md5 CANARYNTP 7", (), "ntp-key"),
    ("license smart trust idtoken CANARYTOK local force", (), "smart-idtoken"),
    ("ip ftp password 0 CANARYFTP", (), "ftp-password"),
    ("ip http client password 0 CANARYHTTP", (), "http-client-password"),
    ("ip http client proxy-server http://u:CANARYPX@proxy.example.invalid:8080", (), "url-password"),
    ("boot system ftp://u:CANARYBOOT@10.0.0.9/image.bin", (), "url-password"),
    (" path scp://u:CANARYARC@10.0.0.9/cfg", ("archive",), "url-password"),
    (" cli copy running-config ftp://u:CANARYKRON@10.0.0.9/cfg", ("kron policy-list P",),
     "url-password"),
    ("  destination address http http://u:CANARYCH1@ch.example.invalid/x",
     ("call-home", "profile P1"), "url-password"),
    (" http-proxy http://u:CANARYCH2@proxy.example.invalid:80", ("call-home",), "url-password"),
    (" enrollment url http://u:CANARYEN@ca.example.invalid/x", ("crypto pki trustpoint TP",),
     "url-password"),
    ("  key-hash ssh-rsa CANARYHASH01", ("ip ssh pubkey-chain", "username bob"), "ssh-pubkey-hash"),
    ("  key-string", ("ip ssh pubkey-chain", "username bob"), "ssh-pubkey-body"),
    (' action 2.0 cli command "tacacs-server key CANARYEEM"', ("event manager applet X",),
     "eem-cli-secret"),
    ("event manager environment _tacacs_key CANARYENV", (), "eem-env-secret"),
    ("cts sxp default password 0 CANARYSXP", (), "cts-sxp-password"),
    (" password 0 CANARYDOT1X", ("dot1x credentials C1",), "dot1x-password"),
    (" credentials username u1 password 0 CANARYSIP", ("sip-ua",), "sip-password"),
    ("wsma profile listener P transport https password 0 CANARYWSMA", (), "wsma-password"),
    (" transport https ipv4 10.0.0.9 password 0 CANARYPNP", ("pnp profile P",), "pnp-password"),
    ("vtp password CANARYVTP", (), "vtp-password"),
    (" ppp chap password 0 CANARYCHAP", ("interface Serial0/0",), "ppp-chap-password"),
    (" ppp pap sent-username u password 0 CANARYPAP", ("interface Serial0/0",), "ppp-pap-password"),
    ("  key-string 7 CANARYKC", ("key chain KC1", "key 1"), "key-chain-key"),
    (" ip ospf message-digest-key 1 md5 CANARYMD", ("interface Vlan10",), "ospf-md-key"),
    (" ip ospf authentication-key 7 CANARYOAK", ("interface Vlan10",), "ospf-auth-key"),
    (" ipv6 ospf encryption ipsec spi 256 esp null sha1 CANARYV3A", ("interface Vlan10",),
     "ospfv3-ipsec-key"),
    (" ipv6 ospf encryption ipsec spi 257 esp aes-cbc 128 CANARYV3B sha1 CANARYV3C",
     ("interface Vlan10",), "ospfv3-ipsec-key"),
    (" ipv6 ospf authentication ipsec spi 258 sha1 CANARYV3D", ("interface Vlan10",),
     "ospfv3-ipsec-key"),
    (" ospfv3 1 encryption ipsec spi 259 esp null sha1 CANARYV3E", ("interface Vlan10",),
     "ospfv3-ipsec-key"),
    (" ospfv3 1 encryption ipsec spi 260 esp aes-cbc 128 CANARYV3F sha1 CANARYV3G",
     ("interface Vlan10",), "ospfv3-ipsec-key"),
    (" ospfv3 1 authentication ipsec spi 261 md5 CANARYV3H", ("interface Vlan10",),
     "ospfv3-ipsec-key"),
    (" area 1 encryption ipsec spi 262 esp null sha1 CANARYV3I", ("router ospfv3 1",),
     "ospfv3-ipsec-key"),
    (" area 1 encryption ipsec spi 263 esp aes-cbc 128 CANARYV3J sha1 CANARYV3K",
     ("router ospfv3 1",), "ospfv3-ipsec-key"),
    (" area 1 authentication ipsec spi 264 sha1 CANARYV3L", ("router ospfv3 1",),
     "ospfv3-ipsec-key"),
    (" ip rip authentication key-string 0 CANARYRIP", ("interface Vlan10",), "rip-key"),
    ("   authentication mode hmac-sha-256 0 CANARYEIGRP",
     ("router eigrp NAMED", "address-family ipv4 unicast autonomous-system 1",
      "af-interface default"), "eigrp-key"),
    (" isis password 0 CANARYISIS1", ("interface Vlan10",), "isis-password"),
    (" area-password CANARYISIS2", ("router isis",), "isis-password"),
    (" neighbor 10.0.0.2 password 7 CANARYBGP", ("router bgp 65000",), "bgp-password"),
    ("mpls ldp neighbor 10.0.0.3 password 0 CANARYLDP", (), "ldp-password"),
    ("ip msdp password peer 10.0.0.4 0 CANARYMSDP", (), "msdp-password"),
    (" authentication-key 0 CANARYLISP", ("router lisp",), "lisp-key"),
    (" standby 1 authentication md5 key-string 7 CANARYHS1", ("interface Vlan10",), "hsrp-key"),
    (" standby 2 authentication text CANARYHS2", ("interface Vlan10",), "hsrp-key"),
    (" standby 3 authentication CANARYHS3", ("interface Vlan10",), "hsrp-key"),
    (" vrrp 1 authentication text CANARYVR", ("interface Vlan10",), "vrrp-key"),
    (" glbp 1 authentication md5 key-string 7 CANARYGL", ("interface Vlan10",), "glbp-key"),
    (" ip nhrp authentication CANARYNH", ("interface Tunnel0",), "nhrp-key"),
    ("crypto isakmp key 0 CANARYIK address 10.0.0.1", (), "isakmp-psk"),
    (" pre-shared-key address 10.0.0.1 key CANARYKR", ("crypto keyring K1",), "isakmp-psk"),
    ("  pre-shared-key local 0 CANARYIKEV2", ("crypto ikev2 keyring KR1", "peer P1"), "ikev2-psk"),
    (" authentication local pre-share key 0 CANARYIKP", ("crypto ikev2 profile PR1",), "ikev2-psk"),
    (" password 0 CANARYCHAL", ("crypto pki trustpoint TP",), "pki-challenge"),
    (" certificate ca 01", ("crypto pki certificate chain TP",), "pki-cert-body"),
    ("certificate self-signed 01", ("crypto pki certificate chain TP",), "pki-cert-body"),
    ("  key-string", ("crypto key pubkey-chain rsa", "named-key R1"), "rsa-key-body"),
    (" security wpa psk set-key hex 0 CANARYPSK", ("wlan W 1 W",), "wlan-psk"),
    ("ap dot1x username u password 0 CANARYAP1", (), "ap-password"),
    ("ap mgmtuser username u password 0 CANARYAP2 secret 0 CANARYAP3", (), "ap-password"),
    (" member mac-address 0011.2233.4455 ip 10.0.0.9 key 0 CANARYMOB",
     ("wireless mobility group name G",), "mobility-key"),
    # additional construct rows
    (' action 1.2 set pw "CANARYSET"', ("event manager applet X",), "eem-env-secret"),
    ("crypto key export rsa K1 pem terminal 3des CANARYKX1", (), "crypto-key-passphrase"),
    ("crypto key export rsa K1 pem url flash: 3des CANARYKX2", (), "crypto-key-passphrase"),
    ("crypto key import rsa K1 pem terminal CANARYKI1", (), "crypto-key-passphrase"),
    ("crypto key import rsa K1 usage-keys pem url tftp://10.0.0.9/k CANARYKI2", (),
     "crypto-key-passphrase"),
    ("crypto key export ec K1 der terminal CANARYKX3", (), "crypto-key-passphrase"),
    # further construct rows
    ("crypto pki export TP pem terminal 3des CANARYPK1", (), "crypto-key-passphrase"),
    ("crypto pki export TP pem url flash:tp 3des CANARYPK2", (), "crypto-key-passphrase"),
    ("crypto pki import TP pkcs12 tftp://192.0.2.1/tp.p12 CANARYPK3", (), "crypto-key-passphrase"),
    ("crypto ca import TP certificate CANARYPK4", (), "crypto-key-passphrase"),
    (" area 1 virtual-link 10.0.0.1 message-digest-key 1 md5 CANARYVL1", ("router ospf 1",),
     "ospf-md-key"),
    (" area 1 sham-link 10.0.0.1 10.0.0.2 authentication-key 7 CANARYVL2", ("router ospf 1",),
     "ospf-auth-key"),
    ("  sap pmk CANARYPMK mode-list gcm-encrypt", ("interface TenGigabitEthernet1/1/1", "cts manual"),
     "sap-pmk"),
    ("energywise domain D security shared-secret 0 CANARYEW", (), "energywise-secret"),
    (" ospfv3 1 ipv4 encryption ipsec spi 600 esp null sha1 CANARYV3M", ("interface Vlan10",),
     "ospfv3-ipsec-key"),
    (" ospfv3 1 ipv6 encryption ipsec spi 601 esp aes-cbc 128 CANARYV3N sha1 CANARYV3O",
     ("interface Vlan10",), "ospfv3-ipsec-key"),
    (" ospfv3 1 ipv4 authentication ipsec spi 602 sha1 CANARYV3P", ("interface Vlan10",),
     "ospfv3-ipsec-key"),
    (" area 1 virtual-link 10.0.0.1 encryption ipsec spi 603 esp null sha1 CANARYV3Q",
     ("router ospfv3 1",), "ospfv3-ipsec-key"),
    (" area 1 virtual-link 10.0.0.1 encryption ipsec spi 604 esp aes-cbc 128 CANARYV3R sha1 CANARYV3S",
     ("router ospfv3 1",), "ospfv3-ipsec-key"),
    (" area 1 virtual-link 10.0.0.1 authentication ipsec spi 605 md5 CANARYV3T",
     ("router ospfv3 1",), "ospfv3-ipsec-key"),
]


def _matching_rows(line: str, mp: tuple[str, ...]) -> list[int]:
    """Every row whose mode gate and grammar accept the line (a later same-class row may be
    subsumed by an earlier one, e.g. the `algorithm-type` form by the `%REST ... secret` row)."""
    t = mask._Toks(tokenize(line), scrub=False)
    spans = mask._spans(line)
    return [i for i, (c, els) in enumerate(zip(CONSTRUCTS, mask._COMPILED))
            if mask._mode_ok(c.mode, mp)
            and mask._first_binding(c.cls, els, t, 0, line, spans) is not None]


@pytest.mark.parametrize("line,mp,cls", ROW_CASES, ids=[f"{c[2]}:{c[0].strip()[:30]}" for c in ROW_CASES])
def test_construct_row(line, mp, cls):
    r = red(line, mp)
    canaries = re.findall(r"CANARY[A-Z0-9-]*", line)
    for c in canaries:
        assert c not in r.text
    if cls in ("ssh-pubkey-body", "pki-cert-body", "rsa-key-body"):
        # a $BODY opener survives as an ordinary line; the body is redacted by mask_lines
        assert r.text == line.rstrip() and r.redactions == ()
        _, body = mask._scan(line, mp)
        assert body == cls
    else:
        assert r.redactions and r.redactions[0].cls == cls
    # structural head always survives
    assert r.text.split()[0] == line.split()[0]


def test_every_construct_row_has_a_case():
    covered: set[int] = set()
    for line, mp, _cls in ROW_CASES:
        covered.update(i for i in _matching_rows(line, mp) if CONSTRUCTS[i].cls == _cls)
    missing = [f"{i}:{CONSTRUCTS[i].cls}:{CONSTRUCTS[i].pattern}"
               for i in range(len(CONSTRUCTS)) if i not in covered]
    assert missing == []


def test_table_order_and_ingest_only_flags():
    # 3 base prefixes + 2 additional prefixes (ipv4|ipv6 form, virtual-link), x 3 suffixes
    assert sum(1 for c in CONSTRUCTS if c.cls == "ospfv3-ipsec-key") == 15
    assert [c.cls for c in CONSTRUCTS if c.chain] == ["snmpv3-auth"]
    for c in CONSTRUCTS:
        first = c.pattern[0]
        trigger_first = any(a.lower() in TRIGGER_KEYWORDS for a in first.split("|"))
        expect = first.startswith("%") or trigger_first or "$BODY" in c.pattern
        assert c.ingest_only is expect, c
    classes = {c.cls for c in CONSTRUCTS}
    assert classes | {"unknown-secret", "snmp-community-weak", "line-password-weak",
                      "enable-password-weak"} <= mask.CANARY_CLASSES


# --------------------------------------------------------------------------- extents

def test_extent_value_token_two_records():
    r = red("snmp-server user u1 grp v3 auth sha AuthPw priv aes 128 PrivPw")
    assert [(x.cls, x.extent, x.length) for x in r.redactions] == [
        ("snmpv3-auth", "value-token", 6), ("snmpv3-priv", "value-token", 6)]


def test_extent_embedded_substring_keeps_scheme_user_host_path():
    r = red(" path ftp://svc:P4ssw0rd@10.0.0.9/cfg", ("archive",))
    assert r.redactions[0].extent == "embedded-substring"
    assert r.text.startswith(" path ftp://svc:") and r.text.endswith("@10.0.0.9/cfg")


def test_extent_opaque_body_first_line_carries_total():
    doc = mask.mask_lines([
        "crypto pki certificate chain TP1",
        " certificate ca 01",
        "  3082ABCD 3082ABCD",
        "  CANARYCERTBODY",
        "  quit",
        "hostname SW1",
    ])
    texts = [m.result.text for m in doc.lines]
    assert texts[0] == "crypto pki certificate chain TP1"
    assert texts[1] == " certificate ca 01"
    assert texts[2] == "  " + token("pki-cert-body", len("3082ABCD 3082ABCD") + len("CANARYCERTBODY"))
    assert texts[3] == "  " + token("pki-cert-body", 0)
    assert texts[4] == "  quit"
    assert texts[5] == "hostname SW1"
    body = [m.result.redactions[0] for m in doc.lines[2:4]]
    assert all(r.extent == "opaque-body" and r.key.endswith("|-1") for r in body)
    assert doc.lines[1].opaque_open and doc.lines[4].opaque_close
    assert not any("CANARY" in t for t in texts)


def test_extent_span_is_default_deny_only():
    r = red("some-new-feature secret CANARY-NEW-01 more tokens")
    assert r.text == "some-new-feature secret [REDACTED unknown-secret, span]"
    assert r.redactions[0].extent == "span" and r.redactions[0].length is None


# --------------------------------------------------------------------------- directions

@pytest.mark.parametrize("line", [
    "foo-server key 7 CANARY-UNKNOWN-01 extra",
    "bar-service password CANARY-UNKNOWN-02",
    "widget token CANARY-UNKNOWN-03",
    "xyz psk CANARY-UNKNOWN-04",
])
def test_default_deny_redacts_unknown_constructs(line):
    r = red(line)
    assert "CANARY" not in r.text
    assert r.redactions[0].cls == "unknown-secret"


@pytest.mark.parametrize("line,mp", [
    ("ntp server 10.0.0.1 key 1", ()),
    ("ntp server 10.0.0.1 key 1 prefer", ()),
    ("ntp trusted-key 1", ()),
    ("ntp authenticate", ()),
    (" ip ospf authentication key-chain CHAIN1", ("interface Vlan10",)),
    ("key chain CHAIN1", ()),
    (" key 1", ("key chain CHAIN1",)),
    (" key 0A1B2C3D", ("key chain MKA-KC macsec",)),
    ("crypto ikev2 keyring KR1", ()),
    ("tacacs server TS1", ()),
    ("aaa group server tacacs+ G1", ()),
    ("snmp-server group G v3 priv", ()),
    ("snmp-server enable traps snmp authentication linkdown linkup", ()),
    ("license smart transport smart", ()),
    ("key config-key 1 something", ()),
    ("event manager applet PASSWORD-AUDIT", ()),
])
def test_reference_forms_are_not_redacted(line, mp):
    r = red(line, mp)
    assert r.text == line.rstrip() and r.redactions == ()


def test_placeholder_exact_is_exempt_and_near_misses_are_redacted():
    r = red("tacacs-server key <REPLACE-ME:tacacs-key>")
    assert r.text == "tacacs-server key <REPLACE-ME:tacacs-key>" and r.redactions == ()
    for near in ("<REPLACE-ME:tacacs-key>CANARY", "<REPLACE-ME:Tacacs Key>", "<replace-me:x>"):
        r = red(f"tacacs-server key {near}")
        assert "[REDACTED tacacs-key" in r.text or "[REDACTED unknown-secret" in r.text
        assert "CANARY" not in r.text
    assert is_placeholder("<REPLACE-ME:tacacs-key>")
    assert not is_placeholder("<REPLACE-ME:tacacs-key>CANARY")
    assert not is_placeholder("<replace-me:x>")


def test_placeholder_exemption_never_applies_to_span_or_embedded():
    r = red("foo-server key <REPLACE-ME:x>")
    assert r.redactions[0].extent == "span"
    r = red(" path ftp://svc:<REPLACE-ME:pw>@10.0.0.9/cfg", ("archive",))
    assert r.redactions[0].extent == "embedded-substring"


def test_token_spelling_all_four_forms():
    assert token("tacacs-key", 16) == "[REDACTED tacacs-key, 16 chars]"
    assert token("tacacs-key", 16, changed=True) == "[REDACTED tacacs-key, 16 chars, changed]"
    assert token("unknown-secret", None) == "[REDACTED unknown-secret, span]"
    assert token("unknown-secret", None, changed=True) == "[REDACTED unknown-secret, span, changed]"
    for t in (token("a-b", 1), token("a-b", 1, changed=True), token("x", None),
              token("x", None, changed=True)):
        assert REDACTION_RE.fullmatch(t)


def test_weak_values_become_weak_classes():
    assert red("snmp-server community public RO").redactions[0].cls == "snmp-community-weak"
    assert red("snmp-server community S3cretRO RO").redactions[0].cls == "snmp-community"
    assert red(" password 0 cisco", ("line vty 0 4",)).redactions[0].cls == "line-password-weak"
    assert red("enable password 0 cisco").redactions[0].cls == "enable-password-weak"
    # the verdict travels, the value does not
    assert "public" not in red("snmp-server community public RO").text


def test_digests_are_salted_and_never_the_value():
    r = red("snmp-server community S3cretRO RO 99")
    d = r.digests[0]
    assert re.fullmatch(r"[0-9a-f]{64}", d)
    import hashlib
    assert d != hashlib.sha256(b"S3cretRO").hexdigest()


# --------------------------------------------------------------------------- scrub

def test_scrub_passes_tool_own_product():
    assert scrub("crypto key generate rsa modulus 2048") == ()
    remediation_block = [
        "no snmp-server community <REPLACE-ME:snmp-ro-community>",
        "snmp-server group RO-GROUP v3 priv",
        "tacacs-server key <REPLACE-ME:tacacs-key>",
        "username admin privilege 15 algorithm-type scrypt secret <REPLACE-ME:local-admin-secret>",
        "enable algorithm-type scrypt secret <REPLACE-ME:enable-secret>",
        "ntp authentication-key 1 hmac-sha2-256 <REPLACE-ME:ntp-key-1>",
        "interface GigabitEthernet1/0/1",
        " spanning-tree bpduguard enable",
        "snmp-server community <TODO:community> RO",
    ]
    for line in remediation_block:
        assert scrub(line) == (), line
    baseline_sample = """hostname SW-ACCESS-01
ip domain name example.invalid
no ip http server
no service pad
enable algorithm-type scrypt secret <REPLACE-ME:enable-secret>
username admin privilege 15 algorithm-type scrypt secret <REPLACE-ME:local-admin-secret>
aaa new-model
aaa authentication login default group ISE local
line vty 0 15
 access-class MGMT-ACCESS in
 transport input ssh
crypto key generate rsa modulus 4096
ip ssh version 2
snmp-server group RO-GROUP v3 priv
snmp-server user monuser RO-GROUP v3 auth sha <REPLACE-ME:snmpv3-auth> priv aes 256 <REPLACE-ME:snmpv3-priv>
ntp authenticate
ntp authentication-key 1 hmac-sha2-256 <REPLACE-ME:ntp-key-1>
ntp trusted-key 1
ntp server 192.0.2.1 key 1
tacacs server ISE-1
 address ipv4 192.0.2.5
 key <REPLACE-ME:tacacs-key>
archive
 path flash:archive
 log config
  hidekeys
banner motd ^C
Authorized access only.
^C
interface range GigabitEthernet1/0/1 - 24
 switchport mode access
 spanning-tree portfast edge
boot system flash:packages.conf
end"""
    for line in baseline_sample.split("\n"):
        assert scrub(line) == (), line


def test_scrub_hits_raw_secret_and_never_rewrites():
    line = "snmp-server community S3cretRO RO 99"
    hits = scrub(line)
    assert hits == (mask.EgressHit("snmp-community", 2),)
    assert line == "snmp-server community S3cretRO RO 99"


@pytest.mark.parametrize("line", [
    'evidence: snmp-server community CANARY-C1 RO 99',
    '      "text": "snmp-server community CANARY-C1 RO 99",',
    '"snippet": {"text": "tacacs-server key 7 CANARY-C2"}',
    'error: enable secret 5 CANARY-C3',
    '"text": "snmp-server community \\"CANARY-C4\\" RO"',
    '  fix: crypto isakmp key CANARY-C5 address 10.0.0.1',
    ' path ftp://svc:CANARY-C6@10.0.0.9/cfg',
])
def test_scrub_detects_prefixed_and_json_embedded_leaks(line):
    assert scrub(line) != ()


def test_egress_guard_error_carries_no_content():
    e = EgressGuardError("snmp-community", 2)
    assert str(e) == "egress guard: unmasked snmp-community detected at token 2; output suppressed"
    assert e.cls == "snmp-community" and e.position == 2


def test_type7_value_plaintext_appears_nowhere():
    from ciscocheck import parser
    cfg = parser.parse("hostname SW1\nenable password 7 0822455D0A16\n"
                       "line vty 0 4\n password 7 0822455D0A16\ninterface Vlan1\n shutdown\nend\n")
    everything = "\n".join(l.text for l in cfg.lines())
    assert "0822455D0A16" not in everything
    assert "cisco" not in everything.lower()


def test_no_credential_recovery_names_in_package():
    bad = re.compile(r"(?i)(decrypt|decode|reveal|crack).*(7|type7)")
    for path in PKG.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            name = getattr(node, "name", None) or getattr(node, "attr", None) or getattr(node, "id", None)
            if isinstance(name, str):
                assert not bad.search(name), (path.name, name)


# --------------------------------------------------------------------------- named construct cases

R2_F1 = [
    ("enable password level 15 7 CANARY7-0822455D0A16", (), ["enable", "password", "level", "15", "7"]),
    ("ntp authentication-key 3 hmac-sha1 CANARY-NTP-KEY-03", (), ["3", "hmac-sha1"]),
    ("ntp authentication-key 2 hmac-sha2-256 CANARY-NTP-KEY-02 7", (), ["2", "hmac-sha2-256", "7"]),
    ("ntp authentication-key 4 cmac-aes-128 CANARY-NTP-KEY-04", (), ["4", "cmac-aes-128"]),
    (" ipv6 ospf authentication ipsec spi 500 md5 7 CANARYHEX01", ("interface Vlan10",),
     ["500", "md5", "7"]),
    (" ipv6 ospf encryption ipsec spi 501 esp aes-cbc 128 CANARYHEX02 sha1 CANARYHEX03",
     ("interface Vlan10",), ["501", "esp", "aes-cbc", "128", "sha1"]),
    (" ospfv3 1 authentication ipsec spi 502 sha1 CANARYHEX04", ("interface Vlan10",),
     ["ospfv3", "1", "502", "sha1"]),
    (" ospfv3 1 encryption ipsec spi 505 esp aes-cbc 256 CANARYHEX07 sha1 CANARYHEX08",
     ("interface Vlan10",), ["505", "aes-cbc", "256", "sha1"]),
    ("  area 0 authentication ipsec spi 503 sha1 CANARYHEX05", ("router ospfv3 1",),
     ["area", "0", "503", "sha1"]),
    ("  area 1 encryption ipsec spi 504 esp null sha1 CANARYHEX06", ("router ospfv3 1",),
     ["area", "1", "504", "null", "sha1"]),
    ("  area 2 encryption ipsec spi 506 esp aes-cbc 128 CANARYHEX09 sha1 CANARYHEX10",
     ("router ospfv3 1",), ["area", "2", "506", "aes-cbc", "128", "sha1"]),
    ("event manager environment _snmp_community CANARY-COMMUNITY-05", (),
     ["event", "manager", "environment", "_snmp_community"]),
]


@pytest.mark.parametrize("line,mp,structural", R2_F1, ids=[x[0].strip()[:34] for x in R2_F1])
def test_construct_row_grammars_match_structural_tokens(line, mp, structural):
    r = red(line, mp)
    assert "CANARY" not in r.text
    toks = tokenize(r.text)
    for s in structural:
        assert s in toks, s
    assert all(x.cls != "unknown-secret" for x in r.redactions)
    assert scrub(r.text) == ()


@pytest.mark.parametrize("vocab", sorted(mask._VOCAB))
def test_value_slot_never_binds_a_vocab_token(vocab):
    # the value slot never binds a %TYPE/%ENC/%ALG token: the row fails, default-deny catches it
    r = red(f"tacacs-server key {vocab}")
    assert all(x.cls != "tacacs-key" for x in r.redactions)
    r = red(f"snmp-server user u g v3 auth {vocab}")
    assert all(x.cls != "snmpv3-auth" for x in r.redactions)
    # and with a real value after the selector, the value (not the selector) is redacted
    r = red("ntp authentication-key 1 hmac-sha1 CANARY-X")
    assert tokenize(r.text)[3] == "hmac-sha1" and "CANARY" not in r.text


def test_construct_match_order_picks_correct_class():
    assert red("snmp-server host 10.0.0.1 version 3 priv monuser").text == \
        "snmp-server host 10.0.0.1 version 3 priv monuser"
    assert red("enable secret level 15 5 CANARYX").text == \
        "enable secret level 15 5 [REDACTED enable-secret, 7 chars]"
    assert red(" standby 1 authentication text CANARYX", ("interface Vlan10",)).text == \
        " standby 1 authentication text [REDACTED hsrp-key, 7 chars]"
    assert red("key config-key password-encrypt CANARYX").text == \
        "key config-key password-encrypt [REDACTED master-key, 7 chars]"
    assert red("license smart trust idtoken CANARYX local force").text == \
        "license smart trust idtoken [REDACTED smart-idtoken, 7 chars] local force"
    r = red("snmp-server user u1 grp v3 auth sha CANARYA priv aes 128 CANARYP")
    assert [x.cls for x in r.redactions] == ["snmpv3-auth", "snmpv3-priv"]
    # FHRP key-chain is no-value
    for fhrp in ("standby 2 authentication md5 key-chain HSRP-KC",
                 "vrrp 1 authentication md5 key-chain KC", "glbp 1 authentication md5 key-chain KC"):
        assert red(" " + fhrp, ("interface Vlan10",)).redactions == ()


def test_construct_row_order_prefers_more_specific_row():
    def idx(cls: str, first_tokens: tuple[str, ...]) -> list[int]:
        return [i for i, c in enumerate(CONSTRUCTS)
                if c.cls == cls and c.pattern[:len(first_tokens)] == first_tokens]
    assert idx("enable-password", ("enable", "password", "level"))[0] < \
        [i for i in idx("enable-password", ("enable", "password"))
         if CONSTRUCTS[i].pattern[2] != "level"][0]
    assert idx("enable-secret", ("enable", "secret", "level"))[0] < \
        [i for i in idx("enable-secret", ("enable", "secret"))
         if CONSTRUCTS[i].pattern[2] != "level"][0]
    hsrp = [i for i, c in enumerate(CONSTRUCTS) if c.cls == "hsrp-key"]
    assert [CONSTRUCTS[i].pattern[3] for i in hsrp] == ["md5", "text", "$"]
    auth = [i for i, c in enumerate(CONSTRUCTS) if c.cls == "snmpv3-auth"][0]
    priv = [i for i, c in enumerate(CONSTRUCTS) if c.cls == "snmpv3-priv"][0]
    assert auth < priv
    assert red("enable password level 15 7 CANARYX").text == \
        "enable password level 15 7 [REDACTED enable-password, 7 chars]"


MODE_DEPTH = """\
line vty 0 4
 password 7 CANARY-LINE-01
parser view NOC
 secret 5 CANARY-VIEW-01
tacacs server TS1
 address ipv4 10.0.0.5
 key 7 CANARY-TACACS-KEY-01
radius server RS1
 key 7 CANARY-RADIUS-KEY-01
 pac key 7 CANARY-PAC-01
aaa group server tacacs+ G1
 server-private 10.0.0.5 key 7 CANARY-SP-01
aaa server radius dynamic-author
 client 10.0.0.7 server-key 7 CANARY-COA-01
archive
 path ftp://svc:CANARY-URL-PW-01@10.0.0.9/cfg
kron policy-list P1
 cli copy running-config ftp://svc:CANARY-URL-PW-03@10.0.0.9/x
call-home
 http-proxy http://svc:CANARY-URL-PW-04@proxy.example.invalid:80
 profile P1
  destination address http http://svc:CANARY-URL-PW-05@ch.example.invalid/x
crypto pki trustpoint TP1
 enrollment url http://svc:CANARY-URL-PW-02@ca.example.invalid/certsrv
 password 0 CANARY-CHAL-01
ip ssh pubkey-chain
 username bob
  key-hash ssh-rsa CANARYHASH01
  key-string
   AAAACANARYSSHBODY
  quit
event manager applet A1
 action 1.0 cli command "snmp-server community CANARY-COMMUNITY-04 RO"
dot1x credentials C1
 password 0 CANARY-DOT1X-01
sip-ua
 credentials username u1 password 0 CANARY-SIP-01 realm r
pnp profile P
 transport https ipv4 10.0.0.9 password 0 CANARY-PNP-01
key chain KC1
 key 1
  key-string 7 CANARY-KC-01
router ospfv3 1
 area 0 authentication ipsec spi 503 sha1 CANARYHEX05
router eigrp NAMED
 address-family ipv4 unicast autonomous-system 1
  af-interface default
   authentication mode hmac-sha-256 0 CANARY-EIGRP-01
router isis
 area-password CANARY-ISIS-01
router bgp 65000
 neighbor 10.0.0.2 password 7 CANARY-BGP-01
crypto keyring K1
 pre-shared-key address 10.0.0.1 key CANARY-PSK-03
crypto ikev2 keyring KR1
 peer P1
  pre-shared-key local 0 CANARY-PSK-02
crypto ikev2 profile PR1
 authentication local pre-share key 0 CANARY-PSK-04
crypto pki certificate chain TP1
 certificate ca 01
  3082CANARYCERT
  quit
crypto key pubkey-chain rsa
 named-key R1
  key-string
   AAAACANARYRSA
  quit
wlan CORP 1 CORP
 security wpa psk set-key ascii 0 CANARY-WLAN-01
wireless mobility group name G
 member mac-address 0011.2233.4455 ip 10.0.0.9 key 0 CANARY-MOB-01
end
"""


def test_mode_gate_matches_at_arbitrary_nesting_depth():
    raw = MODE_DEPTH.splitlines()
    doc = mask.mask_lines(raw)
    masked = [m.result.text for m in doc.lines]
    assert not any("CANARY" in t for t in masked), [t for t in masked if "CANARY" in t]
    classes = {r.cls for m in doc.lines for r in m.result.redactions}
    for expected in ("line-password", "parser-view-secret", "tacacs-key", "radius-key",
                     "radius-pac-key", "aaa-server-key", "coa-server-key", "url-password",
                     "pki-challenge", "ssh-pubkey-hash", "ssh-pubkey-body", "eem-cli-secret",
                     "dot1x-password", "sip-password", "pnp-password", "key-chain-key",
                     "ospfv3-ipsec-key", "eigrp-key", "isis-password", "bgp-password",
                     "isakmp-psk", "ikev2-psk", "pki-cert-body", "rsa-key-body", "wlan-psk",
                     "mobility-key"):
        assert expected in classes, expected
    # no mode-gated secret fell through to default-deny
    assert "unknown-secret" not in classes
    # deep nesting: the eigrp line's mode_path has three ancestors
    eigrp = next(m for m in doc.lines if "eigrp-key" in {r.cls for r in m.result.redactions})
    assert eigrp.mode_path == ("router eigrp NAMED",
                               "address-family ipv4 unicast autonomous-system 1",
                               "af-interface default")


@pytest.mark.parametrize("line,mp", [
    (" login authentication default", ("line vty 0 4",)),
    (" authentication order dot1x mab", ("interface GigabitEthernet1/0/1",)),
    ("ip http authentication aaa", ()),
    (" address ipv4 10.0.0.5 auth-port 1812", ("radius server RS1",)),
    ("privilege exec level 15 show running-config", ()),
    ("aaa authentication login default group tacacs+ local", ()),
    ("aaa authorization exec default group tacacs+ local", ()),
    ("aaa accounting commands 15 default start-stop group tacacs+", ()),
    (" authentication port-control auto", ("interface GigabitEthernet1/0/1",)),
    (" ppp authentication chap pap", ("interface Serial0/0",)),
    ("login block-for 120 attempts 3 within 60", ()),
])
def test_exact_token_match_required_no_false_positive(line, mp):
    r = red(line, mp)
    assert r.text == line.rstrip() and r.redactions == ()


@pytest.mark.parametrize("text", [
    "No RSA/EC key generated",
    "the key is rotated",
    "a password that",
    "boot system flash:x.bin",
    " path flash:archive",
    "certificate ca 01",
    "crypto key generate rsa modulus 2048",
    "SEVERITY  CHECK          CONF  LINE  TITLE",
    "snmp-server host 192.0.2.10 version 3 priv monuser",
    " standby 2 authentication md5 key-chain HSRP-KC",
    "ntp server 10.0.0.1 key 1",
])
def test_egress_scrub_ignores_benign_prose(text):
    assert scrub(text) == ()


def test_tokenize_splits_on_whitespace_and_keeps_redaction_markers():
    masked = "snmp-server community [REDACTED snmp-community, 8 chars] RO 99"
    toks = tokenize(masked)
    assert toks == ("snmp-server", "community", "[REDACTED snmp-community, 8 chars]", "RO", "99")
    assert toks.index("RO") == 3
    assert tokenize("x [REDACTED unknown-secret, span, changed] y") == (
        "x", "[REDACTED unknown-secret, span, changed]", "y")
    assert tokenize(" path ftp://svc:[REDACTED url-password, 8 chars]@10.0.0.9/cfg") == (
        "path", "ftp://svc:[REDACTED url-password, 8 chars]@10.0.0.9/cfg")
    assert tokenize("  a   b\tc  ") == ("a", "b", "c")
    # the redaction key's arg_index and an egress hit index use the same tokenisation
    r = red("snmp-server community S3cretRO RO 99")
    assert r.redactions[0].key.endswith("|2")
    assert scrub("snmp-server community S3cretRO RO 99")[0].token_index == 2


@pytest.mark.parametrize("quoted,redacted", [
    ('"snmp-server host 10.0.0.1 version 2c CANARY-COMMUNITY-06"', True),   # construct, no trigger
    ('"standby 1 authentication text CANARYX"', True),                      # construct, no trigger
    ('"ip nhrp authentication CANARYX"', True),                             # construct, no trigger
    ('"tacacs-server key CANARYX"', True),                                   # trigger
    ('"copy running-config ftp://svc:CANARYX@10.0.0.9/cfg"', True),          # user:pw@ URL
    ('"show version"', False),
    ('"show running-config | include hostname"', False),
])
def test_eem_cli_command_masks_any_construct_shape(quoted, redacted):
    r = red(f" action 1.0 cli command {quoted}", ("event manager applet A1",))
    if redacted:
        assert r.redactions and r.redactions[0].cls == "eem-cli-secret"
        assert r.redactions[0].length == len(quoted)
        assert "CANARY" not in r.text
    else:
        assert r.redactions == () and r.text.endswith(quoted)


def test_eem_environment_variable_masks_secret_shaped_condition():
    assert red("event manager environment _snmp_community S3cret").redactions
    assert red('event manager environment q_password "S3cret value"').redactions
    assert red("event manager environment _mail_server 10.0.0.1").redactions == ()


@pytest.mark.parametrize("line,mp", [
    ("boot system flash:cat9k_iosxe.17.09.04a.SPA.bin", ()),
    ("boot system tftp://10.0.0.1/image.bin", ()),
    (" path ftp://10.0.0.9/cfg", ("archive",)),
    (" path ftp://user@10.0.0.9/cfg", ("archive",)),
    (" path flash:archive", ("archive",)),
    ("  destination address http https://tools.cisco.com/its/service/oddce/services/DDCEService",
     ("call-home", "profile CiscoTAC-1")),
])
def test_url_without_userinfo_left_unmasked(line, mp):
    r = red(line, mp)
    assert r.redactions == () and r.text == line.rstrip()
    assert scrub(line) == ()


# --------------------------------------------------------------------------- backstop rows: keyword-then-algorithm-then-value
# Masking on secret-bearing lines fails closed: a value that follows an optional
# algorithm/type selector never leaves a trailing token in clear, on ingest or on egress.

def _backstop_cases():
    """(line, mp, row index, first value-slot token index) for every ROW_CASES entry whose
    matching same-class row is an algorithm-then-value (backstop) row."""
    out = []
    for line, mp, cls in ROW_CASES:
        for i in _matching_rows(line, mp):
            c = CONSTRUCTS[i]
            if c.cls != cls or not c.backstop:
                continue
            t = mask._Toks(tokenize(line), scrub=False)
            binds, _end = mask._first_match(c.cls, mask._COMPILED[i], t, 0, line, mask._spans(line))
            slots = [b[1] for b in binds if b[0] == "val"]
            if slots:          # every same-class backstop row the line matches (incl. subsumed)
                out.append((line, mp, i, min(slots)))
    return out


BACKSTOP_CASES = _backstop_cases()
_BS_IDS = [f"{CONSTRUCTS[c[2]].cls}:{c[0].strip()[:28]}" for c in BACKSTOP_CASES]
UNKNOWN_WORDS = ["blake9", "hmac-sha-1024", "future-alg", "x", "SELECTOR9", "aes-512-xts", "11"]


def _insert(line: str, pos: int, word: str) -> str:
    indent = line[:len(line) - len(line.lstrip())]
    toks = list(tokenize(line))
    return indent + " ".join(toks[:pos] + [word] + toks[pos:])


def _canaries(line: str) -> list[str]:
    return re.findall(r"CANARY[A-Za-z0-9-]*", line)


def test_every_backstop_row_has_a_case():
    covered = {c[2] for c in BACKSTOP_CASES}
    missing = [f"{i}:{c.cls}:{c.pattern}" for i, c in enumerate(CONSTRUCTS)
               if c.backstop and i not in covered]
    assert missing == []
    # the rows the ruling names are all in the backstop set
    names = {c.cls for c in CONSTRUCTS if c.backstop}
    for cls in ("ntp-key", "key-chain-key", "ospf-md-key", "ospf-auth-key", "ospfv3-ipsec-key",
                "eigrp-key", "bgp-password", "hsrp-key", "vrrp-key", "glbp-key", "tacacs-key",
                "radius-key", "snmpv3-auth", "snmpv3-priv", "local-user-secret",
                "local-user-password", "enable-secret", "enable-password"):
        assert cls in names, cls


@pytest.mark.parametrize("line", ["ntp authentication-key 1 hmac-sha-512 S3cretX",
                                  "ntp authentication-key 1 blake9 S3cretX",
                                  "ntp authentication-key 1 blake9 S3cretX 7"])
def test_ntp_key_masks_unlisted_or_future_algorithm(line):
    r = red(line)
    assert "S3cretX" not in r.text
    assert tokenize(r.text)[:3] == ("ntp", "authentication-key", "1")
    assert scrub(r.text) == ()


def test_widened_algorithm_selector_stays_structural():
    for alg in ("hmac-sha-512", "hmac-sha2-384", "sha512", "cmac-aes-256"):
        r = red(f"ntp authentication-key 1 {alg} S3cretX 7")
        assert r.text == f"ntp authentication-key 1 {alg} [REDACTED ntp-key, 7 chars] 7"


@pytest.mark.parametrize("line,mp,row,pos", BACKSTOP_CASES, ids=_BS_IDS)
def test_unknown_selector_before_value_still_masked(line, mp, row, pos):
    shaped = _insert(line, pos, "blake9")
    r = red(shaped, mp)
    for c in _canaries(line):
        assert c not in r.text, r.text
    assert scrub(r.text) == ()


@pytest.mark.parametrize("line,mp,row,pos", BACKSTOP_CASES, ids=_BS_IDS)
def test_unexpected_trailing_token_after_value_masked(line, mp, row, pos):
    # a stray token after the whole line. The isakmp tail ends in an optional netmask slot,
    # so a bare word there is structural by that row's grammar; it is asserted separately.
    if CONSTRUCTS[row].cls == "isakmp-psk" and CONSTRUCTS[row].pattern[0] == "crypto":
        return
    r = red(line.rstrip() + " S3cretX", mp)
    assert "S3cretX" not in r.text
    for c in _canaries(line):
        assert c not in r.text


@pytest.mark.parametrize("line,mp,row,pos", BACKSTOP_CASES, ids=_BS_IDS)
def test_property_any_unknown_word_before_value_masked(line, mp, row, pos):
    for word in UNKNOWN_WORDS:
        for extra in (1, 2):
            shaped = line
            for _ in range(extra):
                shaped = _insert(shaped, pos, word)
            r = red(shaped, mp)
            for c in _canaries(line):
                assert c not in r.text, (word, extra, r.text)


@pytest.mark.parametrize("line,mp,row,pos", BACKSTOP_CASES, ids=_BS_IDS)
def test_egress_scrub_catches_the_same_backstop_shape(line, mp, row, pos):
    masked = red(line, mp).text
    assert scrub(masked) == ()                   # the tool's own masked line passes
    if CONSTRUCTS[row].ingest_only:
        return                                    # prose-unsafe rows are ingest-only (3.4.8)
    toks = list(tokenize(masked))
    first_red = next(i for i, x in enumerate(toks) if REDACTION_RE.search(x))
    leaked = " ".join(toks[:first_red + 1] + ["S3cretX"] + toks[first_red + 1:])
    assert scrub(leaked) != (), leaked
    assert scrub(f'      "text": "{leaked}",') != ()


def test_backstop_note_is_content_free():
    doc = mask.mask_lines(["hostname SW1", "ntp authentication-key 1 blake9 S3cretX"])
    assert doc.lines[1].result.text == "ntp authentication-key 1 [REDACTED ntp-key, span]"
    assert mask.Note("CSC-SELF-0004", 2, "masking backstop applied") in doc.notes
    assert not any("S3cret" in n.detail or "blake" in n.detail for n in doc.notes)


def test_legitimate_trailing_tokens_unchanged():
    assert red("crypto isakmp key MyPsk address 10.0.0.1 255.255.255.255 no-xauth").text == \
        "crypto isakmp key [REDACTED isakmp-psk, 5 chars] address 10.0.0.1 255.255.255.255 no-xauth"
    assert red("snmp-server user u g v3 auth sha AuthPw priv aes 256 PrivPw access 99").text == (
        "snmp-server user u g v3 auth sha [REDACTED snmpv3-auth, 6 chars] priv aes 256 "
        "[REDACTED snmpv3-priv, 6 chars] access 99")
    assert red(" isis password 0 IsisPw level-2", ("interface Vlan10",)).text == \
        " isis password 0 [REDACTED isis-password, 6 chars] level-2"


def test_optional_qualifier_cannot_swallow_the_value():
    # %OPT (key length) absorbing the real value was a slot-shift leak; it now fails closed
    r = red("snmp-server user u g v3 priv aes CANARYP9 S3cretX")
    assert "CANARYP9" not in r.text and "S3cretX" not in r.text
    r = red("  pre-shared-key CANARYPSK S3cretX", ("crypto ikev2 keyring KR", "peer P"))
    assert "CANARYPSK" not in r.text and "S3cretX" not in r.text
    assert scrub("snmp-server user u g v3 priv aes CANARYP9 [REDACTED snmpv3-priv, 7 chars]") != ()


def test_isakmp_tail_is_bounded():
    r = red("crypto isakmp key MyPsk address 10.0.0.1 255.255.255.255 no-xauth S3cretX")
    assert "S3cretX" not in r.text and "MyPsk" not in r.text


def test_egress_leftmost_match_and_span_rules():
    assert scrub("ap mgmtuser username u password 0 [REDACTED ap-password, 5 chars] "
                 "secret 0 [REDACTED ap-password, 5 chars]") == ()
    assert scrub(" ipv6 ospf encryption ipsec spi 257 esp aes-cbc 128 "
                 "[REDACTED ospfv3-ipsec-key, span]") == ()
    assert scrub("ntp authentication-key 1 [REDACTED ntp-key, span]") == ()


# --------------------------------------------------------------------------- shape-based masking (no command list required)
# A secret is masked because of its shape, never because a command is listed. Every
# regression case is masked at INGEST (CANARYZ absent after mask_lines) and, injected raw
# into output, is caught by scrub() both bare and JSON-embedded.

import json as _json

from ciscocheck import parser as _parser


def _ingest(lines: list[str]) -> list[str]:
    return [m.result.text for m in mask.mask_lines(lines).lines]


def _assert_both_layers(lines: list[str], *, egress: bool = True) -> list[str]:
    masked = _ingest(lines)
    assert not any("CANARYZ" in t for t in masked), masked
    if egress:
        for raw in lines:
            if "CANARYZ" in raw:
                assert scrub(raw) != (), raw
                assert scrub('      "text": ' + _json.dumps(raw) + ",") != (), raw
                assert scrub(f"          evidence: {raw.strip()}") != (), raw
    for t in masked:
        assert scrub(t) == (), t            # the tool's own masked output passes
    return masked


@pytest.mark.parametrize("line", [
    "ip dhcp snooping database ftp://svc:CANARYZ@10.0.0.9/snoop",
    "ip dhcp database ftp://svc:CANARYZ@10.0.0.9/db",
    "boot host ftp://svc:CANARYZ@10.0.0.9/host-cfg",
    "boot network ftp://svc:CANARYZ@10.0.0.9/net-cfg",
    "boot config ftp://svc:CANARYZ@10.0.0.9/cfg",
    "scripting tcl init ftp://svc:CANARYZ@10.0.0.9/init.tcl",
])
def test_url_userinfo_masked_in_unlisted_commands(line):
    masked = _assert_both_layers([line])
    assert "svc:[REDACTED url-password, 7 chars]@10.0.0.9/" in masked[0]      # username kept


def test_call_home_mail_server_url_password_masked():
    masked = _assert_both_layers(["call-home",
                                  " mail-server smtp://u:CANARYZ@mail.example.invalid priority 1"])
    assert masked[1] == " mail-server smtp://u:[REDACTED url-password, 7 chars]@mail.example.invalid priority 1"


def test_scheme_less_userinfo_masked():
    masked = _assert_both_layers(["call-home", " http-proxy svc:CANARYZ@proxy.example.invalid:8080"])
    assert masked[1] == " http-proxy svc:[REDACTED url-password, 7 chars]@proxy.example.invalid:8080"
    # the fixture's own line shape
    assert "CANARY-URL-PW-07" not in red(" http-proxy svc:CANARY-URL-PW-07@proxy.example.invalid:8080",
                                         ("call-home",)).text


@pytest.mark.parametrize("line", [
    "crypto key export rsa MYKEY pem url flash: 3des CANARYZ",
    "crypto key import rsa MYKEY pem terminal CANARYZ",
    "crypto key export rsa MYKEY pem terminal des CANARYZ",
    "crypto key import rsa MYKEY exportable pem url tftp://10.0.0.9/k CANARYZ",
    "crypto key export rsa MYKEY pem url flash: 3des CANARYZ trailing",
])
def test_crypto_key_export_import_passphrases_masked(line):
    masked = _assert_both_layers([line])
    assert masked[0].startswith("crypto key ") and "MYKEY" in masked[0]


def test_master_key_masked_under_mode_indent_and_flat():
    _assert_both_layers(["line vty 0 4", " transport input ssh",
                         " key config-key password-encrypt CANARYZ"])
    _assert_both_layers(["hostname A", "line vty 0 4", "transport input ssh",
                         "key config-key password-encrypt CANARYZ", "exit", "end"])
    _assert_both_layers(["interface Gi1/0/1", " license smart trust idtoken CANARYZ local force"])


def test_flat_global_lines_pop_to_global_and_keep_structure():
    lines = ["hostname A", "interface Gi1/0/2", "description y",
             "snmp-server host 192.0.2.10 version 2c CANARYZ",
             "line vty 0 4", "transport input ssh", "enable secret 9 CANARYZ",
             "snmp-server community public RO 99", "tacacs-server host 10.0.0.5 key 7 CANARYZ",
             "exit", "end"]
    doc = mask.mask_lines(lines)
    assert doc.nesting == "exit-driven"
    _assert_both_layers(lines)
    by_text = {m.result.text: m for m in doc.lines}
    assert by_text["snmp-server host 192.0.2.10 version 2c [REDACTED snmp-community, 7 chars]"].mode_path == ()
    assert by_text["enable secret 9 [REDACTED enable-secret, 7 chars]"].mode_path == ()
    rw = by_text["snmp-server community [REDACTED snmp-community-weak, 6 chars] RO 99"]
    assert rw.mode_path == () and rw.result.redactions[0].cls == "snmp-community-weak"
    assert by_text["tacacs-server host 10.0.0.5 key 7 [REDACTED tacacs-key, 7 chars]"].mode_path == ()
    assert by_text["transport input ssh"].mode_path == ("line vty 0 4",)
    # AC15 12: the ingest masker alone carries it through the parser too
    cfg = _parser.parse("\n".join(lines) + "\n")
    assert all("CANARYZ" not in l.text for l in cfg.lines())
    assert cfg.find_one("enable secret").parent is None


@pytest.mark.parametrize("lines", [
    ["event manager applet X", ' action 1.0 cli command "enable" pattern "assword"',
     ' action 1.1 cli command "CANARYZ"'],
    ["event manager applet X", ' action 1.1 set pw "CANARYZ"'],
    ["event manager applet X", ' action 1.1 set snmp-ro CANARYZ'],
    ["event manager environment _snmp_ro CANARYZ"],
    ["event manager environment q-comm-string CANARYZ"],
    ["event manager applet X", ' action 1.3 cli command "username bob secret 0 CANARYZ"'],
])
def test_eem_prompt_answers_and_variables_masked(lines):
    _assert_both_layers(lines)


def test_eem_benign_commands_stay_readable():
    for cmd in ('"enable"', '"show running-config | include hostname"', '"write memory"',
                '"configure terminal"'):
        r = red(f" action 1.0 cli command {cmd}", ("event manager applet X",))
        assert r.redactions == () and r.text.endswith(cmd)
    r = red(' action 1.0 cli command "enable" pattern "assword"', ("event manager applet X",))
    assert r.redactions == ()
    assert red("event manager environment _mail_server 10.0.0.1").redactions == ()


def test_egress_span_and_quoted_extent_detected():
    assert scrub("tacacs-server key 7 CANARYZ ; tacacs-server key [REDACTED tacacs-key, span]") != ()
    assert scrub("action 1.0 cli command [REDACTED eem-cli-secret, 9 chars] "
                 "snmp-server community CANARYZ RO") != ()
    # the backstop's own output still passes
    assert scrub("ntp authentication-key 1 [REDACTED ntp-key, span]") == ()


def test_malformed_snmpv3_host_is_not_exempt():
    masked = _assert_both_layers(["snmp-server host 10.0.0.1 version 2c CANARYZ version 3 priv u1"])
    assert red("snmp-server host 10.0.0.1 version 3 priv monuser").redactions == ()
    assert masked[0].startswith("snmp-server host 10.0.0.1 version 2c [REDACTED")


@pytest.mark.parametrize("line", ["snmp-server community​ CANARYZ RO",
                                  "snmp-server community／ CANARYZ",
                                  "snmp-server community CANARYZ RO",
                                  "snmp-server community\x07 CANARYZ RO"])
def test_format_and_control_characters_normalised_before_masking(line):
    _assert_both_layers([line])
    cfg = _parser.parse(f"hostname A\n{line}\ninterface Gi1/0/1\n shutdown\nend\n")
    assert all("CANARYZ" not in l.text for l in cfg.lines())
    notes = [n for n in cfg.notes if n.detail == "input normalised"]
    assert notes and notes[0].code == "CSC-SELF-0003" and notes[0].line_no == 2


def test_blob_bodies_truncated_and_inside_banner_masked():
    # ingest only: a bare certificate-body line has no construct shape for egress to detect
    _assert_both_layers(["crypto pki certificate chain TP", " certificate 01", "CANARYZAAAA",
                         "  quit"], egress=False)
    _assert_both_layers(["banner motd ^C", "crypto pki certificate chain TP", " certificate 01",
                         "  CANARYZBBBB", "  quit"], egress=False)
    _assert_both_layers(["banner motd ^C", "crypto pki certificate chain TP", " certificate 01",
                         "  CANARYZCCCC", "^C", "hostname A"], egress=False)


# ---- property: each new class, 5 unrelated heads x 3 modes x indent/flat

_MODES = [None, "interface GigabitEthernet1/0/1", "line vty 0 4"]
_HEADS = ["description uplink to core", "shutdown", "logging synchronous", "exec-timeout 5 0",
          "no ip redirects"]
_URL_HEADS = ["ip dhcp snooping database", "boot host", "scripting tcl init", "description",
              "archive-helper source"]
_SHAPES = {
    "url-password": [f"{h} ftp://svc:CANARYZ@10.0.0.9/x" for h in _URL_HEADS],
    "url-password-bare": [f"{h} svc:CANARYZ@host.example.invalid:8080" for h in _URL_HEADS],
    "crypto-key-passphrase": ["crypto key export rsa K pem terminal 3des CANARYZ",
                              "crypto key import rsa K pem terminal CANARYZ"],
    "eem-cli-secret": ['action 1.1 cli command "CANARYZ"'],
    "eem-env-secret": ['action 1.2 set pw "CANARYZ"', "event manager environment _snmp_ro CANARYZ"],
    "master-key": ["key config-key password-encrypt CANARYZ"],
}


def _contexts(secret: str):
    for mode in _MODES:
        for head in _HEADS:
            body = [head, secret]
            indent = ([mode] if mode else []) + [(" " if mode else "") + x for x in body]
            flat = ([mode] if mode else []) + body + ["exit", "end"]
            if not mode:
                flat = ["interface Gi1/0/9"] + body + ["exit", "end"]   # a flat document
            yield mode, head, indent
            yield mode, head, flat


@pytest.mark.parametrize("cls", sorted(_SHAPES))
def test_property_new_secret_classes_never_survive_ingest(cls):
    checked = 0
    for secret in _SHAPES[cls]:
        for mode, head, lines in _contexts(secret):
            masked = _ingest(lines)
            assert not any("CANARYZ" in t for t in masked), (cls, mode, head, lines, masked)
            checked += 1
            assert scrub(secret) != () and scrub(_json.dumps({"text": secret})) != ()
    assert checked >= 30


def test_normalise_keeps_line_breaks():
    # a multi-line string handed to scrub() must not be glued into one line by item 7
    assert mask.normalise("a\nb\r\nc\u200bd\x07e\tf") == "a\nb\r\ncde\tf"
    assert scrub("! a comment line\ntacacs-server key 7 CANARYZ\n! another") != ()


# --------------------------------------------------------------------------- logical-line scanning across JSON/SARIF escapes
# An escaped line break inside JSON/SARIF text is a logical line break: each logical line is
# scanned on its own, exactly as table output is. Nothing is exempted by the change.

_R4_OWN = ["no enable password", "enable algorithm-type sha256 secret <REPLACE-ME:enable-secret>"]


def test_multiline_remediation_in_json_passes_scrub():
    joined = "\n".join(_R4_OWN)
    assert scrub(_json.dumps({"text": joined})) == ()
    assert scrub('      "help": {"text": ' + _json.dumps(joined) + "},") == ()
    assert scrub(_json.dumps(_json.dumps(joined))) == ()          # doubly escaped


@pytest.mark.parametrize("leak", [
    "snmp-server community CANARYX\nno enable password",           # before an escaped \n
    "no enable password\ntacacs-server key 7 CANARYX",             # after an escaped \n
    "enable secret 5 CANARYX",                                     # glued to the closing quote
    'snmp-server community "CANARYX" RO',                          # inside escaped quotes
    "no enable password\nenable secret 5 CANARYX\n",               # glued to a trailing \n
    "crypto isakmp key CANARYX address 10.0.0.1\r\nend",           # CRLF
])
def test_raw_secret_glued_to_json_punctuation_still_hits(leak):
    for rendered in (_json.dumps({"text": leak}), '"help": ' + _json.dumps(leak) + ",",
                     _json.dumps(_json.dumps(leak)), leak):
        assert scrub(rendered) != (), rendered


def test_token_indices_count_across_logical_lines():
    hits = scrub("hostname A\nsnmp-server community CANARYX RO")
    assert hits == (mask.EgressHit("snmp-community", 4),)


# --------------------------------------------------------------------------- literal backslash-n between keyword and value
# scrub() runs a LOGICAL (line-split) scan and a PHYSICAL (unsplit) scan; a hit in either one
# fails the run, so a keyword and a value joined by a literal backslash-n are still caught.

_BS = chr(92)


@pytest.mark.parametrize("raw", [
    "enable password" + _BS + "nZQXFAKE05",                 # literal backslash-n repro
    " description enable secret" + _BS + "nZQXFAKE06",      # variant
    "snmp-server community" + _BS + "rZQXFAKE07",           # variant, backslash-r
    "tacacs-server key 7" + _BS + "nZQXFAKE08",
    "crypto isakmp key" + _BS + "nZQXFAKE09 address 10.0.0.1",
])
def test_literal_backslash_n_between_keyword_and_value_hits(raw):
    for rendered in (raw,                                            # table / diff table
                     "  - " + raw.strip(),                            # diff line
                     _json.dumps({"text": raw}),                      # JSON (escaped backslash)
                     '      "text": ' + _json.dumps(raw) + ",",
                     _json.dumps(_json.dumps(raw))):                  # doubly escaped
        assert scrub(rendered) != (), rendered


def test_multiline_remediation_still_passes_after_logical_split():
    joined = "no enable password\nenable algorithm-type sha256 secret <REPLACE-ME:enable-secret>"
    assert scrub(_json.dumps({"text": joined})) == ()
    assert scrub('      "help": {"text": ' + _json.dumps(joined) + "},") == ()


def test_physical_scan_carve_out_is_narrow():
    # The one physical-pass carve-out: a value slot that starts right after a break AND is a
    # command-head word is the next logical line's command, and the logical pass scans it.
    assert scrub("enable password" + _BS + "nenable") == ()
    # a non-head word in the same position is reported
    assert scrub("enable password" + _BS + "nZQXFAKE10") != ()
    # a raw value later on the next logical line is still found by the logical pass
    assert scrub("no enable password\ntacacs-server key 7 ZQXFAKE11") != ()
    assert scrub(_json.dumps({"t": "no enable password\nenable secret 5 ZQXFAKE12"})) != ()


# --------------------------------------------------------------------------- shape-based rules catch trigger-less secrets
# The table is an optimisation: shape-based rules catch trigger-less secrets in commands the
# table does not list. Every regression case here: absent after mask_lines, and the
# raw form is a scrub() hit bare and JSON-embedded.

def _sec_both_layers(lines: list[str]) -> list[str]:
    masked = _ingest(lines)
    assert not any("ZQXFAKE" in t for t in masked), masked
    for raw in lines:
        if "ZQXFAKE" in raw:
            assert scrub(raw) != (), raw
            assert scrub('      "text": ' + _json.dumps(raw) + ",") != (), raw
    for t in masked:
        assert scrub(t) == (), t
    return masked


SEC_REPROS = {
    "f1_ospf_virtual_link_md5": ["router ospf 1",
                                 " area 1 virtual-link 10.0.0.1 message-digest-key 1 md5 ZQXFAKE01"],
    "f1_ospf_virtual_link_md5_type7": ["router ospf 1",
                                       " area 1 virtual-link 10.0.0.1 message-digest-key 1 md5 7 ZQXFAKE02"],
    "f1_ospf_sham_link": ["router ospf 1",
                          " area 1 sham-link 10.0.0.1 10.0.0.2 message-digest-key 1 md5 ZQXFAKE03"],
    "f1_ospfv3_virtual_link_ipsec": ["router ospfv3 1",
                                     " area 1 virtual-link 10.0.0.1 authentication ipsec spi 500 md5 ZQXFAKE04"],
    "f2_sap_pmk": ["interface TenGigabitEthernet1/1/1", " cts manual",
                   "  sap pmk ZQXFAKE06 mode-list gcm-encrypt"],
    "f3_pki_export_pem": ["crypto pki export TP pem terminal 3des ZQXFAKE11"],
    "f3_pki_export_pkcs12": ["crypto pki export TP pkcs12 tftp://192.0.2.1/tp.p12 ZQXFAKE12"],
    "f3_pki_import_pkcs12": ["crypto pki import TP pkcs12 tftp://192.0.2.1/tp.p12 ZQXFAKE13"],
    "f4_teagent_token": ["app-hosting appid teagent", " app-resource docker",
                         '  run-opts 1 "-e TEAGENT_ACCOUNT_TOKEN=ZQXFAKE18"'],
    "f4_env_password": ['  run-opts 1 "--env MYSQL_ROOT_PASSWORD=ZQXFAKE19"'],
    "f5_energywise_domain": ["energywise domain D security shared-secret 0 ZQXFAKE07 protocol udp port 43440"],
    "f5_energywise_ntp": ["energywise domain D security ntp-shared-secret 7 ZQXFAKE08"],
    "f5_energywise_management": ["energywise management security shared-secret 0 ZQXFAKE09 port 43440"],
    "f5_energywise_endpoint": ["energywise endpoint security shared-secret 0 ZQXFAKE10"],
    "f6_combining_mark": ["snmp-server communitý ZQXFAKE35 RO"],
    "f10_pubkey_exit": ["ip ssh pubkey-chain", " username admin", "  key-string",
                        "   AAAAB3ZQXFAKEKEY", "  exit", "snmp-server community ZQXFAKE36 RO", "end"],
    "n11_ospfv3_af": ["interface Vlan10", " ospfv3 1 ipv4 authentication ipsec spi 500 sha1 ZQXFAKE05"],
}


@pytest.mark.parametrize("name", sorted(SEC_REPROS))
def test_shape_based_leak_repros_masked_and_scrubbed(name):
    lines = SEC_REPROS[name]
    if name == "f10_pubkey_exit":
        masked = _ingest(lines)                 # the key body is public-key data: ingest check
        assert not any("ZQXFAKE" in t for t in masked)
        assert masked[5] == "snmp-server community [REDACTED snmp-community, 9 chars] RO"
        assert masked[4] == "  exit"            # the body closed on `exit`, not at EOF
        assert not any(n.code == "CSC-SELF-0005" for n in mask.mask_lines(lines).notes)
        return
    _sec_both_layers(lines)


def test_structure_kept_by_specific_construct_rows():
    assert red(" area 1 virtual-link 10.0.0.1 message-digest-key 1 md5 7 ZQXFAKE02",
               ("router ospf 1",)).text == \
        " area 1 virtual-link 10.0.0.1 message-digest-key 1 md5 7 [REDACTED ospf-md-key, 9 chars]"
    assert red("  sap pmk ZQXFAKE06 mode-list gcm-encrypt").text == \
        "  sap pmk [REDACTED sap-pmk, 9 chars] mode-list gcm-encrypt"
    assert red("energywise domain D security shared-secret 0 ZQXFAKE07 protocol udp port 43440").text == \
        "energywise domain D security shared-secret 0 [REDACTED energywise-secret, 9 chars] protocol udp port 43440"
    assert red("crypto pki import TP certificate").text.startswith("crypto pki import TP [REDACTED")


def test_pubkey_body_closes_on_dedent_but_not_in_flat_input():
    doc = mask.mask_lines(["ip ssh pubkey-chain", " username a", "  key-string", "   AAAAZQXFAKE1",
                           " username b", "  key-hash ssh-rsa ZQXFAKE2HASH", "end"])
    texts = [m.result.text for m in doc.lines]
    assert texts[4] == " username b" and "ZQXFAKE" not in "".join(texts)
    flat = mask.mask_lines(["ip ssh pubkey-chain", "username a", "key-string", "AAAAZQXFAKE1",
                            "hostname x"])
    assert "ZQXFAKE" not in "".join(m.result.text for m in flat.lines)


# ---- legitimate structure stays readable (over-redaction guard)

STRUCTURE = [
    ("spanning-tree mode rapid-pvst", ()),
    ("ip ssh version 2", ()),
    ("crypto key generate rsa modulus 2048", ()),
    ("ntp authenticate", ()),
    (" encryption aes 256", ("crypto isakmp policy 10",)),
    (" hash sha256", ("crypto isakmp policy 10",)),
    (" hash md5", ("crypto isakmp policy 10",)),
    ("ip ssh server algorithm encryption aes256-gcm aes256-ctr aes128-ctr", ()),
    ("ip ssh server algorithm mac hmac-sha2-512 hmac-sha2-256", ()),
    (" standby 1 authentication md5 key-chain HSRP-KC", ("interface Vlan10",)),
    (" hash sha256", ("crypto pki trustpoint TP",)),
    (" integrity sha384 sha256", ("crypto ikev2 proposal P",)),
    (" encryption aes-cbc-256", ("crypto ikev2 proposal P",)),
    ("crypto ipsec transform-set TS esp-aes 256 esp-sha256-hmac", ()),
    ("  cryptographic-algorithm hmac-sha-256", ("key chain KC", "key 1")),
    ("snmp-server host 10.0.0.1 version 3 priv USER01", ()),
    ("snmp-server group G v3 priv", ()),
    ("mka pre-shared-key key-chain KC", ()),
    ("! generated by gen_baseline.py from spec sha256 " + "ab" * 32, ()),
    (" address ipv4 10.0.0.5 auth-port 1812 acct-port 1813", ("radius server R",)),
]


@pytest.mark.parametrize("line,mp", STRUCTURE, ids=[x[0].strip()[:40] for x in STRUCTURE])
def test_legitimate_structure_is_not_redacted(line, mp):
    r = red(line, mp)
    assert r.text == line.rstrip() and r.redactions == ()
    assert scrub(line) == ()
    assert scrub(_json.dumps({"text": line})) == ()


def test_algorithm_name_followed_by_structure_or_value():
    # md5 / sha256 followed by a keyword is structural; followed by a value it is a secret
    assert red("frobnicate md5 key-chain KC").redactions == ()
    assert red("frobnicate sha256 mode fast").redactions == ()
    r = red("frobnicate sha256 ZQXFAKE77 mode fast")
    assert r.text == "frobnicate sha256 [REDACTED alg-secret, 9 chars] mode fast"
    r = red("frobnicate md5 7 ZQXFAKE78")
    assert r.text == "frobnicate md5 7 [REDACTED alg-secret, 9 chars]"


def test_egress_scrub_passes_benign_security_prose():
    for prose in ("NTP authentication key uses MD5 rather than SHA1/SHA2",
                  "a token that is", "the shared-secret field must be set on the device",
                  "a type-8/9 (PBKDF2/scrypt) hash resists offline attack",
                  "Remove the passphrase from the change script"):
        assert scrub(prose) == (), prose


# ---- property tests: each generic rule, 8 invented heads x 3 modes x indent/flat

_INVENTED = ["frobnicate", "zz-agent config", "widget-svc set", "acme-feature 3",
             "telemetry-x profile P", "oddball", "newproto 5 opt", "vendor-ext tool run"]
_P_MODES = [None, "interface GigabitEthernet1/0/1", "line vty 0 4"]
_GENERIC = {
    "alg-trigger": ["{h} md5 ZQXFAKE91", "{h} sha256 7 ZQXFAKE92", "{h} 3des ZQXFAKE93",
                    "{h} aes256-gcm ZQXFAKE94", "{h} hmac-sha-512 ZQXFAKE95"],
    "trigger-vocabulary": ["{h} pmk ZQXFAKE81", "{h} passphrase ZQXFAKE82",
                           "{h} shared-secret ZQXFAKE83", "{h} message-digest-key ZQXFAKE84",
                           "{h} db_password ZQXFAKE85", "{h} ACCOUNT-TOKEN ZQXFAKE86"],
    "name-equals-value": ["{h} API_TOKEN=ZQXFAKE71", '{h} "--env DB_PASSWORD=ZQXFAKE72"',
                          "{h} snmp_secret=ZQXFAKE73", "{h} -e AUTH_KEY=ZQXFAKE74"],
}


def _p_contexts(line: str):
    for mode in _P_MODES:
        indent = ([mode] if mode else []) + [(" " if mode else "") + line]
        flat = ([mode] if mode else ["interface Gi1/0/9"]) + [line, "exit", "end"]
        yield mode, indent
        yield mode, flat


@pytest.mark.parametrize("rule", sorted(_GENERIC))
def test_property_generic_rule_never_leaks(rule):
    checked = 0
    for template in _GENERIC[rule]:
        for head in _INVENTED:
            line = template.format(h=head)
            for mode, lines in _p_contexts(line):
                masked = _ingest(lines)
                assert not any("ZQXFAKE" in t for t in masked), (rule, mode, lines, masked)
                checked += 1
            assert scrub(line) != (), line
            assert scrub(_json.dumps({"text": line})) != (), line
    assert checked == len(_GENERIC[rule]) * len(_INVENTED) * 6


# --------------------------------------------------------------------------- comment and pseudo-comment lines
# Comment lines (`!`, or `#` pseudo-comments) fail closed: keep the first trigger word (or the
# NAME of a secret NAME=VALUE), redact the rest of the line as one `[REDACTED comment, N chars]`.
# Egress: on a comment line, a trigger followed by anything but a redaction token or EOL is a
# hit. The algorithm trigger stays off comments (gen_baseline's sha256 header is kept), and
# redaction tokens / exact placeholders are inert (gen_baseline's `!   <REPLACE-ME:...>`).

def _comment_fail_closed(line: str, secret: str) -> str:
    masked = _ingest([line])[0]
    assert secret not in masked, masked
    assert "[REDACTED comment, " in masked
    for rendered in (line, _json.dumps({"text": line}), "   12  " + line,
                     '      "text": ' + _json.dumps(line) + ","):
        assert scrub(rendered) != (), rendered
    for rendered in (masked, "   12  " + masked, _json.dumps({"text": masked})):
        assert scrub(rendered) == (), rendered
    return masked


ITEM11_REPROS = [
    # comment-leak regression cases
    ("! password: ZQXFAKEC01", "ZQXFAKEC01"),
    ("! Password: ZQXFAKEC02", "ZQXFAKEC02"),
    ("! db_password=ZQXFAKEC07", "ZQXFAKEC07"),
    ("! API_KEY=ZQXFAKEC08", "ZQXFAKEC08"),
    ("! token=ZQXFAKEC09", "ZQXFAKEC09"),
    ("! secret ZQXFAKEC03", "ZQXFAKEC03"),
    ("! key ZQXFAKEC04", "ZQXFAKEC04"),
    ("! snmp-server community ZQXFAKEC05 RO", "ZQXFAKEC05"),
    # additional comment-leak regression cases
    ("! PSK -> ZQXFAKED01", "ZQXFAKED01"),
    ("! `password` rotation schedule ZQXFAKED02", "ZQXFAKED02"),
    # further variants
    ("# password: ZQXFAKED03", "ZQXFAKED03"),
    ("! password： ZQXFAKED04", "ZQXFAKED04"),               # full-width colon
    ("! password:\tZQXFAKED05", "ZQXFAKED05"),                   # tab
    ("! the password letmein", "letmein"),
    ("! the psk banana", "banana"),
    ("! password for admin is ZQXFAKED06", "ZQXFAKED06"),
    ("! note - community string ZQXFAKED07", "ZQXFAKED07"),
    ("! passwd ZQXFAKED08", "ZQXFAKED08"),
    ("! the key: ZQXFAKED09", "ZQXFAKED09"),
    ("! Pre-Shared-Key=ZQXFAKED10", "ZQXFAKED10"),
    ("! secret (ZQXFAKED11)", "ZQXFAKED11"),
    ('! key "ZQXFAKED12"', "ZQXFAKED12"),
    ("! TOKEN:ZQXFAKED13", "ZQXFAKED13"),
    ("# API_KEY=ZQXFAKED14", "ZQXFAKED14"),
    ("# password ZQXFAKED15", "ZQXFAKED15"),
    ("! DB_PASS=ZQXFAKED16", "ZQXFAKED16"),                      # secret NAME, pass segment
    ("!password:ZQXFAKED17", "ZQXFAKED17"),
    ("! [password] ZQXFAKED18", "ZQXFAKED18"),                   # brackets
    ("! 'Secret': ZQXFAKED19.", "ZQXFAKED19"),                   # quotes, mixed case, punctuation
    ("! PASSWORD = ZQXFAKED20, rotated", "ZQXFAKED20"),
    ("! the enable secret is ZQXFAKED21", "ZQXFAKED21"),
]


@pytest.mark.parametrize("line,secret", ITEM11_REPROS, ids=[x[0][:30] for x in ITEM11_REPROS])
def test_comment_leak_repros_fail_closed(line, secret):
    _comment_fail_closed(line, secret)


@pytest.mark.parametrize("line,expected", [
    ("! PSK -> ZQXFAKED01", "! PSK [REDACTED comment, 14 chars]"),
    ("! the password letmein", "! the password [REDACTED comment, 8 chars]"),
    ("! API_KEY=ZQXFAKED14", "! API_KEY[REDACTED comment, 11 chars]"),
    ("# password: ZQXFAKED03", "# password[REDACTED comment, 12 chars]"),
])
def test_comment_trigger_word_stays_visible(line, expected):
    assert _ingest([line])[0] == expected


# Expected over-redaction of comment prose (accepted by the ruling), pinned exactly.
@pytest.mark.parametrize("line,expected", [
    ("! rotate the password quarterly", "! rotate the password [REDACTED comment, 10 chars]"),
    ("! key-chain KC used for HSRP", "! key[REDACTED comment, 23 chars]"),
    ("! community meetings are on Tuesdays", "! community [REDACTED comment, 25 chars]"),
    ("! Every secret-shaped value is from the canary vocabulary",
     "! Every secret[REDACTED comment, 43 chars]"),
])
def test_comment_expected_prose_over_redaction(line, expected):
    assert _ingest([line])[0] == expected
    assert scrub(expected) == ()


@pytest.mark.parametrize("line", [
    "! generated by gen_baseline.py (skill 1.0.0) from spec sha256 " + "ab" * 32,
    "!   <REPLACE-ME:tacacs-key>",
    "!   <REPLACE-ME:local-admin-secret>",
    "! Fill every REPLACE-ME placeholder on the device before this configuration is used.",
    "! Unfilled placeholders. Set each one on the device, from the organisation's",
    "! platform iosxe, role access",
    "!",
    "#### garbage ####",
    "! cisco-switch-config hardened baseline for ACC-SW-01",
])
def test_comment_lines_without_a_trigger_stay_intact(line):
    assert _ingest([line])[0] == line
    assert scrub(line) == () and scrub(_json.dumps([line])) == ()


def test_algorithm_trigger_stays_off_comments():
    header = "! generated by gen_baseline.py (skill 1.0.0) from spec sha256 " + "0f" * 32
    assert _ingest([header])[0] == header
    assert scrub(header) == ()


def test_url_before_the_comment_trigger_is_still_masked():
    masked = _ingest(["! pulled from ftp://svc:ZQXFAKEU1@10.0.0.9/c then password ZQXFAKEU2"])[0]
    assert "ZQXFAKEU" not in masked
    assert "ftp://svc:[REDACTED url-password, 9 chars]@10.0.0.9/c" in masked


def test_comment_redaction_is_not_reported_as_a_backstop():
    doc = mask.mask_lines(["hostname A", "! rotate the password quarterly", "end"])
    assert not any(n.detail == "masking backstop applied" for n in doc.notes)


# --------------------------------------------------------------------------- non-ASCII comments and free-text fields
# Non-ASCII in a comment or free-text body redacts the whole body (no confusables table);
# free-text fields (description, remark, access-list N remark, macro description, EEM comment,
# alias bodies, snmp-server location/contact) get the item-11 fail-closed rule, keyword visible.

def _ft_both_layers(lines: list[str], secret: str) -> str:
    masked = _ingest(lines)
    assert not any(secret in t for t in masked), masked
    raw = lines[-1]
    for rendered in (raw, _json.dumps({"text": raw}), "   12  " + raw,
                     "added           -    12  + " + raw.strip(),
                     "          evidence: " + raw.strip()):
        assert scrub(rendered) != (), rendered
    for t in masked:
        for rendered in (t, "   12  " + t, _json.dumps({"text": t})):
            assert scrub(rendered) == (), rendered
    return masked[-1]


@pytest.mark.parametrize("line,secret", [
    ("! pаssword: ZQXFAKEE01", "ZQXFAKEE01"),             # Cyrillic a
    ("! passwοrd: ZQXFAKEE02", "ZQXFAKEE02"),             # Greek omicron
    ("! sеcret ZQXFAKEE03", "ZQXFAKEE03"),                # Cyrillic e
    ("! tоken=ZQXFAKEE04", "ZQXFAKEE04"),                 # Cyrillic o
    ("! рsk ZQXFAKEE05", "ZQXFAKEE05"),                   # Cyrillic er (looks like p)
    ("! сommunity ZQXFAKEE06", "ZQXFAKEE06"),             # Cyrillic es (looks like c)
    ("# kеy ZQXFAKEE14", "ZQXFAKEE14"),                   # `#` pseudo-comment
])
def test_homoglyph_comment_body_redacted_whole(line, secret):
    out = _ft_both_layers([line], secret)
    assert out.startswith(line[0] + " [REDACTED comment, ")


@pytest.mark.parametrize("lines,secret,expected", [
    (["interface Gi1/0/1", " description password ZQXFAKEE07"], "ZQXFAKEE07",
     " description password [REDACTED free-text, 11 chars]"),
    (["ip access-list extended MGMT", " 10 remark psk=ZQXFAKEE08"], "ZQXFAKEE08",
     " 10 remark psk[REDACTED free-text, 11 chars]"),
    (["ip access-list extended MGMT", " remark café ZQXFAKEE09"], "ZQXFAKEE09",
     " remark [REDACTED free-text, 16 chars]"),                     # non-ASCII ACL remark
    (["access-list 10 remark key ZQXFAKEE10"], "ZQXFAKEE10",
     "access-list 10 remark key [REDACTED free-text, 11 chars]"),
    (["alias exec sw username bob secret ZQXFAKEE11"], "ZQXFAKEE11",
     "alias exec sw username bob secret [REDACTED free-text, 11 chars]"),
    (["snmp-server location closet key ZQXFAKEE12"], "ZQXFAKEE12",
     "snmp-server location closet key [REDACTED free-text, 11 chars]"),
    (["macro description token: ZQXFAKEE15"], "ZQXFAKEE15",
     "macro description token[REDACTED free-text, 12 chars]"),
    (["event manager applet X", " comment the pаssword ZQXFAKEE16"], "ZQXFAKEE16",
     " comment [REDACTED free-text, 24 chars]"),
    (["interface Gi1/0/1", " description md5 ZQXFAKEE13"], "ZQXFAKEE13",
     " description md5 [REDACTED alg-secret, 10 chars]"),          # generic rules still apply
])
def test_free_text_fields_fail_closed(lines, secret, expected):
    assert _ft_both_layers(lines, secret) == expected


@pytest.mark.parametrize("lines", [
    ["interface Gi1/0/1", " description Uplink to core"],
    ["interface Gi1/0/1", " description to-dist-1"],
    ["ip access-list extended MGMT", " remark permit mgmt"],
    ["interface Gi1/0/1", " description Printer on floor 3"],
    ["interface Vlan99", " description OOB mgmt"],
    ["snmp-server location Building 4, closet 2"],
    ["! generated by gen_baseline.py (skill 1.0.0) from spec sha256 " + "ab" * 32],
])
def test_ascii_free_text_without_trigger_stays_readable(lines):
    masked = _ingest(lines)
    assert masked == [l.rstrip() for l in lines]
    for t in masked:
        assert scrub(t) == () and scrub("   12  " + t) == ()


def test_roles_still_read_descriptions_after_masking():
    from ciscocheck import parser as _p
    cfg = _p.parse("hostname SW1\ninterface Gi1/0/1\n description Uplink to core\n"
                   " switchport mode trunk\nend\n")
    assert cfg.interface("Gi1/0/1").role == "uplink"
