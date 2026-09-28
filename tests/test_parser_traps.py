"""Parser trap rows (a), (b), (b2), (c)-(i), inline fixtures."""
from __future__ import annotations

import pytest

from ciscocheck import parser
from ciscocheck.parser import NotACiscoConfigError

TAIL = "\n".join(f"interface GigabitEthernet1/0/{i}\n switchport mode access" for i in range(1, 11))


# ---------------------------------------------------------------- (a) banners

def test_a_single_line_banner_closes_on_same_line():
    text = ("hostname SW1\nbanner motd ^CUnauthorized access is prohibited^C\n" + TAIL + "\nend\n")
    cfg = parser.parse(text)
    banner = cfg.find_one("banner motd")
    assert banner.line.kind == "opaque-open"
    lines = cfg.lines()
    # a line 20 lines after the banner is still ordinary configuration
    later = lines[banner.line.line_no - 1 + 20]
    assert later.kind == "command"
    assert len(cfg.interfaces()) == 10
    assert not any(n.code == "CSC-SELF-0005" for n in cfg.notes)


def test_a_multi_line_banner_with_password_in_body():
    text = ("hostname SW1\nbanner login ^C\nWarning: enable password cisco is not a config line\n"
            "Contact NOC #4711\n^C\nline vty 0 4\n transport input ssh\nend\n")
    cfg = parser.parse(text)
    body = [l for l in cfg.lines() if l.kind == "opaque"]
    assert [b.text for b in body][1] == "Contact NOC #4711"          # not a prompt echo
    assert "cisco" not in body[0].text                                # masked like any line
    close = next(l for l in cfg.lines() if l.kind == "opaque-close")
    assert close.text == "^C"
    # banner body is never structurally parsed: no `enable password` command node exists
    assert cfg.find("enable password") == ()
    assert cfg.find_one("transport input ssh").mode_path == ("line vty 0 4",)
    # the body is reachable for CSC-VTY-0011 through the banner node
    opener = cfg.find_one("banner login")
    assert len(cfg.children_of(opener)) == 3


def test_a_ctrl_c_byte_delimiter_and_mixed_closer():
    cfg = parser.parse("hostname SW1\nbanner motd \x03\nAuthorized use only\n^C\n" + TAIL + "\nend\n")
    assert len(cfg.interfaces()) == 10
    cfg = parser.parse("hostname SW1\nbanner exec #Hello#\n" + TAIL + "\nend\n")
    assert len(cfg.interfaces()) == 10


def test_a_unterminated_banner_closes_at_eof_with_note():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n shutdown\nbanner motd ^C\n"
                       "snmp-server community CANARY-BANNER-02 RO\nstill banner\n")
    notes = [n for n in cfg.notes if n.code == "CSC-SELF-0005"]
    assert notes and notes[0].detail == "unterminated banner block opened at line 4"
    assert all("CANARY" not in l.text for l in cfg.lines())


# ---------------------------------------------------------------- (b) blobs

def test_b_certificate_chain_through_quit():
    text = ("hostname SW1\ncrypto pki certificate chain TP-self-signed-1\n"
            " certificate self-signed 01\n  30820229 30820192 A0030201\n  CANARYCERT 0D06092A\n"
            "  \tquit\ncrypto key pubkey-chain rsa\n named-key R1\n  key-string\n   AAAACANARYRSA\n"
            "  quit\ninterface Gi1/0/1\n shutdown\nend\n")
    cfg = parser.parse(text)
    assert all("CANARY" not in l.text for l in cfg.lines())
    body = [l for l in cfg.lines() if l.kind == "opaque"]
    assert len(body) == 3
    assert body[0].redactions[0].extent == "opaque-body"
    assert body[1].redactions[0].length == 0
    assert cfg.find_one("certificate self-signed 01").line.kind == "opaque-open"
    assert cfg.interface("Gi1/0/1") is not None
    assert not any(n.code == "CSC-SELF-0005" for n in cfg.notes)


def test_b_truncated_chain_closes_with_note():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n shutdown\n"
                       "crypto pki certificate chain TP1\n certificate ca 01\n  3082CANARYTRUNC\n")
    assert any(n.code == "CSC-SELF-0005" and "blob" in n.detail for n in cfg.notes)
    assert all("CANARY" not in l.text for l in cfg.lines())


def test_b_truncated_chain_closes_at_eof():
    # the shallower-line early close is withdrawn; a truncated body runs to EOF (trap row b),
    # so what follows it is opaque, masked and never parsed.
    cfg = parser.parse("hostname SW1\ncrypto pki certificate chain TP1\n certificate ca 01\n"
                       "  3082CANARYTRUNC\nCANARYZAAAA\ninterface Gi1/0/1\n shutdown\nend\n")
    assert cfg.interface("Gi1/0/1") is None
    assert all("CANARY" not in l.text for l in cfg.lines())
    assert any(n.code == "CSC-SELF-0005" and "blob" in n.detail for n in cfg.notes)


def test_b_ssh_pubkey_chain_key_string():
    cfg = parser.parse("hostname SW1\nip ssh pubkey-chain\n username bob\n  key-string\n"
                       "   AAAAB3NzaCANARYSSH\n  quit\n username amy\n  key-hash ssh-rsa CANARYHASH\n"
                       "interface Gi1/0/1\n shutdown\nend\n")
    assert all("CANARY" not in l.text for l in cfg.lines())
    assert cfg.find_one("username amy").mode_path == ("ip ssh pubkey-chain",)


# ---------------------------------------------------------------- (b2) macro payloads

def test_b2_macro_body_is_opaque():
    cfg = parser.parse("hostname SW1\nmacro name EdgePort\n switchport mode access\n"
                       " snmp-server community CANARY-MACRO-01 RO\n@\ninterface Gi1/0/1\n"
                       " switchport mode trunk\nend\n")
    # the macro body is not a phantom node for cfg.find(), and `@` is not a command node
    assert len(cfg.find("switchport mode access")) == 0
    assert len(cfg.find("switchport mode trunk")) == 1
    assert not any(n.code == "CSC-SELF-0004" for n in cfg.notes)
    assert all("CANARY" not in l.text for l in cfg.lines())
    assert next(l for l in cfg.lines() if l.text == "@").kind == "opaque-close"


def test_b2_unterminated_macro():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n shutdown\nmacro name M\n switchport\n")
    assert any(n.detail == "unterminated macro block opened at line 4" for n in cfg.notes)


# ---------------------------------------------------------------- (c) ranges

@pytest.mark.parametrize("spec,count", [
    ("GigabitEthernet1/0/1 - 48", 48),
    ("Gi1/0/1-48", 48),
    ("Gi1/0/1 -48", 48),
    ("Gi1/0/1 - 4, Gi1/0/10 - 12", 7),
    ("Gi1/0/1 - Gi1/0/4", 4),
    ("Te1/1/1 - 2, Gi1/0/5", 3),
    ("Port-channel1 - 3", 3),
])
def test_c_range_expansion(spec, count):
    cfg = parser.parse(f"hostname SW1\ninterface range {spec}\n switchport mode access\nend\n")
    ifs = cfg.interfaces()
    assert len(ifs) == count
    assert all(i.from_range and i.evidence_line.text.startswith("interface range") for i in ifs)


def test_c_member_with_own_block_appears_once_with_union_children():
    text = ("hostname SW1\ninterface range Gi1/0/1 - 24\n switchport mode access\n"
            " switchport access vlan 10\ninterface Gi1/0/5\n description printer\n"
            " switchport access vlan 20\nend\n")
    cfg = parser.parse(text)
    assert len(cfg.interfaces()) == 24
    g5 = cfg.interface("GigabitEthernet1/0/5")
    assert not g5.from_range and g5.node.line.text == "interface Gi1/0/5"
    kids = [c.line.text.strip() for c in cfg.children_of(g5.node)]
    assert kids == ["switchport mode access", "switchport access vlan 10", "description printer",
                    "switchport access vlan 20"]


def test_c_range_macro_and_unresolvable_macro():
    cfg = parser.parse("hostname SW1\ndefine interface-range EDGE Gi1/0/1 - 3\n"
                       "interface range macro EDGE\n switchport mode access\n"
                       "interface range macro NOPE\n shutdown\nend\n")
    assert [i.name for i in cfg.interfaces()] == [f"GigabitEthernet1/0/{i}" for i in (1, 2, 3)]
    assert any(n.code == "CSC-SELF-0004" for n in cfg.notes)


def test_c_range_finding_anchors_on_range_line():
    from ciscocheck.model import Catalogue, Context
    cfg = parser.parse("hostname SW1\ninterface range Gi1/0/1 - 2\n switchport mode access\nend\n")
    iface = cfg.interfaces()[0]
    cat = Catalogue.from_dict({"version": 1, "catalogue_version": "t", "checks": [{
        "id": "CSC-TST-0001", "title": "t", "severity": "low", "category": "security",
        "confidence": "deterministic", "platforms": ["iosxe"], "profiles": ["campus"],
        "test_kind": "present", "subject": [], "rationale": "r", "params_required": [],
        "refs": [{"authority": "NIST", "id": "x"}], "remediation": []}]})
    ctx = Context(platform="iosxe", platform_source="given", profile="campus", role_map={},
                  defaults=cfg.defaults, dialect=cfg.dialect, refs_index=cfg.refs,
                  entry=cat.entries[0], skill_version="1", catalogue_version="t")
    f = ctx.finding(line=iface.evidence_line)
    assert f.evidence.anchor == "range-line"


# ---------------------------------------------------------------- (d) defaults

def test_d_absence_resolves_through_defaults_table():
    cfg = parser.parse("hostname SW1\nline vty 0 4\n transport input ssh\ninterface Gi1/0/1\n"
                       " description x\nend\n", platform="iosxe")
    vty = cfg.find_one("line vty 0 4")
    eff = cfg.defaults.effective(cfg, "iosxe", "line.exec-timeout", scope=vty)
    assert eff.observed is False and eff.value == "10 0"
    eff = cfg.defaults.effective(cfg, "iosxe", "cdp.run")
    assert eff.observed is False and eff.state == "on"
    g1 = cfg.interface("Gi1/0/1")
    eff = cfg.defaults.effective(cfg, "iosxe", "switchport.mode", scope=g1.node)
    assert eff.observed is False and eff.value == "dynamic auto"


def test_d_observed_positive_and_negated_forms():
    cfg = parser.parse("hostname SW1\nno cdp run\nline vty 0 4\n exec-timeout 5 0\nend\n")
    assert cfg.defaults.effective(cfg, "iosxe", "cdp.run") .state == "off"
    vty = cfg.find_one("line vty 0 4")
    eff = cfg.defaults.effective(cfg, "iosxe", "line.exec-timeout", scope=vty)
    assert eff.observed and eff.value == "5 0" and eff.state == "on"


# ---------------------------------------------------------------- (e) dialect

def test_e_portfast_edge_bpduguard_default_is_recognised():
    cfg = parser.parse("version 17.9\nhostname SW1\nspanning-tree portfast edge bpduguard default\n"
                       "interface Gi1/0/1\n shutdown\nend\n")
    assert cfg.platform == "iosxe"
    assert cfg.dialect.matches(cfg, "stp.bpduguard.default", "iosxe")
    eff = cfg.defaults.effective(cfg, "iosxe", "spanning-tree.portfast.bpduguard.default")
    assert eff.observed and eff.state == "on"
    assert cfg.dialect.canonical_remediation("stp.bpduguard.default", "iosxe") == (
        "spanning-tree portfast edge bpduguard default",)
    assert cfg.dialect.canonical_remediation("stp.bpduguard.default", "ios") == (
        "spanning-tree portfast bpduguard default",)


# ---------------------------------------------------------------- (f) all-lines

def test_f_line_ranges_full_universe():
    cfg = parser.parse("hostname SW1\nline con 0\n exec-timeout 5 0\nline vty 0 4\n"
                       " transport input ssh\nend\n")
    vty = cfg.line_ranges("vty")
    assert [(r.first, r.last, r.observed) for r in vty] == [(0, 4, True), (5, 15, False)]
    assert vty[1].node is None
    assert any(n.code == "CSC-SELF-0006" and n.detail ==
               "assumed line vty 5 15 present at platform defaults" for n in cfg.notes)
    assert [(r.first, r.last, r.observed) for r in cfg.line_ranges("con")] == [(0, 0, True)]
    assert cfg.line_ranges("aux") == ()


def test_f_vty_universe_override():
    cfg = parser.parse("hostname SW1\nline vty 0 4\n transport input ssh\nline vty 5 15\n"
                       " transport input none\nend\n", vty_universe=(0, 31))
    assert [(r.first, r.last, r.observed) for r in cfg.line_ranges("vty")] == [
        (0, 4, True), (5, 15, True), (16, 31, False)]


# ---------------------------------------------------------------- (g) references

def test_g_reference_resolution_on_masked_text():
    text = ("hostname SW1\nsnmp-server community CANARY-COMMUNITY-01 RO 99\n"
            "ntp server 10.0.0.1 key 1\nline vty 0 4\n access-class 10 in\n"
            "ip access-list standard MGMT\n permit 10.0.0.0 0.0.0.255\n"
            "aaa authentication login default group ISE local\nend\n")
    cfg = parser.parse(text)
    undefined = {(k, n) for k, n, _node in cfg.refs.undefined()}
    assert ("acl", "99") in undefined and ("acl", "10") in undefined
    assert ("ntp-key", "1") in undefined and ("aaa-group", "ISE") in undefined
    assert ("aaa-group", "local") not in undefined
    assert cfg.refs.defined("acl", "MGMT")
    assert cfg.refs.uses("acl", "99")[0].line.text.startswith("snmp-server community [REDACTED")


# ---------------------------------------------------------------- (h) snmp-server user

def test_h_snmp_user_masked_and_group_visible():
    cfg = parser.parse("hostname SW1\nsnmp-server group RO-GROUP v3 priv\n"
                       "snmp-server user mon RO-GROUP v3 auth sha CANARY-AUTH-02 access 99\nend\n")
    assert cfg.has("snmp-server group RO-GROUP v3 priv")
    user = cfg.find_one("snmp-server user").line
    assert "CANARY" not in user.text and user.tokens[-2:] == ("access", "99")


# ---------------------------------------------------------------- (i) paste artefacts

def test_i_paste_artefacts_are_stripped_with_content_free_notes():
    text = ("\ufeffSW1#show running-config\r\nBuilding configuration...\r\n\r\n"
            "Current configuration : 1234 bytes\r\n!\r\nhostname SW1\r\n"
            "snmp-server comm --More-- \x08\x08\x08\x08\x08\x08\x08\x08\x08         "
            "\x08\x08\x08\x08\x08\x08\x08\x08\x08unity S3cretRO RO 99\r\n"
            "interface Gi1/0/1\r\n shutdown\r\nend\r\n\r\nSW1#\r\nConnection closed.\r\n")
    cfg = parser.parse(text)
    snmp = cfg.find_one("snmp-server community")
    assert snmp is not None
    assert snmp.line.text == "snmp-server community [REDACTED snmp-community, 8 chars] RO 99"
    classes = [n.detail for n in cfg.notes if n.code == "CSC-SELF-0003"]
    assert set(classes) == {"bom", "prompt echo", "build-banner", "size-banner", "pager artefact",
                            "trailing end"}
    for n in cfg.notes:
        assert "S3cret" not in n.detail and "comm" not in n.detail
    assert cfg.find_one("end") is not None
    assert all("\r" not in l.text for l in cfg.lines())


def test_i_clean_capture_emits_no_preclean_note():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n shutdown\nend\n")
    assert not any(n.code == "CSC-SELF-0003" for n in cfg.notes)


# ---------------------------------------------------------------- exit-2 detection

@pytest.mark.parametrize("text", [
    "",
    "   \n\n",
    "hello world\nthis is a letter\nnot a config at all\nregards\n",
    "hostname SW1\n",
])
def test_not_a_cisco_config(text):
    with pytest.raises(NotACiscoConfigError) as ei:
        parser.parse(text)
    assert "hello" not in str(ei.value) and "letter" not in str(ei.value)


def test_non_utf8_replacement_characters_do_not_crash():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n description caf\ufffd\nend\n")
    assert cfg.hostname() == "SW1"


def test_unclassifiable_line_is_kept_with_note():
    cfg = parser.parse("hostname SW1\n#### garbage ####\ninterface Gi1/0/1\n shutdown\nend\n")
    assert any(n.code == "CSC-SELF-0004" and n.detail == "unclassified line" for n in cfg.notes)
    assert cfg.find("#### garbage ####")


def test_placeholder_note():
    cfg = parser.parse("hostname SW1\ntacacs-server key <REPLACE-ME:tacacs-key>\n"
                       "interface Gi1/0/1\n shutdown\nend\n")
    assert any(n.code == "CSC-SELF-0007" and n.detail == "unfilled placeholder tacacs-key"
               for n in cfg.notes)


def test_platform_inference_order():
    assert parser.parse("version 15.2\nhostname A\ninterface Gi0/1\nend\n").platform == "ios"
    cfg = parser.parse("hostname A\nboot system flash:c2960x-universalk9-mz.152-7.E.bin\n"
                       "interface Gi0/1\nend\n")
    assert (cfg.platform, cfg.platform_source) == ("ios", "inferred-image")
    cfg = parser.parse("hostname A\ndevice-tracking policy P\ninterface Gi0/1\nend\n")
    assert (cfg.platform, cfg.platform_source) == ("iosxe", "inferred-surface")
    cfg = parser.parse("hostname A\ninterface Gi0/1\n shutdown\nend\n")
    assert (cfg.platform, cfg.platform_source) == ("iosxe", "default")
    cfg = parser.parse("version 15.2\nhostname A\ninterface Gi0/1\nend\n", platform="iosxe")
    assert (cfg.platform, cfg.platform_source) == ("iosxe", "given")
    assert cfg.notes[0].code == "CSC-SELF-0001" and cfg.notes[0].detail == "platform=iosxe source=given"


# ---------------------------------------------------------------- DHCP snooping, ip domain-name, vstack defaults

def _eff(text: str, key: str, platform: str = "iosxe", scope_pattern: str | None = None):
    cfg = parser.parse("hostname SW1\n" + text + "\ninterface Gi1/0/9\n shutdown\nend\n",
                       platform=platform)
    scope = cfg.find_one(scope_pattern) if scope_pattern else None
    return cfg.defaults.effective(cfg, platform, key, scope=scope)


def test_dhcp_snooping_subcommand_does_not_count_as_the_global_form():
    # a sub-command alone never makes snooping "on" -- false-negative regression case
    for sub in ("ip dhcp snooping vlan 10", "ip dhcp snooping database flash:snoop.db",
                "ip dhcp snooping information option allow-untrusted"):
        eff = _eff(sub, "ip.dhcp.snooping")
        assert eff.observed is False and eff.state == "off", sub
    # false-positive regression case: the latest sub-command does not decide the global state
    eff = _eff("ip dhcp snooping\nip dhcp snooping vlan 10\nno ip dhcp snooping information option",
               "ip.dhcp.snooping")
    assert eff.observed and eff.state == "on"
    assert _eff("no ip dhcp snooping\nip dhcp snooping vlan 10", "ip.dhcp.snooping").state == "off"
    opt = _eff("ip dhcp snooping information option allow-untrusted",
               "ip.dhcp.snooping.information.option")
    assert opt.observed is False


def test_declared_value_slots_still_match():
    vty = "line vty 0 4"
    assert _eff("line vty 0 4\n exec-timeout 5 0", "line.exec-timeout", scope_pattern=vty).value == "5 0"
    assert _eff("line vty 0 4\n exec-timeout 5", "line.exec-timeout", scope_pattern=vty).value == "5"
    assert _eff("spanning-tree mode rapid-pvst", "spanning-tree.mode").value == "rapid-pvst"
    assert _eff("logging console", "logging.console").state == "on"
    assert _eff("logging console informational", "logging.console").value == "informational"
    assert _eff("no logging console", "logging.console").state == "off"
    # too many trailing tokens is a different command, not a value
    assert _eff("spanning-tree mode rapid-pvst extra", "spanning-tree.mode").observed is False


def test_audit_every_defaults_form_rejects_a_subcommand():
    cfg0 = parser.parse("hostname SW1\ninterface Gi1/0/9\n shutdown\nend\n")
    table = cfg0.defaults
    checked = 0
    for platform in ("ios", "iosxe"):
        for key in table.keys(platform):
            lo, hi = table.value_slots(platform, key)
            for form in table.forms(platform, key):
                sub = " ".join([form] + ["zzsub"] * (hi + 1))
                exact = " ".join([form] + ["1"] * lo)
                cfg = parser.parse(f"hostname SW1\n{sub}\ninterface Gi1/0/9\n shutdown\nend\n",
                                   platform=platform)
                assert table.effective(cfg, platform, key).observed is False, (platform, key, sub)
                cfg = parser.parse(f"hostname SW1\n{exact}\ninterface Gi1/0/9\n shutdown\nend\n",
                                   platform=platform)
                assert table.effective(cfg, platform, key).observed is True, (platform, key, exact)
                checked += 1
    assert checked >= 90


def test_ip_domain_name_intent_matches_both_spellings():
    for platform in ("ios", "iosxe"):
        for line in ("ip domain-name example.invalid", "ip domain name example.invalid"):
            cfg = parser.parse(f"hostname SW1\n{line}\ninterface Gi1/0/9\n shutdown\nend\n",
                               platform=platform)
            assert cfg.dialect.matches(cfg, "ip-domain-name", platform), (platform, line)
        cfg = parser.parse("hostname SW1\nip domain lookup source-interface Vlan99\n"
                           "interface Gi1/0/9\n shutdown\nend\n", platform=platform)
        assert not cfg.dialect.matches(cfg, "ip-domain-name", platform)
    assert parser.parse("hostname A\ninterface Gi0/1\nend\n").dialect.canonical_remediation(
        "ip-domain-name", "iosxe") == ("ip domain name <REPLACE-ME:domain-name>",)
    # the domain-lookup key reads both spellings too, and a sub-command does not count
    assert _eff("no ip domain lookup", "ip.domain-lookup").state == "off"
    assert _eff("no ip domain-lookup", "ip.domain-lookup", platform="ios").state == "off"
    assert _eff("ip domain lookup source-interface Vlan99", "ip.domain-lookup").observed is False


def test_vstack_fails_safe_on_iosxe():
    eff = _eff("version 3.6", "vstack")
    assert eff.observed is False and eff.state == "on"           # IOS-XE 3.x silent: on
    assert _eff("", "vstack").state == "on"                      # unknown release: on
    assert _eff("no vstack", "vstack").state == "off"            # explicitly disabled
    assert _eff("version 3.6\nno vstack", "vstack").state == "off"
    assert _eff("version 16.12", "vstack").state == "off"        # off by default from 16.x
    assert _eff("version 17.9", "vstack").state == "off"
    assert _eff("version 17.9\nvstack", "vstack").state == "on"  # explicitly enabled wins
    assert _eff("", "vstack", platform="ios").state == "on"
