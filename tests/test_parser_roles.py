"""Interface-role precedence, every row in order, plus --role-map."""
from __future__ import annotations

import pytest

from ciscocheck import parser
from ciscocheck.parser import RoleMapError, load_role_map


def role_of(body: str, name: str = "GigabitEthernet1/0/1", role_map=None):
    iface_line = f"interface {name}"
    cfg = parser.parse(f"hostname SW1\n{iface_line}\n{body}\nend\n", role_map=role_map)
    i = cfg.interface(name)
    return i.role, i.role_source


def test_row1_role_map_wins_over_everything():
    rm = load_role_map({"version": 1, "roles": {"Gi1/0/1": "management"}})
    assert role_of(" shutdown\n switchport mode trunk", role_map=rm) == ("management", "role-map")


def test_row2_shutdown_is_unused():
    assert role_of(" switchport mode access\n shutdown") == ("unused", "inferred-shutdown")


def test_row2_not_unused_with_channel_group_or_trunk():
    assert role_of(" shutdown\n channel-group 1 mode active\n switchport mode trunk")[0] == "uplink"
    assert role_of(" shutdown\n switchport mode trunk")[0] == "trunk"


def test_row3_management_svi_by_description_or_role_map_vlan():
    assert role_of(" description OOB mgmt\n ip address 10.0.0.2 255.255.255.0", "Vlan99") == (
        "management", "inferred-description")
    rm = load_role_map({"version": 1, "management_vlan": 50})
    assert role_of(" ip address 10.0.0.2 255.255.255.0", "Vlan50", role_map=rm) == (
        "management", "inferred-description")
    # an SVI without an address is not management
    assert role_of(" description mgmt", "Vlan99")[0] == "unknown"


def test_row4_routed():
    assert role_of(" no switchport\n ip address 10.1.1.1 255.255.255.252") == (
        "routed", "inferred-routed")
    assert role_of(" ip address 10.1.1.1 255.255.255.252") == ("routed", "inferred-routed")


def test_row5_uplink_by_channel_group_or_description():
    assert role_of(" switchport mode trunk\n channel-group 1 mode active") == (
        "uplink", "inferred-uplink")
    assert role_of(" description to-core-1\n switchport mode trunk") == ("uplink", "inferred-uplink")
    assert role_of(" description to distribution A\n switchport trunk encapsulation dot1q") == (
        "uplink", "inferred-uplink")
    # the bare word no longer promotes a trunk to an uplink
    assert role_of(" description Distribution A\n switchport trunk encapsulation dot1q")[0] == "trunk"


def test_row6_trunk():
    assert role_of(" switchport mode trunk") == ("trunk", "inferred-trunk")
    assert role_of(" switchport mode dynamic desirable") == ("trunk", "inferred-trunk")


def test_row7_voice_access_before_access():
    assert role_of(" switchport mode access\n switchport access vlan 10\n switchport voice vlan 20") \
        == ("voice-access", "inferred-voice")


def test_row8_access():
    assert role_of(" switchport mode access") == ("access", "inferred-access")
    assert role_of(" switchport access vlan 10") == ("access", "inferred-access")


def test_row9_unknown_default():
    assert role_of(" description nothing to see") == ("unknown", "default")


def test_interfaces_filter_on_resolved_role_and_kind():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n shutdown\ninterface Gi1/0/2\n"
                       " switchport mode access\ninterface Vlan10\n ip address 10.0.0.1 255.0.0.0\n"
                       "end\n")
    assert [i.name for i in cfg.interfaces(role="unused")] == ["GigabitEthernet1/0/1"]
    assert [i.name for i in cfg.interfaces(kind="svi")] == ["Vlan10"]
    assert [i.name for i in cfg.interfaces(role="unknown")] == ["Vlan10"]


def test_role_map_ranges_and_note():
    rm = load_role_map({"version": 1, "ranges": {"Gi1/0/1 - 2": "access"},
                        "roles": {"Te1/1/1": "uplink", "Gi9/9/9": "access"}})
    cfg = parser.parse("hostname SW1\ninterface range Gi1/0/1 - 2\n description x\n"
                       "interface Te1/1/1\n description y\nend\n", role_map=rm)
    assert [(i.name, i.role_source) for i in cfg.interfaces()] == [
        ("GigabitEthernet1/0/1", "role-map"), ("GigabitEthernet1/0/2", "role-map"),
        ("TenGigabitEthernet1/1/1", "role-map")]
    note = next(n for n in cfg.notes if n.code == "CSC-SELF-0008")
    assert note.detail == "role-map applied to 3 interfaces (1 ignored)"


@pytest.mark.parametrize("doc,fragment", [
    ({"version": 1, "roles": {"Gi1/0/1": "core"}}, 'key "Gi1/0/1" has invalid role "core"'),
    ({"version": 2}, 'key "version"'),
    ({"version": 1, "colour": "red"}, 'key "colour" is not recognised'),
    ({"version": 1, "ranges": {"Gi1/0/9 - 2": "access"}}, 'key "Gi1/0/9 - 2"'),
    ({"version": 1, "management_vlan": 5000}, 'key "management_vlan"'),
    ({"version": 1, "vty_universe": [4, 0]}, 'key "vty_universe"'),
    ("{not json", "not valid JSON"),
])
def test_malformed_role_map_is_rejected_naming_key_and_value(doc, fragment):
    with pytest.raises(RoleMapError) as ei:
        load_role_map(doc)
    assert fragment in str(ei.value)


# ---- explicit uplink words only, whole-word

@pytest.mark.parametrize("desc,role", [
    ("link to ACC-SW-01", "trunk"),               # a downlink, not an uplink
    ("to ACC-SW-02 port 48", "trunk"),
    ("core switch feed", "trunk"),                # bare `core` no longer promotes
    ("WAN edge", "trunk"),
    ("not-uplink spare", "trunk"),
    ("Uplink to core", "uplink"),
    ("UPSTREAM A", "uplink"),
    ("to-core-1", "uplink"),
    ("to_dist-2", "uplink"),
    ("to distribution stack", "uplink"),
])
def test_uplink_description_words(desc, role):
    assert role_of(f" description {desc}\n switchport mode trunk")[0] == role


def test_channel_group_still_marks_uplink():
    assert role_of(" description link to ACC-SW-01\n switchport mode trunk\n"
                   " channel-group 1 mode active") == ("uplink", "inferred-uplink")
