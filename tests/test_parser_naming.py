"""Canonical interface naming: every abbreviation row and both collisions."""
from __future__ import annotations

import pytest

from ciscocheck import parser
from ciscocheck.parser import canonical_interface

ROWS = [
    (("TwentyFiveGigE", "Twe", "TwentyFiveGig"), "TwentyFiveGigE"),
    (("TwoGigabitEthernet", "Tw", "Two"), "TwoGigabitEthernet"),
    (("TenGigabitEthernet", "TenGig", "Te"), "TenGigabitEthernet"),
    (("FortyGigabitEthernet", "Fo", "FortyGig"), "FortyGigabitEthernet"),
    (("HundredGigE", "Hu", "HundredGig"), "HundredGigE"),
    (("GigabitEthernet", "Gig", "Gi", "G"), "GigabitEthernet"),
    (("FastEthernet", "Fas", "Fa", "F"), "FastEthernet"),
    (("AppGigabitEthernet", "Ap", "App"), "AppGigabitEthernet"),
    (("Port-channel", "Po"), "Port-channel"),
    (("Ethernet", "Eth", "Et"), "Ethernet"),
    (("Vlan", "Vl"), "Vlan"),
    (("Loopback", "Lo"), "Loopback"),
    (("Tunnel", "Tu"), "Tunnel"),
    (("Serial", "Se"), "Serial"),
    (("BDI",), "BDI"),
]
CASES = [(abbr, canon) for abbrs, canon in ROWS for abbr in abbrs]


@pytest.mark.parametrize("abbr,canon", CASES, ids=[c[0] for c in CASES])
def test_every_abbreviation_row(abbr, canon):
    assert canonical_interface(f"{abbr}1/0/1") == f"{canon}1/0/1"
    assert canonical_interface(f"{abbr.lower()}1/0/1") == f"{canon}1/0/1"
    assert canonical_interface(f"{abbr.upper()}1/0/1") == f"{canon}1/0/1"


def test_collision_twe_vs_tw():
    assert canonical_interface("Twe1/0/1") == "TwentyFiveGigE1/0/1"
    assert canonical_interface("Tw1/0/1") == "TwoGigabitEthernet1/0/1"


def test_collision_te_vs_tu():
    assert canonical_interface("Te1/1/1") == "TenGigabitEthernet1/1/1"
    assert canonical_interface("Tu0") == "Tunnel0"


def test_remainder_kept_verbatim_and_unknown_prefix_kept():
    assert canonical_interface("Gi1/0/1.100") == "GigabitEthernet1/0/1.100"
    assert canonical_interface("Po10") == "Port-channel10"
    assert canonical_interface("Nve1") == "Nve1"
    assert canonical_interface("Giga1/0/1") == "GigabitEthernet1/0/1"


def test_text_never_rewritten_but_lookup_canonicalises_both_sides():
    cfg = parser.parse("hostname SW1\ninterface Gi1/0/1\n shutdown\n"
                       "interface GigabitEthernet1/0/2\n shutdown\nend\n")
    assert cfg.find_one("interface Gi1/0/1").line.text == "interface Gi1/0/1"
    assert cfg.find("interface GigabitEthernet1/0/1")
    assert cfg.find("interface Gi1/0/2")
    assert cfg.interface("gi1/0/2").name == "GigabitEthernet1/0/2"
    assert cfg.interface("GigabitEthernet1/0/1").evidence_line.text == "interface Gi1/0/1"


def test_role_map_keys_canonicalised_before_matching():
    rm = parser.load_role_map({"version": 1, "roles": {"Gi1/0/1": "uplink"}})
    cfg = parser.parse("hostname SW1\ninterface GigabitEthernet1/0/1\n shutdown\nend\n", role_map=rm)
    i = cfg.interface("Gi1/0/1")
    assert (i.role, i.role_source) == ("uplink", "role-map")
