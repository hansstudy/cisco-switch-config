"""DHCP -- snooping, DAI, IP Source Guard (9 checks)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config


def _vlan_set(spec: str) -> set[int]:
    out: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            if a.strip().isdigit() and b.strip().isdigit():
                out.update(range(int(a), int(b) + 1))
        elif part.isdigit():
            out.add(int(part))
    return out


def _snooping_vlans(cfg: "Config") -> set[int]:
    # "ip dhcp snooping vlan" is a 4-token pattern (ip, dhcp, snooping, vlan); the vlan-list
    # value is token index 4, one past the pattern itself.
    out: set[int] = set()
    for n in cfg.find("ip dhcp snooping vlan"):
        if len(n.line.tokens) > 4:
            out |= _vlan_set(n.line.tokens[4])
    return out


def _dai_vlans(cfg: "Config") -> set[int]:
    # "ip arp inspection vlan" is likewise a 4-token pattern; the value is index 4.
    out: set[int] = set()
    for n in cfg.find("ip arp inspection vlan"):
        if len(n.line.tokens) > 4:
            out |= _vlan_set(n.line.tokens[4])
    return out


def _active_access_vlans(cfg: "Config") -> set[int]:
    out: set[int] = set()
    for iface in cfg.interfaces():
        if iface.role == "unused":
            continue
        n = cfg.find_one("switchport access vlan", scope=iface.node)
        if n is not None and len(n.line.tokens) > 3 and n.line.tokens[3].isdigit():
            out.add(int(n.line.tokens[3]))
    return out


def _snooping_global(cfg: "Config"):
    """Whether `ip dhcp snooping` is globally enabled, decided from the EXACT global command
    line only. `data/defaults.json`'s `ip.dhcp.snooping` key now
    carries a `value_slots()` fix in parallel, so `ctx.defaults.effective()`/`is_on()`
    already compute the right *state* (a sub-command like `ip dhcp snooping vlan 10` or `no ip
    dhcp snooping information option` no longer counts as the global toggle). This helper is
    kept anyway because `_util.observed_node()` still anchors evidence with a plain
    token-prefix `find_one()`, which would still happily return that same sub-command line as
    "the observed line" even though it correctly decided the *state* is "off" -- exact state
    and exact evidence line are computed together here instead. Matches a line whose tokens
    are exactly `ip dhcp snooping` (on) or `no ip dhcp snooping` (off); whichever exact line
    appears last in the file wins, same tie-break as `DefaultsTable.effective()`."""
    candidates = []
    for n in cfg.find("ip dhcp snooping"):
        if len(n.line.tokens) == 3:
            candidates.append((n.line.line_no, True, n))
    for n in cfg.find("no ip dhcp snooping"):
        if len(n.line.tokens) == 4:
            candidates.append((n.line.line_no, False, n))
    if not candidates:
        return False, None  # data/defaults.json: ip.dhcp.snooping state is off by default
    candidates.sort(key=lambda c: c[0])
    _, on, node = candidates[-1]
    return on, node


@rule("CSC-DHCP-0001")
def snooping_absent(cfg: "Config", ctx: "Context"):
    on, node = _snooping_global(cfg)
    if not on:
        yield ctx.finding(line=node.line if node else None)


@rule("CSC-DHCP-0002", supplies=("vlan",))
def snooping_no_vlan_list(cfg: "Config", ctx: "Context"):
    if not _snooping_global(cfg)[0]:
        return
    if not cfg.has("ip dhcp snooping vlan"):
        yield ctx.finding(line=None, params={"vlan": _util.UNKNOWN_VLAN})


@rule("CSC-DHCP-0003", supplies=("vlan",))
def access_vlan_not_snooped(cfg: "Config", ctx: "Context"):
    if not _snooping_global(cfg)[0]:
        return
    snoop = _snooping_vlans(cfg)
    for v in sorted(_active_access_vlans(cfg) - snoop):
        yield ctx.finding(line=None, params={"vlan": str(v)}, title_suffix=f"VLAN {v}")


@rule("CSC-DHCP-0004", supplies=("interface",))
def snooping_trust_missing_uplink(cfg: "Config", ctx: "Context"):
    if not _snooping_global(cfg)[0]:
        return
    for iface in cfg.interfaces(role="uplink"):
        if not cfg.has("ip dhcp snooping trust", scope=iface.node):
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-DHCP-0005", supplies=("interface",))
def limit_rate_absent(cfg: "Config", ctx: "Context"):
    if not _snooping_global(cfg)[0]:
        return
    for iface in _util.access_like_interfaces(cfg):
        if not cfg.has("ip dhcp snooping limit rate", scope=iface.node):
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-DHCP-0006")
def database_absent(cfg: "Config", ctx: "Context"):
    if not cfg.has("ip dhcp snooping database"):
        yield ctx.finding(line=None)


@rule("CSC-DHCP-0007")
def info_option_handling(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "ip.dhcp.snooping.information.option") and not cfg.has("allow-untrusted"):
        n = _util.observed_node(cfg, ctx, "ip.dhcp.snooping.information.option")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-DHCP-0008", supplies=("vlan",))
def dai_missing_on_snooped_vlans(cfg: "Config", ctx: "Context"):
    snoop = _snooping_vlans(cfg)
    if not snoop:
        return
    dai = _dai_vlans(cfg)
    for v in sorted(snoop - dai):
        yield ctx.finding(line=None, params={"vlan": str(v)}, title_suffix=f"VLAN {v}")


@rule("CSC-DHCP-0009")
def dai_validate_or_trust_misplaced(cfg: "Config", ctx: "Context"):
    v = cfg.find_one("ip arp inspection validate")
    need = {"src-mac", "dst-mac", "ip"}
    # "ip arp inspection validate" is a 4-token pattern; the checked-item list is index 4+.
    validate_ok = v is not None and need <= {t.lower() for t in v.line.tokens[4:]}
    trust_misplaced = any(cfg.has("ip arp inspection trust", scope=i.node)
                          for i in _util.access_like_interfaces(cfg))
    if not validate_ok or trust_misplaced:
        yield ctx.finding(line=v.line if v else None)
