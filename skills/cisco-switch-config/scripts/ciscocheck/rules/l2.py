"""L2 -- VLAN hygiene, port security, trunking, storm control (14 checks)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config


def _trunk_interfaces(cfg: "Config"):
    return tuple(i for i in cfg.interfaces()
                 if cfg.has("switchport mode trunk", scope=i.node)
                 or cfg.has("switchport trunk encapsulation", scope=i.node))


def _access_vlans(cfg: "Config") -> set[int]:
    vlans: set[int] = set()
    for n in cfg.find("switchport access vlan"):
        if len(n.line.tokens) > 3 and n.line.tokens[3].isdigit():
            vlans.add(int(n.line.tokens[3]))
    return vlans


def _native_vlan(cfg: "Config", iface):
    n = cfg.find_one("switchport trunk native vlan", scope=iface.node)
    native = 1
    if n is not None and len(n.line.tokens) > 4 and n.line.tokens[4].isdigit():
        native = int(n.line.tokens[4])
    return native, n


@rule("CSC-L2-0001", supplies=("interface",))
def native_vlan_is_1(cfg: "Config", ctx: "Context"):
    for iface in _trunk_interfaces(cfg):
        native, n = _native_vlan(cfg, iface)
        if native == 1:
            yield ctx.finding(line=(n.line if n else iface.evidence_line),
                              params={"interface": iface.name}, title_suffix=iface.name)


@rule("CSC-L2-0002", supplies=("interface", "vlan"))
def native_equals_access(cfg: "Config", ctx: "Context"):
    access_vlans = _access_vlans(cfg)
    for iface in _trunk_interfaces(cfg):
        native, n = _native_vlan(cfg, iface)
        if native in access_vlans:
            # The remediation moves the native VLAN OFF the colliding value, never back onto
            # it: the engine cannot know a genuinely unused VLAN from this config alone, so
            # the fix carries an explicit placeholder for the operator to fill in (never the
            # observed `native` value, and never VLAN 1).
            yield ctx.finding(line=(n.line if n else iface.evidence_line),
                              params={"interface": iface.name, "vlan": _util.UNKNOWN_VLAN},
                              title_suffix=iface.name)


@rule("CSC-L2-0003", supplies=("interface", "vlan"))
def access_vlan_1(cfg: "Config", ctx: "Context"):
    for iface in cfg.interfaces(role="access") + cfg.interfaces(role="voice-access"):
        n = cfg.find_one("switchport access vlan", scope=iface.node)
        vlan = 1
        if n is not None and len(n.line.tokens) > 3 and n.line.tokens[3].isdigit():
            vlan = int(n.line.tokens[3])
        if vlan == 1:
            # This check exists BECAUSE the port is on VLAN 1: the fix must move it to a
            # dedicated, unused VLAN, never restate 1. The engine cannot know a safe target
            # from this config alone, so the fix carries an explicit placeholder.
            yield ctx.finding(line=(n.line if n else iface.evidence_line),
                              params={"interface": iface.name, "vlan": _util.UNKNOWN_VLAN},
                              title_suffix=iface.name)


@rule("CSC-L2-0004")
def vlan1_not_shutdown(cfg: "Config", ctx: "Context"):
    iface = cfg.interface("Vlan1")
    if iface is None:
        return
    if not cfg.has("shutdown", scope=iface.node):
        yield ctx.finding(line=iface.evidence_line)


@rule("CSC-L2-0005", supplies=("interface",))
def allowed_vlan_all(cfg: "Config", ctx: "Context"):
    for iface in _trunk_interfaces(cfg):
        n = cfg.find_one("switchport trunk allowed vlan", scope=iface.node)
        bad = n is None or (len(n.line.tokens) > 4 and n.line.tokens[4].lower() == "all")
        if bad:
            yield ctx.finding(line=(n.line if n else iface.evidence_line),
                              params={"interface": iface.name}, role_source=iface.role_source,
                              title_suffix=iface.name)


@rule("CSC-L2-0006", supplies=("interface",))
def dtp_not_disabled(cfg: "Config", ctx: "Context"):
    for iface in _trunk_interfaces(cfg):
        if not cfg.has("switchport nonegotiate", scope=iface.node):
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-L2-0007", supplies=("interface",))
def dtp_dynamic(cfg: "Config", ctx: "Context"):
    for iface in cfg.interfaces(kind="physical"):
        if cfg.has("no switchport", scope=iface.node):
            continue
        if not cfg.has("switchport mode", scope=iface.node):
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              title_suffix=iface.name)


@rule("CSC-L2-0008", supplies=("interface",))
def unused_port_not_shutdown(cfg: "Config", ctx: "Context"):
    for iface in cfg.interfaces(role="unknown", kind="physical"):
        if not cfg.has("shutdown", scope=iface.node):
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-L2-0009", supplies=("interface", "vlan"))
def unused_port_wrong_vlan(cfg: "Config", ctx: "Context"):
    active_vlans: set[int] = set()
    for iface in cfg.interfaces(kind="physical"):
        if iface.role == "unused":
            continue
        n = cfg.find_one("switchport access vlan", scope=iface.node)
        if n is not None and len(n.line.tokens) > 3 and n.line.tokens[3].isdigit():
            active_vlans.add(int(n.line.tokens[3]))
    # Physical ports only: an SVI (e.g. a shut, address-less Vlan1) has no access-VLAN
    # concept at all and can incidentally match the "unused" role inference (shutdown,
    # no channel-group, no trunk mode all hold trivially for a shut SVI); the role table
    # has no SVI-specific carve-out, so the carve-out belongs here.
    for iface in cfg.interfaces(role="unused", kind="physical"):
        n = cfg.find_one("switchport access vlan", scope=iface.node)
        vlan = 1
        if n is not None and len(n.line.tokens) > 3 and n.line.tokens[3].isdigit():
            vlan = int(n.line.tokens[3])
        if n is None or vlan in active_vlans or vlan == 1:
            # The fix parks the port in a dedicated, unused ("black-hole") VLAN -- never the
            # observed value, which is by definition either live or VLAN 1 here. Which VLAN is
            # genuinely unused is a judgment call (references/judgment-checks.md #13), so the
            # fix carries an explicit placeholder rather than a guessed number.
            yield ctx.finding(line=(n.line if n else iface.evidence_line),
                              params={"interface": iface.name, "vlan": _util.UNKNOWN_VLAN},
                              role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-L2-0010", supplies=("interface",))
def port_security_absent(cfg: "Config", ctx: "Context"):
    for iface in _util.access_like_interfaces(cfg):
        if not cfg.has("switchport port-security", scope=iface.node):
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-L2-0011", supplies=("interface",))
def port_security_weak(cfg: "Config", ctx: "Context"):
    for iface in cfg.interfaces():
        if not cfg.has("switchport port-security", scope=iface.node):
            continue
        mx = cfg.find_one("switchport port-security maximum", scope=iface.node)
        max_bad = (mx is not None and len(mx.line.tokens) > 3 and mx.line.tokens[3].isdigit()
                  and int(mx.line.tokens[3]) > 3)
        vio = cfg.find_one("switchport port-security violation", scope=iface.node)
        vio_bad = vio is not None and len(vio.line.tokens) > 3 and \
            vio.line.tokens[3].lower() not in ("restrict", "shutdown")
        if max_bad or vio_bad:
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              title_suffix=iface.name)


@rule("CSC-L2-0012", supplies=("interface",))
def storm_control_absent(cfg: "Config", ctx: "Context"):
    for iface in _util.access_like_interfaces(cfg):
        if not cfg.has("storm-control", scope=iface.node):
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-L2-0013")
def vtp_mode_bad(cfg: "Config", ctx: "Context"):
    eff = ctx.defaults.effective(cfg, ctx.platform, "vtp.mode")
    val = (eff.value or "server").strip().lower()
    if val in ("server", "client"):
        n = _util.observed_node(cfg, ctx, "vtp.mode")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-L2-0014")
def vtp_domain_no_password(cfg: "Config", ctx: "Context"):
    dom = cfg.find_one("vtp domain")
    if dom is not None and not cfg.has("vtp password"):
        yield ctx.finding(line=dom.line)
