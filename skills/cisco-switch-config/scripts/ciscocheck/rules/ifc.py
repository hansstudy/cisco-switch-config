"""IFC -- interface hygiene and operability (8 checks).

CSC-IFC-0007/0008 are implemented as the single modelled conflict this rule family requires: a
switch with any `switchport voice vlan` port is judged by 0008 (global CDP must stay on for
phone provisioning) instead of 0007 (CDP should be off globally), never both.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config


def _routed_like(cfg: "Config"):
    return tuple(i for i in cfg.interfaces()
                 if i.kind not in ("loopback", "tunnel")
                 and cfg.has("ip address", scope=i.node)
                 and not cfg.has("switchport", scope=i.node))


@rule("CSC-IFC-0001", supplies=("interface",))
def hardcoded_speed_duplex(cfg: "Config", ctx: "Context"):
    for iface in _util.access_like_interfaces(cfg):
        sp = cfg.find_one("speed", scope=iface.node)
        du = cfg.find_one("duplex", scope=iface.node)
        sp_bad = sp is not None and len(sp.line.tokens) > 1 and sp.line.tokens[1].lower() != "auto"
        du_bad = du is not None and len(du.line.tokens) > 1 and du.line.tokens[1].lower() != "auto"
        if sp_bad or du_bad:
            anchor = sp.line if sp_bad else (du.line if du_bad else iface.evidence_line)
            yield ctx.finding(line=anchor, params={"interface": iface.name}, title_suffix=iface.name)


@rule("CSC-IFC-0002", supplies=("interface",))
def trunk_no_description(cfg: "Config", ctx: "Context"):
    seen: set[str] = set()
    for iface in cfg.interfaces(role="trunk") + cfg.interfaces(role="uplink"):
        if iface.name in seen:
            continue
        seen.add(iface.name)
        if not cfg.has("description", scope=iface.node):
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-IFC-0003", supplies=("interface",))
def proxy_arp_enabled(cfg: "Config", ctx: "Context"):
    for iface in _routed_like(cfg):
        if _util.is_on(cfg, ctx, "ip.proxy-arp", scope=iface.node):
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              title_suffix=iface.name)


@rule("CSC-IFC-0004", supplies=("interface",))
def redirects_unreachables_enabled(cfg: "Config", ctx: "Context"):
    for iface in _routed_like(cfg):
        bad = (_util.is_on(cfg, ctx, "ip.redirects", scope=iface.node)
               or _util.is_on(cfg, ctx, "ip.unreachables", scope=iface.node))
        if bad:
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              title_suffix=iface.name)


@rule("CSC-IFC-0005", supplies=("interface",))
def directed_broadcast_enabled(cfg: "Config", ctx: "Context"):
    for iface in cfg.interfaces():
        n = cfg.find_one("ip directed-broadcast", scope=iface.node)
        if n is not None:
            yield ctx.finding(line=n.line, params={"interface": iface.name}, title_suffix=iface.name)


@rule("CSC-IFC-0006", supplies=("interface",))
def urpf_absent(cfg: "Config", ctx: "Context"):
    for iface in _routed_like(cfg):
        if not cfg.has("ip verify unicast source", scope=iface.node):
            yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                              role_source=iface.role_source, title_suffix=iface.name)


def _voice_present(cfg: "Config") -> bool:
    return any(cfg.has("switchport voice vlan", scope=i.node) for i in cfg.interfaces())


@rule("CSC-IFC-0007")
def cdp_enabled_globally(cfg: "Config", ctx: "Context"):
    if _voice_present(cfg):
        return
    if _util.is_on(cfg, ctx, "cdp.run"):
        n = _util.observed_node(cfg, ctx, "cdp.run")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-IFC-0008")
def cdp_disabled_with_voice(cfg: "Config", ctx: "Context"):
    if not _voice_present(cfg):
        return
    if not _util.is_on(cfg, ctx, "cdp.run"):
        n = _util.observed_node(cfg, ctx, "cdp.run")
        yield ctx.finding(line=n.line if n else None)
