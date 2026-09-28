"""MGT -- management plane and global services (14 checks)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config

_REF_PARAM_KEY = {"acl": "acl_name", "aaa-group": "group", "ntp-key": "key_id", "vlan": "vlan"}


@rule("CSC-MGT-0001")
def http_server(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "ip.http.server"):
        n = _util.observed_node(cfg, ctx, "ip.http.server")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-MGT-0002", supplies=("acl_name",))
def https_no_access_class(cfg: "Config", ctx: "Context"):
    reachable = _util.is_on(cfg, ctx, "ip.http.server") or _util.is_on(cfg, ctx, "ip.http.secure-server")
    if reachable and not cfg.has("ip http access-class"):
        n = _util.observed_node(cfg, ctx, "ip.http.secure-server") or cfg.find_one("ip http server")
        yield ctx.finding(line=n.line if n else None, params={"acl_name": _util.UNKNOWN_ACL})


@rule("CSC-MGT-0003")
def http_without_https(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "ip.http.server") and not _util.is_on(cfg, ctx, "ip.http.secure-server"):
        n = cfg.find_one("ip http server")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-MGT-0004")
def service_pad(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "service.pad"):
        n = _util.observed_node(cfg, ctx, "service.pad")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-MGT-0005")
def small_servers(cfg: "Config", ctx: "Context"):
    tcp = _util.is_on(cfg, ctx, "service.tcp-small-servers")
    udp = _util.is_on(cfg, ctx, "service.udp-small-servers")
    if tcp or udp:
        n = (_util.observed_node(cfg, ctx, "service.tcp-small-servers")
             or _util.observed_node(cfg, ctx, "service.udp-small-servers"))
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-MGT-0006")
def bootp_server(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "ip.bootp.server"):
        n = _util.observed_node(cfg, ctx, "ip.bootp.server")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-MGT-0007")
def finger(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "ip.finger") or cfg.has("service finger"):
        n = (_util.observed_node(cfg, ctx, "ip.finger") or cfg.find_one("service finger"))
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-MGT-0008")
def source_route(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "ip.source-route"):
        n = _util.observed_node(cfg, ctx, "ip.source-route")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-MGT-0009")
def service_config(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "service.config"):
        n = _util.observed_node(cfg, ctx, "service.config")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-MGT-0010")
def vstack(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "vstack"):
        n = _util.observed_node(cfg, ctx, "vstack")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-MGT-0011")
def call_home(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "service.call-home") or cfg.has("call-home"):
        n = _util.observed_node(cfg, ctx, "service.call-home") or cfg.find_one("call-home")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-MGT-0012")
def netconf_restconf_unrestricted(cfg: "Config", ctx: "Context"):
    # `ip http access-class` governs the HTTP/RESTCONF listener
    # only. NETCONF (port 830, over SSH) is restricted by its own access-list clause under
    # `netconf-yang`, never by the HTTP ACL -- the two features are judged independently.
    netconf = cfg.find_one("netconf-yang")
    if netconf is not None:
        restricted = any("access-list" in [t.lower() for t in n.line.tokens]
                         for n in cfg.find("netconf-yang"))
        if not restricted:
            yield ctx.finding(line=netconf.line, title_suffix="netconf-yang")
    restconf = cfg.find_one("restconf")
    if restconf is not None and not cfg.has("ip http access-class"):
        yield ctx.finding(line=restconf.line, title_suffix="restconf")


def _domain_lookup_state(cfg: "Config", ctx: "Context"):
    """`ip domain-lookup`'s effective state, both surface forms:
    IOS-XE accepts both the hyphenated and the space-separated spelling. `data/defaults.json`'s
    `ip.domain-lookup` key has no `intent` link to resolve this through `effective()`, so the
    dialect table's own `ip-domain-lookup` intent (both positive forms) is read directly, with
    the same "last matching line wins" tie-break `DefaultsTable.effective()` uses; default is
    on when neither a positive nor a negated form appears anywhere.
    """
    candidates = []
    for form in ctx.dialect.forms("ip-domain-lookup", ctx.platform):
        for n in cfg.find(form):
            candidates.append((n.line.line_no, True, n))
        for n in cfg.find("no " + form):
            candidates.append((n.line.line_no, False, n))
    if not candidates:
        return True, None
    candidates.sort(key=lambda c: c[0])
    _, on, node = candidates[-1]
    return on, node


@rule("CSC-MGT-0013")
def domain_lookup_no_resolver(cfg: "Config", ctx: "Context"):
    on, node = _domain_lookup_state(cfg, ctx)
    if on and not cfg.has("ip name-server"):
        yield ctx.finding(line=node.line if node else None)


@rule("CSC-MGT-0014", supplies=("acl_name", "group", "key_id", "vlan"))
def undefined_reference(cfg: "Config", ctx: "Context"):
    for kind, name, node in cfg.refs.undefined():
        params = {}
        pkey = _REF_PARAM_KEY.get(kind)
        if pkey:
            params[pkey] = name
        yield ctx.finding(line=node.line, params=params, title_suffix=f"{kind} {name}")
