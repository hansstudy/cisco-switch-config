"""SNMP (10 checks).

CSC-SNMP-0003 relies on `mask.py`'s known-weak-value classification: a community
matching a well-known default is redacted with `cls == "snmp-community-weak"` instead of the
ordinary `"snmp-community"` class. The verdict travels as a class name on the already-masked
`Redaction` record; this rule never sees, compares against, or needs the raw value.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import extractor, rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config


@rule("CSC-SNMP-0001")
def v1v2c_community_configured(cfg: "Config", ctx: "Context"):
    for n in cfg.find("snmp-server community"):
        yield ctx.finding(line=n.line)


@rule("CSC-SNMP-0002")
def community_read_write(cfg: "Config", ctx: "Context"):
    for n in cfg.find("snmp-server community"):
        toks = [t.lower() for t in n.line.tokens]
        if "rw" in toks:
            yield ctx.finding(line=n.line)


@rule("CSC-SNMP-0003")
def community_known_weak(cfg: "Config", ctx: "Context"):
    for n in cfg.find("snmp-server community"):
        if any(r.cls == "snmp-community-weak" for r in n.line.redactions):
            yield ctx.finding(line=n.line)


@rule("CSC-SNMP-0004", supplies=("acl_name",))
def community_no_acl(cfg: "Config", ctx: "Context"):
    # The IPv4 ACL is whatever comes right after the
    # optional `view`/`RO`/`RW` clauses. An `ipv6 <acl>` clause in that slot means no IPv4
    # ACL was given at all (IPv4 stays unrestricted), and an unfilled `<REPLACE-ME:...>` name
    # restricts nothing -- neither may be read as "restricted".
    for n in cfg.find("snmp-server community"):
        raw_rest = n.line.tokens[3:]
        rest = [t.lower() for t in raw_rest]
        if rest[:1] == ["view"] and len(rest) >= 2:
            rest = rest[2:]
            raw_rest = raw_rest[2:]
        if rest[:1] in (["ro"], ["rw"]):
            rest = rest[1:]
            raw_rest = raw_rest[1:]
        restricted = bool(rest) and rest[0] != "ipv6" and not _util.is_placeholder_token(raw_rest[0])
        if not restricted:
            yield ctx.finding(line=n.line, params={"acl_name": _util.UNKNOWN_ACL})


@rule("CSC-SNMP-0005", supplies=("acl_name",))
def community_acl_undefined(cfg: "Config", ctx: "Context"):
    for kind, name, node in cfg.refs.undefined():
        if kind != "acl" or node.line.head != "snmp-server":
            continue
        yield ctx.finding(line=node.line, params={"acl_name": name}, title_suffix=name)


@rule("CSC-SNMP-0006", supplies=("group",))
def no_v3_priv_group(cfg: "Config", ctx: "Context"):
    for n in cfg.find("snmp-server group"):
        toks = [t.lower() for t in n.line.tokens]
        if "v3" in toks and "priv" in toks:
            return
    yield ctx.finding(line=None, params={"group": _util.UNKNOWN_GROUP})


@rule("CSC-SNMP-0007", supplies=("host", "group"))
def trap_target_v1v2c(cfg: "Config", ctx: "Context"):
    for n in cfg.find("snmp-server host"):
        toks = [t.lower() for t in n.line.tokens]
        version = None
        if "version" in toks:
            i = toks.index("version")
            if i + 1 < len(toks):
                version = toks[i + 1]
        if version in (None, "1", "2c"):
            host = n.line.tokens[2] if len(n.line.tokens) > 2 else _util.UNKNOWN_HOST
            yield ctx.finding(line=n.line, params={"host": host, "group": _util.UNKNOWN_GROUP})


@rule("CSC-SNMP-0008")
def no_enable_traps(cfg: "Config", ctx: "Context"):
    nodes = cfg.find("snmp-server enable traps")
    toksets = [[t.lower() for t in n.line.tokens] for n in nodes]
    have_link = any("linkdown" in t or "linkup" in t or "snmp" in t for t in toksets)
    have_config = any("config" in t for t in toksets)
    have_auth = any("aaa" in t or "authentication" in t for t in toksets)
    if not (have_link and have_config and have_auth):
        yield ctx.finding(line=nodes[0].line if nodes else None)


@rule("CSC-SNMP-0009")
def ifindex_persist_absent(cfg: "Config", ctx: "Context"):
    if not _util.is_on(cfg, ctx, "snmp.ifindex.persist"):
        n = _util.observed_node(cfg, ctx, "snmp.ifindex.persist")
        yield ctx.finding(line=n.line if n else None)


@extractor("CSC-SNMP-0010")
def v3_user_inventory(cfg: "Config", ctx: "Context"):
    for n in cfg.find("snmp-server group"):
        toks = [t.lower() for t in n.line.tokens]
        if "v3" in toks:
            yield ctx.finding(line=n.line)
            return
