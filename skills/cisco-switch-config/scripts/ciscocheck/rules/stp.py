"""STP -- spanning tree (10 checks)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import extractor, rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config


@rule("CSC-STP-0001")
def mode_pvst(cfg: "Config", ctx: "Context"):
    if ctx.dialect.matches(cfg, "stp.mode.rapid", ctx.platform):
        return
    n = cfg.find_one("spanning-tree mode")
    yield ctx.finding(line=n.line if n else None)


@rule("CSC-STP-0002", supplies=("interface",))
def portfast_access_missing(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "spanning-tree.portfast.default"):
        return
    for iface in _util.access_like_interfaces(cfg):
        if ctx.dialect.matches(cfg, "stp.portfast.access", ctx.platform, scope=iface.node):
            continue
        yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                          role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-STP-0003")
def bpduguard_default_absent(cfg: "Config", ctx: "Context"):
    if not _util.is_on(cfg, ctx, "spanning-tree.portfast.bpduguard.default"):
        n = _util.observed_node(cfg, ctx, "spanning-tree.portfast.bpduguard.default")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-STP-0004", supplies=("interface",))
def bpduguard_port_missing(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "spanning-tree.portfast.bpduguard.default"):
        return
    for iface in _util.access_like_interfaces(cfg):
        if ctx.dialect.matches(cfg, "stp.bpduguard.port", ctx.platform, scope=iface.node):
            continue
        yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                          role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-STP-0005", supplies=("interface",))
def root_guard_absent(cfg: "Config", ctx: "Context"):
    # Root Guard belongs on ports facing a peer that must NEVER become root -- never on the
    # link that is itself this switch's own path toward the root bridge. The right way to
    # decide this is from role PLUS topology, because role alone is
    # not reliable: `role="uplink"` is meant to be that one upstream path (by
    # precedence), but the parser's description-based heuristic can also catch a genuine
    # downstream link whose description merely contains "to <neighbour>". The topology signal this rule adds: a switch with only ONE
    # trunk/uplink-role interface almost certainly has that as its sole path to the root, so
    # guarding it would break the very thing STP is protecting -- skip entirely. A switch with
    # two or more (a distribution switch with several downstream trunks, or genuinely
    # redundant uplinks) has no single link that can be assumed safe, so every one of them is
    # evaluated; guarding a redundant, non-forwarding uplink is standard practice, not a
    # false positive.
    candidates = cfg.interfaces(role="uplink") + cfg.interfaces(role="trunk")
    if len(candidates) <= 1:
        return
    for iface in candidates:
        if ctx.dialect.matches(cfg, "stp.guard.root", ctx.platform, scope=iface.node):
            continue
        yield ctx.finding(line=iface.evidence_line, params={"interface": iface.name},
                          role_source=iface.role_source, title_suffix=iface.name)


@rule("CSC-STP-0006")
def loopguard_default_absent(cfg: "Config", ctx: "Context"):
    if not _util.is_on(cfg, ctx, "spanning-tree.loopguard.default"):
        n = _util.observed_node(cfg, ctx, "spanning-tree.loopguard.default")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-STP-0007", supplies=("interface",))
def bpdufilter_enabled(cfg: "Config", ctx: "Context"):
    # The global switch-wide default forms insert "portfast"[+"edge"]
    # BEFORE "bpdufilter" (`spanning-tree portfast [edge] bpdufilter default`), so they never
    # token-prefix-match the plain `spanning-tree bpdufilter` pattern that catches the global
    # `spanning-tree bpdufilter default`/per-port `spanning-tree bpdufilter enable` forms.
    for n in (cfg.find("spanning-tree portfast bpdufilter default")
              + cfg.find("spanning-tree portfast edge bpdufilter default")):
        yield ctx.finding(line=n.line, params={"interface": _util.UNKNOWN_INTERFACE},
                          title_suffix="global default")
    for n in cfg.find("spanning-tree bpdufilter"):
        toks = [t.lower() for t in n.line.tokens]
        if len(toks) >= 3 and toks[2] == "disable":
            continue
        iface_name = None
        if n.mode_path and n.mode_path[-1].startswith("interface "):
            iface_name = n.mode_path[-1].split(" ", 1)[1]
        params = {"interface": iface_name or _util.UNKNOWN_INTERFACE}
        yield ctx.finding(line=n.line, params=params, title_suffix=iface_name or "global default")


@rule("CSC-STP-0008", supplies=("vlan",))
def no_root_priority(cfg: "Config", ctx: "Context"):
    # MST mode roots by instance, not by VLAN (`spanning-tree mst <instance> priority` /
    # `... root primary`). Mapping instances back to VLANs is not attempted here -- any
    # explicit MST priority/root statement is treated as covering every VLAN, since the
    # alternative (ignoring MST posture entirely) reads a fully hardened MST config as if it
    # had never set a root priority at all.
    for n in cfg.find("spanning-tree mst"):
        toks = [t.lower() for t in n.line.tokens]
        if len(toks) >= 2 and toks[1] == "configuration":
            continue
        if "priority" in toks or "root" in toks:
            return
    covered: set[int] = set()
    for n in cfg.find("spanning-tree vlan"):
        toks = n.line.tokens
        if len(toks) < 3:
            continue
        for part in toks[2].split(","):
            part = part.strip()
            if "-" in part:
                a, b = part.split("-", 1)
                if a.strip().isdigit() and b.strip().isdigit():
                    covered.update(range(int(a), int(b) + 1))
            elif part.isdigit():
                covered.add(int(part))
    for v in cfg.vlans():
        if v == 1 or v in covered:
            continue
        yield ctx.finding(line=None, params={"vlan": str(v)}, title_suffix=f"VLAN {v}")


@extractor("CSC-STP-0009")
def root_placement_extractor(cfg: "Config", ctx: "Context"):
    for n in cfg.find("spanning-tree vlan"):
        if "priority" in [t.lower() for t in n.line.tokens]:
            yield ctx.finding(line=n.line)
            return


@rule("CSC-STP-0010")
def udld_not_enabled(cfg: "Config", ctx: "Context"):
    if _util.is_on(cfg, ctx, "udld"):
        return
    for iface in cfg.interfaces():
        if ctx.dialect.matches(cfg, "udld.port", ctx.platform, scope=iface.node):
            return
    n = _util.observed_node(cfg, ctx, "udld")
    yield ctx.finding(line=n.line if n else None)
