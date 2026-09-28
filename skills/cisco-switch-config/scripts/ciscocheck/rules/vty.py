"""VTY -- line and interactive access (11 checks)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config


def _range_params(r) -> dict:
    return {"line_range": f"{r.first} {r.last}"}


def _range_suffix(r) -> str:
    return f"vty {r.first} {r.last}"


def _transport_ok(values: set[str]) -> bool:
    # `none` disables the transport entirely, which trivially
    # satisfies "does not accept a non-SSH transport" -- it is the most restrictive setting
    # a vty line can have, not a gap.
    return bool(values) and (values <= {"ssh"} or values == {"none"})


@rule("CSC-VTY-0001")
def non_ssh_transport(cfg: "Config", ctx: "Context"):
    for r in cfg.line_ranges("vty"):
        eff = _util.effective_scoped(cfg, ctx, "line.transport-input", r.node)
        values = set((eff.value or "").split())
        ok = eff.state == "off" or _transport_ok(values)
        if ok:
            continue
        node = cfg.find_one("transport input", scope=r.node) if r.node is not None else None
        line = node.line if node is not None else (r.node.line if r.node is not None else None)
        yield ctx.finding(line=line, title_suffix=_range_suffix(r))


def _has_real_inbound_access_class(cfg: "Config", node) -> bool:
    """Only an
    IPv4 `access-class NAME in [vrf-also]` with a real (non-placeholder) ACL name actually
    restricts inbound vty access. An IPv6-only clause leaves IPv4 wide open, an `out`-direction
    clause (with or without the trailing `vrf-also` keyword) never touches inbound connections
    at all, and an unfilled `<REPLACE-ME:...>` name restricts nothing -- none of these may be
    read as "restricted". `vrf-also` is a valid trailing keyword after the direction (it tells
    IOS to also apply the ACL to VRF-associated sessions) and must not change which token is
    read as the direction.
    """
    for n in cfg.children_of(node, "access-class"):
        toks = [t.lower() for t in n.line.tokens]
        if len(toks) >= 2 and toks[1] == "ipv6":
            continue
        rest = toks[2:]  # everything after "access-class NAME"
        if rest and rest[-1] == "vrf-also":
            rest = rest[:-1]
        if not rest or rest[-1] != "in":
            continue
        acl_name = n.line.tokens[1] if len(n.line.tokens) > 1 else None
        if acl_name is None or _util.is_placeholder_token(acl_name):
            continue
        return True
    return False


@rule("CSC-VTY-0002", supplies=("line_range", "acl_name"))
def no_access_class(cfg: "Config", ctx: "Context"):
    for r in cfg.line_ranges("vty"):
        if r.node is not None and _has_real_inbound_access_class(cfg, r.node):
            continue
        params = dict(_range_params(r))
        params["acl_name"] = _util.UNKNOWN_ACL
        line = r.node.line if r.node is not None else None
        yield ctx.finding(line=line, params=params, title_suffix=_range_suffix(r))


@rule("CSC-VTY-0003", supplies=("acl_name",))
def access_class_undefined_acl(cfg: "Config", ctx: "Context"):
    for kind, name, node in cfg.refs.undefined():
        if kind != "acl" or node.line.head != "access-class":
            continue
        yield ctx.finding(line=node.line, params={"acl_name": name}, title_suffix=name)


@rule("CSC-VTY-0004", supplies=("line_range",))
def bad_exec_timeout(cfg: "Config", ctx: "Context"):
    for r in cfg.line_ranges("vty"):
        eff = _util.effective_scoped(cfg, ctx, "line.exec-timeout", r.node)
        mins, secs = 10, 0
        if eff.value:
            parts = eff.value.split()
            try:
                mins = int(parts[0])
                secs = int(parts[1]) if len(parts) > 1 else 0
            except (ValueError, IndexError):
                mins, secs = 10, 0
        if not ((mins, secs) == (0, 0) or mins > 10):
            continue
        node = cfg.find_one("exec-timeout", scope=r.node) if r.node is not None else None
        line = node.line if node is not None else (r.node.line if r.node is not None else None)
        yield ctx.finding(line=line, params=_range_params(r), title_suffix=_range_suffix(r))


@rule("CSC-VTY-0005", supplies=("line_range",))
def local_password(cfg: "Config", ctx: "Context"):
    # The title is "A line carries a local password", not "a vty
    # line" -- `line con 0` is exactly as vulnerable to a shared line-level password as vty.
    # The catalogue's remediation template is vty-specific (`line vty {line_range}`), which
    # is imprecise for a con-line finding; `line_range` is still supplied as the con line
    # number so the rendered text at least names the right line to fix, even though it will
    # read "line vty <n>" instead of "line con <n>" (a known, accepted limitation of the
    # catalogue text, not fixed here).
    for r in cfg.line_ranges("vty"):
        if r.node is None:
            continue
        n = cfg.find_one("password", scope=r.node)
        if n is not None:
            yield ctx.finding(line=n.line, params=_range_params(r), title_suffix=_range_suffix(r))
    for r in cfg.line_ranges("con"):
        if r.node is None:
            continue
        n = cfg.find_one("password", scope=r.node)
        if n is not None:
            yield ctx.finding(line=n.line, params={"line_range": f"con {r.first}"},
                              title_suffix=f"con {r.first}")


@rule("CSC-VTY-0006")
def aux_not_disabled(cfg: "Config", ctx: "Context"):
    for r in cfg.line_ranges("aux"):
        if r.node is None:
            continue
        no_exec = cfg.has("no exec", scope=r.node)
        transport_none = False
        tnode = cfg.find_one("transport input", scope=r.node)
        if tnode is not None:
            rest = [t.lower() for t in tnode.line.tokens[2:]]
            transport_none = rest == ["none"]
        if not (no_exec and transport_none):
            yield ctx.finding(line=r.node.line)


@rule("CSC-VTY-0007")
def con_hygiene(cfg: "Config", ctx: "Context"):
    for r in cfg.line_ranges("con"):
        if r.node is None:
            yield ctx.finding(line=None)
            continue
        eff = ctx.defaults.effective(cfg, ctx.platform, "line.logging-synchronous", scope=r.node)
        has_timeout = cfg.has("exec-timeout", scope=r.node)
        if eff.state != "on" or not has_timeout:
            yield ctx.finding(line=r.node.line)


@rule("CSC-VTY-0008", supplies=("line_range",))
def transport_output_unrestricted(cfg: "Config", ctx: "Context"):
    for r in cfg.line_ranges("vty"):
        eff = _util.effective_scoped(cfg, ctx, "line.transport-output", r.node)
        values = set((eff.value or "").split())
        ok = eff.state == "off" or _transport_ok(values)
        if ok:
            continue
        node = cfg.find_one("transport output", scope=r.node) if r.node is not None else None
        line = node.line if node is not None else (r.node.line if r.node is not None else None)
        yield ctx.finding(line=line, params=_range_params(r), title_suffix=_range_suffix(r))


@rule("CSC-VTY-0009")
def login_block_for_absent(cfg: "Config", ctx: "Context"):
    if not _util.is_on(cfg, ctx, "login.block-for"):
        n = _util.observed_node(cfg, ctx, "login.block-for")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-VTY-0010")
def login_banner_absent(cfg: "Config", ctx: "Context"):
    if not (cfg.has("banner login") or cfg.has("banner motd")):
        yield ctx.finding(line=None)


_BANNER_KEYWORDS = ("authoriz", "monitor", "consent", "prosecut")


@rule("CSC-VTY-0011")
def login_banner_trivial(cfg: "Config", ctx: "Context"):
    anchor = cfg.find_one("banner login") or cfg.find_one("banner motd")
    if anchor is None:
        return
    body = []
    in_banner = False
    for line in cfg.lines():
        if line is anchor.line:
            in_banner = True
            body.append(line.text)
            continue
        if in_banner:
            if line.kind == "opaque":
                body.append(line.text)
            elif line.kind == "opaque-close":
                body.append(line.text)
                break
            else:
                break
    text = " ".join(body).lower()
    hits = sum(1 for k in _BANNER_KEYWORDS if k in text)
    if hits < 3:
        yield ctx.finding(line=anchor.line)
