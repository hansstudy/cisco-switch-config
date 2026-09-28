"""RES -- resilience, boot, stacking, recovery (8 checks)."""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from ..registry import extractor, rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config

_NETWORK_BOOT_RE = re.compile(r"(?i)^(tftp|ftp|http|https|rcp|scp)://")
_SWITCH_MEMBER_RE = re.compile(r"(?i)^switch\s+(\d+)\b")


@rule("CSC-RES-0001")
def no_boot_system(cfg: "Config", ctx: "Context"):
    if not cfg.has("boot system"):
        yield ctx.finding(line=None)


@rule("CSC-RES-0002")
def boot_system_network_url(cfg: "Config", ctx: "Context"):
    # The network image isn't always token 2. The Cat9k stack form
    # inserts `switch {N|all}` first (`boot system switch all tftp://...`), and the legacy
    # IOS space-separated form has no `scheme://` at all (`boot system tftp <file> <host>`) --
    # both name the transport as a bare token, not a URL.
    for n in cfg.find("boot system"):
        toks = [t.lower() for t in n.line.tokens]
        raw = n.line.tokens
        if any(_NETWORK_BOOT_RE.match(t) for t in raw[2:]):
            yield ctx.finding(line=n.line)
            continue
        if len(toks) > 2 and toks[2] in ("tftp", "ftp", "rcp"):
            yield ctx.finding(line=n.line)


@rule("CSC-RES-0003")
def errdisable_cause_absent(cfg: "Config", ctx: "Context"):
    # `psecure-violation` is the real Catalyst IOS/IOS-XE errdisable cause keyword for a
    # port-security violation shutdown (`switchport port-security violation shutdown`
    # driving `errdisable recovery cause psecure-violation`). The check previously required
    # the literal string "security-violation" instead, which is a different, real IOS-XE
    # errdisable cause (802.1x/dot1x violation recovery) that a port-security-only baseline
    # never emits -- generated baselines (which correctly use `psecure-violation`)
    # tripped a false "medium" every time. This check's own rationale ("BPDU
    # Guard, UDLD or a security violation") is specifically about port security, matching the
    # L2 family's port-security checks; there is no 802.1x feature anywhere else in this
    # catalogue for "security-violation" to correspond to, so it is dropped rather than kept
    # alongside `psecure-violation`.
    covered = {n.line.tokens[3].lower() for n in cfg.find("errdisable recovery cause")
              if len(n.line.tokens) > 3}
    if not {"bpduguard", "udld", "psecure-violation"} <= covered:
        yield ctx.finding(line=None)


@rule("CSC-RES-0004")
def errdisable_interval_low(cfg: "Config", ctx: "Context"):
    eff = ctx.defaults.effective(cfg, ctx.platform, "errdisable.recovery.interval")
    try:
        val = int((eff.value or "300").strip())
    except ValueError:
        val = 300
    if val < 300:
        n = _util.observed_node(cfg, ctx, "errdisable.recovery.interval")
        yield ctx.finding(line=n.line if n else None)


def _stack_evidence(cfg: "Config"):
    """(member numbers, first evidence node) for a stacked system.

    Evidence is any member-numbered `switch <N> ...` line -- `provision`, `renumber`,
    `priority`, etc. -- whichever the config happens to show. `switch N priority P` itself is
    privileged EXEC on Cat9300 and is never written into `show running-config`,
    so it cannot be the evidence a static audit keys stack presence
    on; it is one of the several forms this pattern also matches when it IS shown.
    """
    members: set[int] = set()
    first = None
    for n in cfg.find("switch"):
        m = _SWITCH_MEMBER_RE.match(" ".join(n.line.tokens))
        if m:
            members.add(int(m.group(1)))
            if first is None:
                first = n
    return members, first


@extractor("CSC-RES-0005")
def stack_priority_extractor(cfg: "Config", ctx: "Context"):
    # `switch N priority P` is privileged EXEC, stored outside
    # running-config, so a static audit cannot see -- let alone judge -- the actual priority.
    # The best a config-only check can do is tell the operator a stack exists and which member
    # numbers it has, so they can go run `show switch` / set priority interactively.
    members, anchor = _stack_evidence(cfg)
    if not members:
        return
    member_list = ", ".join(str(m) for m in sorted(members))
    yield ctx.finding(line=anchor.line if anchor else None, title_suffix=f"members {member_list}")


@rule("CSC-RES-0006")
def stack_mac_persistent_absent(cfg: "Config", ctx: "Context"):
    # The real Cat9300 17.x command is the global `stack-mac
    # persistent timer [0|n]`, not `switch stack-mac persistent-mac`. Only applies to a
    # config that shows stack evidence at all (see `_stack_evidence`) -- a single, unstacked
    # switch has no stack MAC to persist.
    members, _ = _stack_evidence(cfg)
    if not members:
        return
    if not cfg.has("stack-mac persistent timer"):
        yield ctx.finding(line=None)


@rule("CSC-RES-0007")
def redundancy_sso_absent(cfg: "Config", ctx: "Context"):
    r = cfg.find_one("redundancy")
    if r is None or not cfg.has("mode sso", scope=r):
        yield ctx.finding(line=r.line if r else None)


@rule("CSC-RES-0008")
def device_tracking_probe_defaults(cfg: "Config", ctx: "Context"):
    node = _util.observed_node(cfg, ctx, "ip.device-tracking")
    if node is None:
        return
    has_delay = cfg.has("probe delay", scope=node) or cfg.has("ip device tracking probe delay")
    has_interval = cfg.has("probe interval", scope=node) or cfg.has("ip device tracking probe interval")
    if not (has_delay and has_interval):
        yield ctx.finding(line=node.line)
