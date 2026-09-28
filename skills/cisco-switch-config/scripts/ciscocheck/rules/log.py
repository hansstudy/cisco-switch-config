"""LOG -- logging, timestamps, archive (9 checks)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config

_LEVELS = {"emergencies": 0, "alerts": 1, "critical": 2, "errors": 3, "warnings": 4,
           "notifications": 5, "informational": 6, "debugging": 7}


def _rank(value: str | None, default: str = "debugging") -> int:
    val = (value or default).strip().lower()
    if val in _LEVELS:
        return _LEVELS[val]
    if val.isdigit():
        return int(val)
    return _LEVELS[default]


# `logging <host-or-ip>` (no `host` keyword) is the pre-`logging
# host` legacy syntax for exactly the same thing and is still accepted today. Every other
# bare `logging <word>` global command names one of these known sub-features instead of a
# destination; a legacy destination line is a plain `logging <address>` two-token line whose
# second token is not one of them.
_LOGGING_KEYWORDS = frozenset({
    "host", "console", "buffered", "trap", "synchronous", "source-interface", "facility",
    "monitor", "on", "enable", "origin-id", "rate-limit", "history", "queue-limit",
    "userinfo", "esm", "persistent", "filter", "discriminator", "count", "server-arp"})


def _all_logging_destinations(cfg: "Config"):
    legacy = tuple(n for n in cfg.find("logging")
                   if len(n.line.tokens) == 2
                   and n.line.tokens[1].lower() not in _LOGGING_KEYWORDS)
    return cfg.find("logging host") + legacy


@rule("CSC-LOG-0001", supplies=("host",))
def no_logging_host(cfg: "Config", ctx: "Context"):
    if not _all_logging_destinations(cfg):
        yield ctx.finding(line=None, params={"host": _util.UNKNOWN_HOST})


@rule("CSC-LOG-0002", supplies=("host",))
def fewer_than_two_destinations(cfg: "Config", ctx: "Context"):
    nodes = _all_logging_destinations(cfg)
    if len(nodes) < 2:
        host = nodes[0].line.tokens[-1] if nodes else _util.UNKNOWN_HOST
        yield ctx.finding(line=nodes[0].line if nodes else None, params={"host": host})


@rule("CSC-LOG-0003")
def trap_level_low(cfg: "Config", ctx: "Context"):
    eff = ctx.defaults.effective(cfg, ctx.platform, "logging.trap")
    if _rank(eff.value, "informational") < _LEVELS["informational"]:
        n = _util.observed_node(cfg, ctx, "logging.trap")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-LOG-0004")
def timestamps_log_incomplete(cfg: "Config", ctx: "Context"):
    n = cfg.find_one("service timestamps log")
    if n is None:
        yield ctx.finding(line=None)
        return
    toks = {t.lower() for t in n.line.tokens}
    if not {"datetime", "msec", "localtime", "show-timezone"} <= toks:
        yield ctx.finding(line=n.line)


@rule("CSC-LOG-0005")
def buffered_too_small(cfg: "Config", ctx: "Context"):
    n = cfg.find_one("logging buffered")
    if n is None:
        yield ctx.finding(line=None)
        return
    size = next((int(t) for t in n.line.tokens[2:] if t.isdigit()), None)
    if size is None or size < 16384:
        yield ctx.finding(line=n.line)


@rule("CSC-LOG-0006")
def source_interface_absent(cfg: "Config", ctx: "Context"):
    if not cfg.has("logging source-interface"):
        yield ctx.finding(line=None)


@rule("CSC-LOG-0007")
def archive_log_config_absent(cfg: "Config", ctx: "Context"):
    arc = cfg.find_one("archive")
    if arc is None or not cfg.has("log config", scope=arc):
        yield ctx.finding(line=arc.line if arc else None)


@rule("CSC-LOG-0008")
def archive_hidekeys_absent(cfg: "Config", ctx: "Context"):
    arc = cfg.find_one("archive")
    if arc is None:
        return
    lc = cfg.find_one("log config", scope=arc)
    if lc is None:
        return
    if not cfg.has("hidekeys", scope=lc):
        yield ctx.finding(line=lc.line)


@rule("CSC-LOG-0009")
def console_verbose(cfg: "Config", ctx: "Context"):
    eff = ctx.defaults.effective(cfg, ctx.platform, "logging.console")
    if eff.state != "on":
        return
    if _rank(eff.value, "debugging") > _LEVELS["critical"]:
        n = _util.observed_node(cfg, ctx, "logging.console")
        yield ctx.finding(line=n.line if n else None)
