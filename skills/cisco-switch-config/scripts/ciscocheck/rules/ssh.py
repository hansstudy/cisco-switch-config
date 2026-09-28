"""SSH and device crypto (9 checks).

`data/defaults.json` carries platform defaults for version, DH size, retries and time-out
(`ip.ssh.version`, `ip.ssh.dh-min-size`, `ip.ssh.authentication-retries`, `ip.ssh.time-out`),
so those four checks go through `ctx.defaults.effective()`. The three algorithm-restriction
checks (encryption/mac/kex) have no matching defaults-table entry -- IOS/IOS-XE permit a wide,
release-dependent algorithm set until an operator restricts it, which is not a fixed value a
defaults table can encode -- so they are evaluated directly against the configured list, with
"not configured at all" treated as "nothing was restricted" (the least safe case).
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import extractor, rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config

_WEAK_ENC = {"3des-cbc", "des-cbc", "des", "aes-128-cbc", "aes-192-cbc", "aes-256-cbc",
             "aes128-cbc", "aes192-cbc", "aes256-cbc", "blowfish-cbc", "cast128-cbc", "arcfour"}
_WEAK_MAC = {"hmac-sha1", "hmac-sha1-96", "hmac-md5", "hmac-md5-96"}
_WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}


@rule("CSC-SSH-0001")
def version_not_2(cfg: "Config", ctx: "Context"):
    eff = ctx.defaults.effective(cfg, ctx.platform, "ip.ssh.version")
    if (eff.value or "").strip() != "2":
        n = _util.observed_node(cfg, ctx, "ip.ssh.version")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-SSH-0002")
def no_host_key_prereqs(cfg: "Config", ctx: "Context"):
    # A literal `cfg.has("ip domain-name")` misses IOS-XE 16/17's own
    # running-config spelling, `ip domain name` (no hyphen) -- dialect-sensitive.
    # `dialect.json`'s `ip-domain-name` intent covers both forms on
    # both platforms.
    if not ctx.dialect.matches(cfg, "ip-domain-name", ctx.platform):
        yield ctx.finding(line=None)


@rule("CSC-SSH-0003")
def dh_min_size_low(cfg: "Config", ctx: "Context"):
    eff = ctx.defaults.effective(cfg, ctx.platform, "ip.ssh.dh-min-size")
    try:
        size = int((eff.value or "0").strip())
    except ValueError:
        size = 0
    if size < 2048:
        n = _util.observed_node(cfg, ctx, "ip.ssh.dh-min-size")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-SSH-0004")
def encryption_permits_weak(cfg: "Config", ctx: "Context"):
    n = cfg.find_one("ip ssh server algorithm encryption")
    if n is None:
        yield ctx.finding(line=None)
        return
    # "ip ssh server algorithm encryption" is a 5-token pattern; algorithms start at index 5.
    algos = {t.lower() for t in n.line.tokens[5:]}
    if algos & _WEAK_ENC:
        yield ctx.finding(line=n.line)


@rule("CSC-SSH-0005")
def mac_permits_weak(cfg: "Config", ctx: "Context"):
    n = cfg.find_one("ip ssh server algorithm mac")
    if n is None:
        yield ctx.finding(line=None)
        return
    algos = {t.lower() for t in n.line.tokens[5:]}
    if algos & _WEAK_MAC:
        yield ctx.finding(line=n.line)


@rule("CSC-SSH-0006")
def kex_permits_weak(cfg: "Config", ctx: "Context"):
    n = cfg.find_one("ip ssh server algorithm kex")
    if n is None:
        yield ctx.finding(line=None)
        return
    algos = {t.lower() for t in n.line.tokens[5:]}
    if algos & _WEAK_KEX:
        yield ctx.finding(line=n.line)


@rule("CSC-SSH-0007")
def authentication_retries_high(cfg: "Config", ctx: "Context"):
    eff = ctx.defaults.effective(cfg, ctx.platform, "ip.ssh.authentication-retries")
    try:
        retries = int((eff.value or "0").strip())
    except ValueError:
        retries = 0
    if retries > 3:
        n = _util.observed_node(cfg, ctx, "ip.ssh.authentication-retries")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-SSH-0008")
def time_out_high(cfg: "Config", ctx: "Context"):
    eff = ctx.defaults.effective(cfg, ctx.platform, "ip.ssh.time-out")
    try:
        timeout = int((eff.value or "0").strip())
    except ValueError:
        timeout = 0
    if timeout > 60:
        n = _util.observed_node(cfg, ctx, "ip.ssh.time-out")
        yield ctx.finding(line=n.line if n else None)


@extractor("CSC-SSH-0009")
def trustpoint_extractor(cfg: "Config", ctx: "Context"):
    n = cfg.find_one("crypto pki trustpoint") or cfg.find_one("crypto pki certificate chain")
    if n is not None:
        yield ctx.finding(line=n.line)
