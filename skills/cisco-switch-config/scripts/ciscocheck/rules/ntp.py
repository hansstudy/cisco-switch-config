"""NTP (7 checks)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config


def _ntp_host(tokens) -> str | None:
    """The address/hostname argument of an `ntp server`/`ntp peer` line:
    `ntp server [vrf <name>] <host> ...` puts an optional `vrf <name>` clause
    before the actual address, so the naive "token 2" position reads the VRF name (or the
    literal word `vrf`) as the host on a `vrf`-qualified line."""
    low = [t.lower() for t in tokens]
    idx = 2
    if len(low) > 3 and low[2] == "vrf":
        idx = 4
    return tokens[idx] if len(tokens) > idx else None


@rule("CSC-NTP-0001", supplies=("host",))
def no_ntp_server(cfg: "Config", ctx: "Context"):
    if not cfg.has("ntp server"):
        yield ctx.finding(line=None, params={"host": _util.UNKNOWN_HOST})


@rule("CSC-NTP-0002", supplies=("host",))
def fewer_than_two_sources(cfg: "Config", ctx: "Context"):
    nodes = cfg.find("ntp server") + cfg.find("ntp peer")
    if len(nodes) < 2:
        host = (_ntp_host(nodes[0].line.tokens) if nodes else None) or _util.UNKNOWN_HOST
        yield ctx.finding(line=nodes[0].line if nodes else None, params={"host": host})


@rule("CSC-NTP-0003")
def authenticate_absent(cfg: "Config", ctx: "Context"):
    if not _util.is_on(cfg, ctx, "ntp.authenticate"):
        n = _util.observed_node(cfg, ctx, "ntp.authenticate")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-NTP-0004", supplies=("host", "key_id"))
def server_no_key(cfg: "Config", ctx: "Context"):
    for n in cfg.find("ntp server"):
        toks = [t.lower() for t in n.line.tokens]
        if "key" not in toks:
            host = _ntp_host(n.line.tokens) or _util.UNKNOWN_HOST
            yield ctx.finding(line=n.line, params={"host": host, "key_id": _util.UNKNOWN_KEY_ID})


def _trusted_key_ids(tokens) -> set[str]:
    """`ntp trusted-key <n> - <m>` is an inclusive range, not two
    keys with a stray `-` between them -- `1 - 3` trusts 1, 2 AND 3. A plain digit-scan (as
    the old code did) silently drops every key strictly between the two endpoints."""
    if "-" in tokens:
        idx = tokens.index("-")
        if 0 < idx < len(tokens) - 1 and tokens[idx - 1].isdigit() and tokens[idx + 1].isdigit():
            a, b = int(tokens[idx - 1]), int(tokens[idx + 1])
            if a <= b:
                return {str(v) for v in range(a, b + 1)}
    return {t for t in tokens if t.isdigit()}


@rule("CSC-NTP-0005", supplies=("key_id",))
def key_not_trusted(cfg: "Config", ctx: "Context"):
    # `ciscocheck.refs.ReferenceIndex` defines an "ntp-key" from `ntp authentication-key N`
    # and treats `ntp trusted-key N` as just another *use* of that same key -- it has no
    # notion of "trusted" at all. That fits a key that was never created, but not this check,
    # which is specifically about a key that exists and is bound to a server yet was never
    # marked trusted. Computed directly from the trusted-key and server/peer key sets instead
    # of `cfg.refs`, which cannot express that distinction.
    trusted: set[str] = set()
    for n in cfg.find("ntp trusted-key"):
        trusted |= _trusted_key_ids(n.line.tokens[2:])
    seen: set[str] = set()
    for n in cfg.find("ntp server") + cfg.find("ntp peer"):
        toks = [t.lower() for t in n.line.tokens]
        if "key" not in toks:
            continue
        i = toks.index("key")
        if i + 1 >= len(n.line.tokens) or not n.line.tokens[i + 1].isdigit():
            continue
        key_id = n.line.tokens[i + 1]
        if key_id in trusted or key_id in seen:
            continue
        seen.add(key_id)
        yield ctx.finding(line=n.line, params={"key_id": key_id}, title_suffix=key_id)


@rule("CSC-NTP-0006", supplies=("key_id",))
def authentication_key_md5(cfg: "Config", ctx: "Context"):
    for n in cfg.find("ntp authentication-key"):
        toks = [t.lower() for t in n.line.tokens]
        if "md5" in toks:
            key_id = n.line.tokens[2] if len(n.line.tokens) > 2 else _util.UNKNOWN_KEY_ID
            yield ctx.finding(line=n.line, params={"key_id": key_id})


@rule("CSC-NTP-0007")
def source_not_stable(cfg: "Config", ctx: "Context"):
    if not cfg.has("ntp source"):
        yield ctx.finding(line=None)
