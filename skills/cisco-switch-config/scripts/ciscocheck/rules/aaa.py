"""AAA -- authentication, authorization, accounting (12 checks)."""
from __future__ import annotations

from typing import TYPE_CHECKING

from ..registry import rule
from . import _util

if TYPE_CHECKING:  # pragma: no cover
    from ..model import Context
    from ..parser import Config


@rule("CSC-AAA-0001")
def new_model_absent(cfg: "Config", ctx: "Context"):
    if not _util.is_on(cfg, ctx, "aaa.new-model"):
        n = _util.observed_node(cfg, ctx, "aaa.new-model")
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-AAA-0002")
def login_method_list_absent(cfg: "Config", ctx: "Context"):
    if not cfg.has("aaa authentication login"):
        yield ctx.finding(line=None)


@rule("CSC-AAA-0003")
def login_no_local_fallback(cfg: "Config", ctx: "Context"):
    for n in cfg.find("aaa authentication login"):
        toks = [t.lower() for t in n.line.tokens]
        if "local" not in toks and "local-case" not in toks:
            yield ctx.finding(line=n.line)


@rule("CSC-AAA-0004")
def enable_authentication_absent(cfg: "Config", ctx: "Context"):
    if not cfg.has("aaa authentication enable default"):
        yield ctx.finding(line=None)


def _method_list_is_none(node) -> bool:
    """`... default none` is present text but configures no actual
    authorization/accounting method -- IOS performs the operation unconditionally with no
    check at all. A check that only asks "is the line present" must not read `none` as
    compliant."""
    toks = [t.lower() for t in node.line.tokens]
    return bool(toks) and toks[-1] == "none"


@rule("CSC-AAA-0005")
def authorization_exec_absent(cfg: "Config", ctx: "Context"):
    n = cfg.find_one("aaa authorization exec")
    if n is None or _method_list_is_none(n):
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-AAA-0006")
def authorization_console_absent(cfg: "Config", ctx: "Context"):
    if not cfg.has("aaa authorization console"):
        yield ctx.finding(line=None)


@rule("CSC-AAA-0007")
def accounting_commands_15_absent(cfg: "Config", ctx: "Context"):
    n = cfg.find_one("aaa accounting commands 15")
    if n is None or _method_list_is_none(n):
        yield ctx.finding(line=n.line if n else None)


@rule("CSC-AAA-0008", supplies=("host",))
def fewer_than_two_servers(cfg: "Config", ctx: "Context"):
    # A `server-private` host nested under `aaa group server
    # {tacacs+,radius} NAME` is a real, independent AAA server and must count alongside the
    # named `tacacs server`/`radius server`/legacy `*-server host` forms.
    servers = (cfg.find("tacacs server") + cfg.find("radius server")
               + cfg.find("tacacs-server host") + cfg.find("radius-server host")
               + cfg.find("server-private"))
    if len(servers) < 2:
        host = _util.UNKNOWN_HOST
        if servers:
            toks = servers[0].line.tokens
            if len(toks) > 2:
                host = toks[2]
        yield ctx.finding(line=servers[0].line if servers else None, params={"host": host})


@rule("CSC-AAA-0009", supplies=("group",))
def undefined_server_group(cfg: "Config", ctx: "Context"):
    for kind, name, node in cfg.refs.undefined():
        if kind != "aaa-group":
            continue
        yield ctx.finding(line=node.line, params={"group": name}, title_suffix=name)


@rule("CSC-AAA-0010")
def local_user_weak_password(cfg: "Config", ctx: "Context"):
    for n in cfg.find("username"):
        toks = [t.lower() for t in n.line.tokens]
        if "privilege" not in toks:
            continue
        pi = toks.index("privilege")
        if pi + 1 >= len(toks) or toks[pi + 1] != "15":
            continue
        if "password" not in toks:
            continue
        wi = toks.index("password")
        # `username ... password <value>` with no leading type digit
        # is the *implicit* type-0 (cleartext) form -- `password` has no type-5/8/9 variant
        # at all, so ANY value after it (explicit `0`/`7`, or no marker) is type 0 or type 7.
        if wi + 1 >= len(toks):
            continue
        vi = wi + 2 if toks[wi + 1] in ("0", "7") else wi + 1
        if vi >= len(n.line.tokens):
            continue
        if _util.is_placeholder_token(n.line.tokens[vi]):
            continue
        name = n.line.tokens[1] if len(n.line.tokens) > 1 else None
        yield ctx.finding(line=n.line, title_suffix=name)


_STRONG_ENABLE_ALGO = ("sha256", "scrypt")
_STRONG_ENABLE_TYPE = ("8", "9")


def _enable_secret_weakness(n):
    """Decide whether one `enable secret`/`enable algorithm-type ... secret` line is weak.

    Returns `(weak, value_token)`, or `(None, None)` if the line doesn't actually match
    either construct at all (a prior false negative: code that only ever
    looked for `cfg.find("enable secret")`, whose pattern requires "secret" to be literally
    the second token -- `enable algorithm-type md5 secret X` never matched it in the first
    place, so its algorithm was never inspected).
    """
    toks = [t.lower() for t in n.line.tokens]
    raw = n.line.tokens
    if toks[:2] == ["enable", "algorithm-type"] and len(toks) >= 4 and toks[3] == "secret":
        algo = toks[2]
        value = raw[4] if len(raw) > 4 else None
        return algo not in _STRONG_ENABLE_ALGO, value
    if toks[:2] == ["enable", "secret"]:
        rest = toks[2:]
        raw_rest = raw[2:]
        if rest[:1] == ["level"] and len(rest) >= 2 and rest[1].isdigit():
            rest = rest[2:]
            raw_rest = raw_rest[2:]
        if rest[:1] and rest[0].isdigit() and len(rest[0]) <= 2:
            type_ = rest[0]
            value = raw_rest[1] if len(raw_rest) > 1 else None
            return type_ not in _STRONG_ENABLE_TYPE, value
        value = raw_rest[0] if raw_rest else None
        return True, value  # no type marker at all: implicit weak form
    return None, None


@rule("CSC-AAA-0011")
def enable_password_or_weak_secret(cfg: "Config", ctx: "Context"):
    pw = cfg.find_one("enable password")
    if pw is not None:
        yield ctx.finding(line=pw.line)
        return
    for n in cfg.find("enable secret") + cfg.find("enable algorithm-type"):
        weak, value = _enable_secret_weakness(n)
        if weak is None:
            continue
        # An unfilled `<REPLACE-ME:...>` value is neither proven
        # weak nor proven strong -- it is simply not configured yet. `CSC-SELF-0007` already
        # notes the unfilled placeholder; this check must not also call it "weak".
        if value is not None and _util.is_placeholder_token(value):
            continue
        if weak:
            yield ctx.finding(line=n.line)


@rule("CSC-AAA-0012")
def password_encryption_absent(cfg: "Config", ctx: "Context"):
    if not _util.is_on(cfg, ctx, "service.password-encryption"):
        n = _util.observed_node(cfg, ctx, "service.password-encryption")
        yield ctx.finding(line=n.line if n else None)
