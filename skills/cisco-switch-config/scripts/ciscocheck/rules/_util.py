"""Internal helpers shared by the rule modules.

Not part of the frozen `rules/__init__.py` import list and never imported by
anything outside `ciscocheck.rules`. Pure convenience over the frozen `Config`/`Context` API
-- it adds no new capability, only avoids repeating the same few idioms in
every family module. Standard library only; imports nothing outside `ciscocheck.*`.
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..model import Context, Node
    from ..parser import Config

# The exact spelling of `mask.is_placeholder()`'s regex, duplicated here on
# purpose: rules must never import `ciscocheck.mask` at all -- a rule reads
# only the already-masked model, so a rule that needs to recognise an unfilled
# `<REPLACE-ME:...>` slot re-states the frozen pattern instead of reaching into mask.py.
_PLACEHOLDER_RE = re.compile(r"^<REPLACE-ME:[a-z0-9-]+>$")


def is_placeholder_token(token: str) -> bool:
    """True when `token` is exactly an unfilled `<REPLACE-ME:...>` placeholder.

    A placeholder sitting in a *restriction* slot (an access-class
    ACL name, a community's ACL) must never be read as "restricted" -- the operator has not
    filled it in yet, so nothing is actually enforced. Checks that verify a restriction
    exists must treat a placeholder value the same as an absent one. The opposite direction
    also holds: a check that verifies a *value is weak* (e.g. CSC-AAA-0011's
    enable-secret algorithm) must NOT call a placeholder "weak", because no algorithm has
    actually been chosen yet either way. Both call sites use this one helper so the exemption
    is spelled once.
    """
    return bool(_PLACEHOLDER_RE.match(token))

# Placeholder values for a required remediation variable whose real value cannot be known
# from the config alone ("a secret position ... is always <REPLACE-ME:...>";
# extended here to any not-yet-known advisory value so `supplies=` can still name the
# variable honestly -- the rule always puts *something* usable in `params`).
UNKNOWN_ACL = "<REPLACE-ME:acl-name>"
UNKNOWN_HOST = "<REPLACE-ME:host>"
UNKNOWN_GROUP = "<REPLACE-ME:group-name>"
UNKNOWN_VLAN = "<REPLACE-ME:vlan-id>"
UNKNOWN_KEY_ID = "<REPLACE-ME:key-id>"
UNKNOWN_INTERFACE = "<REPLACE-ME:interface-name>"

# Roles treated as "an edge port with an end-user or phone attached" for the access-port
# hygiene checks (STP/L2/DHCP/IFC families): both plain access ports and voice+data ports,
# never trunk/uplink/routed/management/unused/unknown.
ACCESS_LIKE_ROLES = ("access", "voice-access")


def access_like_interfaces(cfg: "Config"):
    return tuple(i for i in cfg.interfaces() if i.role in ACCESS_LIKE_ROLES)


def observed_node(cfg: "Config", ctx: "Context", key: str, *, scope: "Node | None" = None):
    """The Node whose line is the observed positive or negated form of a defaults key,
    or None when the key's state came only from the platform default.

    `ctx.defaults.effective()` intentionally returns only value/state/observed -- never the
    node -- so a rule that wants an evidence line alongside the computed state looks it up
    the same way `effective()` itself does, through the same `forms()` list.
    """
    for form in ctx.defaults.forms(ctx.platform, key):
        n = cfg.find_one(form, scope=scope)
        if n is not None:
            return n
        n = cfg.find_one("no " + form, scope=scope)
        if n is not None:
            return n
    return None


def is_on(cfg: "Config", ctx: "Context", key: str, *, scope: "Node | None" = None) -> bool:
    return ctx.defaults.effective(cfg, ctx.platform, key, scope=scope).state == "on"


def effective_scoped(cfg: "Config", ctx: "Context", key: str, node: "Node | None"):
    """`ctx.defaults.effective()` for a scope that may not exist as text at all -- an
    unobserved `LineRange`, whose `node` is `None` by construction.

    `node=None` here means "this specific sub-range has no configuration", which must
    resolve to the bare platform default. Passing `scope=None` straight to `effective()`
    means something different and far more dangerous: `effective()`'s own semantics define
    `scope=None` as "search every node at every depth", so an unobserved `vty 5 15` would
    silently inherit whatever an *observed* `vty 0 4` block happens to set nearby.
    """
    if node is None:
        dv = ctx.defaults.value(ctx.platform, key)
        from ..defaults import Effective
        return Effective(value=dv.value, state=dv.state, observed=False)
    return ctx.defaults.effective(cfg, ctx.platform, key, scope=node)


def line_range_params(first: int, last: int) -> dict:
    return {"line_range": f"{first} {last}"}


# ---------------------------------------------------------------------------------------
# Absence checks should use `ctx.defaults.effective()` wherever a
# matching `data/defaults.json` key exists, never a bare
# `not cfg.has(...)`. The checks below stay on `cfg.has()` deliberately, because there is no
# defaults-table entry for the construct at all -- confirmed by reading `data/defaults.json`
# key by key, not by omission -- so there is no implicit "on by default" or "off by default"
# value to reconcile against; the literal text is the only signal that exists.
#
#   CSC-AAA-0002  aaa authentication login            (no `aaa.authentication.*` key)
#   CSC-AAA-0004  aaa authentication enable default    (no `aaa.authentication.*` key)
#   CSC-AAA-0006  aaa authorization console            (no `aaa.authorization.*` key)
#   CSC-AAA-0005  aaa authorization exec               (no `aaa.authorization.*` key; also
#                                                        needs the `... default none` check,
#                                                        layered on top of has())
#   CSC-AAA-0007  aaa accounting commands 15           (no `aaa.accounting.*` key; same
#                                                        `... none` layering as AAA-0005)
#   CSC-LOG-0001  logging host                         (no `logging.host` key)
#   CSC-LOG-0006  logging source-interface              (no `logging.source-interface` key)
#   CSC-NTP-0001  ntp server                            (no `ntp.server` key)
#   CSC-NTP-0007  ntp source                            (no `ntp.source` key)
#   CSC-RES-0001  boot system                           (no `boot.system` key -- `boot.system`
#                                                        is a dialect intent name, 3.6, used
#                                                        only for its per-platform remediation
#                                                        text, not a defaults-table entry)
#   CSC-RES-0006  switch stack-mac persistent           (no `switch.stack-mac.*` key)
#   CSC-DHCP-0006 ip dhcp snooping database              (no `ip.dhcp.snooping.database` key)
#   CSC-VTY-0010  banner login / banner motd            (no `banner.*` key)
#
# If a future defaults.json revision adds one of these keys, the corresponding rule should
# move to `is_on()`/`effective_scoped()` at that time -- this comment is the record of why it
# does not today, not a claim that it never should.
