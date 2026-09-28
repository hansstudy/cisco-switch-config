"""Reference-resolution layer. Runs entirely on masked text.

For a known construct only the value token is redacted, so ACL numbers, key ids, peer
addresses and group names survive for resolution (3.4.3).
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:  # pragma: no cover
    from .model import Node
    from .parser import Config

RefKind = Literal["acl", "vlan", "key-chain", "aaa-group", "class-map", "policy-map",
                  "route-map", "prefix-list", "interface", "ntp-key", "parser-view",
                  "interface-range-macro"]

_BUILTIN_GROUPS = frozenset({"tacacs+", "radius", "ldap", "local", "local-case", "none",
                             "enable", "line", "krb5", "if-authenticated"})


def _vlan_ids(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part)
        if not m:
            continue
        a = int(m.group(1))
        b = int(m.group(2)) if m.group(2) else a
        if 0 < a <= b <= 4094 and b - a <= 4094:
            out.extend(range(a, b + 1))
    return out


class ReferenceIndex:
    __slots__ = ("_defs", "_uses")

    def __init__(self) -> None:
        self._defs: dict[tuple[str, str], "Node"] = {}
        self._uses: list[tuple[str, str, "Node"]] = []

    # --- public API (frozen)
    def defined(self, kind: RefKind, name: str) -> bool:
        return (kind, self._norm(kind, name)) in self._defs

    def definition(self, kind: RefKind, name: str) -> "Node | None":
        return self._defs.get((kind, self._norm(kind, name)))

    def uses(self, kind: RefKind, name: str) -> tuple["Node", ...]:
        key = self._norm(kind, name)
        return tuple(n for k, v, n in self._uses if k == kind and v == key)

    def undefined(self) -> tuple[tuple[RefKind, str, "Node"], ...]:
        out = []
        for kind, name, node in self._uses:
            if (kind, name) in self._defs:
                continue
            if kind == "aaa-group" and name.lower() in _BUILTIN_GROUPS:
                continue
            if kind == "class-map" and name == "class-default":
                continue
            out.append((kind, name, node))
        out.sort(key=lambda t: t[2].line.line_no)
        return tuple(out)

    # --- construction
    @staticmethod
    def _norm(kind: str, name: str) -> str:
        if kind == "interface":
            from .parser import canonical_interface
            return canonical_interface(name)
        return name

    def _def(self, kind: str, name: str, node: "Node") -> None:
        self._defs.setdefault((kind, self._norm(kind, name)), node)

    def _use(self, kind: str, name: str, node: "Node") -> None:
        if name.startswith("[REDACTED") or name.startswith("<REPLACE-ME:"):
            return
        self._uses.append((kind, self._norm(kind, name), node))

    @classmethod
    def build(cls, cfg: "Config") -> "ReferenceIndex":
        idx = cls()
        for node in cfg.walk():
            line = node.line
            if line.kind not in ("command", "opaque-open"):
                continue
            t = line.tokens
            low = [x.lower() for x in t]
            n = len(t)

            def at(i: int) -> str:
                return t[i] if i < n else ""

            # ---------------- definitions
            if low[:2] == ["ip", "access-list"] and n >= 4:
                idx._def("acl", t[3] if low[2] in ("standard", "extended", "role-based")
                         else t[2], node)
            elif low[:2] == ["ipv6", "access-list"] and n >= 3:
                idx._def("acl", t[2], node)
            elif low[:1] == ["access-list"] and n >= 2:
                idx._def("acl", t[1], node)
            elif low[:1] == ["vlan"] and n >= 2 and not node.mode_path:
                for v in _vlan_ids(t[1]):
                    idx._def("vlan", str(v), node)
            elif low[:2] == ["key", "chain"] and n >= 3:
                idx._def("key-chain", t[2], node)
            elif low[:3] == ["aaa", "group", "server"] and n >= 5:
                idx._def("aaa-group", t[4], node)
            elif low[:1] == ["class-map"] and n >= 2:
                idx._def("class-map", t[-1], node)
            elif low[:1] == ["policy-map"] and n >= 2:
                idx._def("policy-map", t[-1], node)
            elif low[:1] == ["route-map"] and n >= 2:
                idx._def("route-map", t[1], node)
            elif low[:2] in (["ip", "prefix-list"], ["ipv6", "prefix-list"]) and n >= 3:
                idx._def("prefix-list", t[2], node)
            elif low[:1] == ["interface"] and n >= 2 and low[1] != "range" and not node.mode_path:
                idx._def("interface", t[1], node)
            elif low[:2] == ["ntp", "authentication-key"] and n >= 3:
                idx._def("ntp-key", t[2], node)
            elif low[:2] == ["parser", "view"] and n >= 3:
                idx._def("parser-view", t[2], node)
            elif low[:2] == ["define", "interface-range"] and n >= 3:
                idx._def("interface-range-macro", t[2], node)

            # ---------------- uses
            if low[:1] == ["access-class"] and n >= 2:
                idx._use("acl", t[2] if low[1] == "ipv6" and n >= 3 else t[1], node)
            elif low[:2] == ["ip", "access-group"] and n >= 3:
                idx._use("acl", t[2], node)
            elif low[:2] == ["ipv6", "traffic-filter"] and n >= 3:
                idx._use("acl", t[2], node)
            elif low[:3] == ["ip", "http", "access-class"] and n >= 4:
                idx._use("acl", t[4] if low[3] in ("ipv4", "ipv6") and n >= 5 else t[3], node)
            elif low[:2] == ["snmp-server", "community"] and n >= 4:
                rest = t[3:]
                if rest and rest[0].lower() == "view" and len(rest) >= 2:
                    rest = rest[2:]
                if rest and rest[0].lower() in ("ro", "rw"):
                    rest = rest[1:]
                if rest and rest[0].lower() == "ipv6" and len(rest) >= 2:
                    idx._use("acl", rest[1], node)
                    rest = rest[2:]
                if rest:
                    idx._use("acl", rest[0], node)
            elif low[:2] == ["snmp-server", "group"] and "access" in low:
                i = low.index("access")
                if i + 1 < n:
                    idx._use("acl", t[i + 2] if low[i + 1] == "ipv6" and i + 2 < n else t[i + 1], node)
            elif low[:2] == ["ntp", "access-group"] and n >= 4:
                idx._use("acl", t[-1], node)
            elif low[:3] == ["match", "ip", "address"] and n >= 4:
                if low[3] == "prefix-list":
                    for name in t[4:]:
                        idx._use("prefix-list", name, node)
                else:
                    for name in t[3:]:
                        idx._use("acl", name, node)
            if low[:2] == ["switchport", "access"] and at(2).lower() == "vlan" and at(3).isdigit():
                idx._use("vlan", t[3], node)
            elif low[:2] == ["switchport", "voice"] and at(2).lower() == "vlan" and at(3).isdigit():
                idx._use("vlan", t[3], node)
            elif low[:4] == ["switchport", "trunk", "native", "vlan"] and at(4).isdigit():
                idx._use("vlan", t[4], node)
            if "key-chain" in low:
                i = low.index("key-chain")
                if i + 1 < n and low[:1] != ["key"]:
                    name = t[i + 1]
                    if low[i + 1] == "eigrp" and i + 3 < n:
                        name = t[i + 3]
                    idx._use("key-chain", name, node)
            if low[:1] == ["aaa"] and low[1:2] in (["authentication"], ["authorization"],
                                                   ["accounting"]):
                for i, x in enumerate(low):
                    if x == "group" and i + 1 < n:
                        idx._use("aaa-group", t[i + 1], node)
            if low[:1] == ["class"] and n >= 2 and node.mode_path and \
                    node.mode_path[-1].startswith("policy-map"):
                idx._use("class-map", t[-1], node)
            if low[:1] == ["service-policy"] and n >= 2:
                idx._use("policy-map", t[-1], node)
            if "route-map" in low and low[0] != "route-map":
                i = low.index("route-map")
                if i + 1 < n:
                    idx._use("route-map", t[i + 1], node)
            if low[:1] == ["neighbor"] and "prefix-list" in low:
                i = low.index("prefix-list")
                if i + 1 < n:
                    idx._use("prefix-list", t[i + 1], node)
            if (low[-2:-1] == ["source-interface"] or low[:2] == ["ntp", "source"]
                    or low[:2] == ["snmp-server", "trap-source"]) and n >= 3:
                idx._use("interface", t[-1], node)
            if low[:2] in (["ntp", "server"], ["ntp", "peer"]) and "key" in low:
                i = low.index("key")
                if i + 1 < n and t[i + 1].isdigit():
                    idx._use("ntp-key", t[i + 1], node)
            if low[:2] == ["ntp", "trusted-key"] and n >= 3:
                for v in re.findall(r"\d+", t[2]):
                    idx._use("ntp-key", v, node)
            if low[:1] == ["username"] and "view" in low:
                i = low.index("view")
                if i + 1 < n:
                    idx._use("parser-view", t[i + 1], node)
            if low[:3] == ["interface", "range", "macro"] and n >= 4:
                idx._use("interface-range-macro", t[3], node)
        return idx
