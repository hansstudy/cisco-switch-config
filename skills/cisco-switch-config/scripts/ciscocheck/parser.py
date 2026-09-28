"""The parser contract and the `Config` API rules call.

Raw-text rule: raw content lives only in the parameters and the
`raw_lines` locals of `parse()` / `parse_pair()` and in the pure pre-clean helpers they call
(which return repaired lines and content-free notes). The only structural or content
inspection is `mask.mask_lines(raw_lines)`; everything after it sees masked text only, and
the raw names are deleted before a `Config` is built.
"""
from __future__ import annotations

import fnmatch
import json
import re
from types import MappingProxyType
from typing import Any, Iterable, Literal, Mapping

from . import mask
from .defaults import DefaultsTable
from .dialect import DialectTable
from .model import (ROLES, Interface, Line, LineRange, Node, Note, Platform, Redaction, Role)
from .refs import ReferenceIndex

# --------------------------------------------------------------------------- errors


class NotACiscoConfigError(Exception):
    """Empty input, or input that is not a Cisco configuration. Carries NO input text."""

    def __init__(self, line_count: int = 0) -> None:
        self.line_count = int(line_count)
        super().__init__(f"input is empty or is not a Cisco IOS/IOS-XE configuration "
                         f"({self.line_count} lines read)")


class RoleMapError(Exception):
    """A malformed --role-map file. The message names the key and the offending value only."""


# --------------------------------------------------------------------------- tables

_TABLES: tuple[DefaultsTable, DialectTable] | None = None


def _tables() -> tuple[DefaultsTable, DialectTable]:
    global _TABLES
    if _TABLES is None:
        dialect = DialectTable.load()
        _TABLES = (DefaultsTable.load(None, dialect), dialect)
    return _TABLES


# --------------------------------------------------------------------------- naming (3.5.2)

_ABBREV: tuple[tuple[tuple[str, ...], str], ...] = (
    (("TwentyFiveGigE", "Twe", "TwentyFiveGig"), "TwentyFiveGigE"),
    (("TwoGigabitEthernet", "Tw", "Two"), "TwoGigabitEthernet"),
    (("TenGigabitEthernet", "TenGig", "Te"), "TenGigabitEthernet"),
    (("FortyGigabitEthernet", "Fo", "FortyGig"), "FortyGigabitEthernet"),
    (("HundredGigE", "Hu", "HundredGig"), "HundredGigE"),
    (("GigabitEthernet", "Gig", "Gi", "G"), "GigabitEthernet"),
    (("FastEthernet", "Fas", "Fa", "F"), "FastEthernet"),
    (("AppGigabitEthernet", "Ap", "App"), "AppGigabitEthernet"),
    (("Port-channel", "Po"), "Port-channel"),
    (("Ethernet", "Eth", "Et"), "Ethernet"),
    (("Vlan", "Vl"), "Vlan"),
    (("Loopback", "Lo"), "Loopback"),
    (("Tunnel", "Tu"), "Tunnel"),
    (("Serial", "Se"), "Serial"),
    (("BDI",), "BDI"),
)
# flattened, longest abbreviation first (Twe before Tw, TenGig before Te)
_ABBREV_FLAT = tuple(sorted(((a.lower(), canon) for abbrs, canon in _ABBREV for a in abbrs),
                            key=lambda x: len(x[0]), reverse=True))
_NAME_RE = re.compile(r"^([A-Za-z][A-Za-z-]*?)\s*(\d.*)?$")


def canonical_interface(name: str) -> str:
    """Canonical long form (3.5.2): exact abbreviation first, then the longest listed
    abbreviation the prefix extends while remaining a prefix of the canonical name."""
    name = name.strip()
    m = _NAME_RE.match(name)
    if not m:
        return name
    prefix, rest = m.group(1), m.group(2) or ""
    low = prefix.lower()
    for abbr, canon in _ABBREV_FLAT:
        if low == abbr:
            return canon + rest
    for abbr, canon in _ABBREV_FLAT:
        if low.startswith(abbr) and canon.lower().startswith(low):
            return canon + rest
    return name


def interface_kind(canonical: str) -> str:
    for pfx, kind in (("Vlan", "svi"), ("Port-channel", "portchannel"),
                      ("Loopback", "loopback"), ("Tunnel", "tunnel")):
        if canonical.startswith(pfx) and canonical[len(pfx):len(pfx) + 1].isdigit():
            return kind
    return "physical"


_SEG_RE = re.compile(
    r"^(?P<pfx>[A-Za-z][A-Za-z-]*[A-Za-z]|[A-Za-z])\s*(?P<path>(?:\d+[/:])*)(?P<first>\d+)"
    r"(?:\s*-\s*(?P<end>\S.*?))?$")
_MAX_MEMBERS = 4096


def expand_range(spec: str) -> list[str] | None:
    """Expand an `interface range` argument (3.5 row c). None when the grammar fails."""
    members: list[str] = []
    for seg in spec.split(","):
        seg = seg.strip()
        if not seg:
            return None
        m = _SEG_RE.match(seg)
        if not m:
            return None
        base = canonical_interface(m.group("pfx")) + m.group("path")
        first = int(m.group("first"))
        last = first
        if m.group("end"):
            em = re.search(r"(\d+)\s*$", m.group("end"))
            if not em:
                return None
            last = int(em.group(1))
        if last < first or last - first >= _MAX_MEMBERS:
            return None
        members.extend(f"{base}{i}" for i in range(first, last + 1))
    return members


# --------------------------------------------------------------------------- role map


class RoleMap(dict):
    """Canonical interface name -> role, plus the file's `management_vlan` and
    `vty_universe`. A plain Mapping is accepted by parse() as well."""

    management_vlan: int | None = None
    vty_universe: tuple[int, int] | None = None
    keys_given: int = 0


def load_role_map(doc: Any) -> RoleMap:
    """Validate a --role-map document (3.5.3). Raises RoleMapError naming key and value."""
    if isinstance(doc, (str, bytes)):
        try:
            doc = json.loads(doc)
        except ValueError:
            raise RoleMapError("role-map is not valid JSON") from None
    if not isinstance(doc, dict):
        raise RoleMapError("role-map must be a JSON object")
    allowed = {"version", "roles", "ranges", "management_vlan", "vty_universe"}
    for k in doc:
        if k not in allowed:
            raise RoleMapError(f'role-map key "{k}" is not recognised')
    if doc.get("version") != 1:
        raise RoleMapError(f'role-map key "version" has invalid value "{doc.get("version")}"')
    rm = RoleMap()
    roles = doc.get("roles") or {}
    ranges = doc.get("ranges") or {}
    if not isinstance(roles, dict) or not isinstance(ranges, dict):
        raise RoleMapError('role-map keys "roles" and "ranges" must be objects')
    for k, v in ranges.items():
        if v not in ROLES:
            raise RoleMapError(f'role-map key "{k}" has invalid role "{v}"')
        members = expand_range(str(k))
        if members is None:
            raise RoleMapError(f'role-map key "{k}" is not a valid interface range')
        for name in members:
            rm[name] = v
    for k, v in roles.items():
        if v not in ROLES:
            raise RoleMapError(f'role-map key "{k}" has invalid role "{v}"')
        rm[canonical_interface(str(k))] = v
    rm.keys_given = len(roles) + len(ranges)
    mv = doc.get("management_vlan")
    if mv is not None:
        if not isinstance(mv, int) or isinstance(mv, bool) or not 1 <= mv <= 4094:
            raise RoleMapError(f'role-map key "management_vlan" has invalid value "{mv}"')
        rm.management_vlan = mv
    vu = doc.get("vty_universe")
    if vu is not None:
        if (not isinstance(vu, list) or len(vu) != 2
                or not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in vu)
                or vu[0] > vu[1]):
            raise RoleMapError(f'role-map key "vty_universe" has invalid value "{vu}"')
        rm.vty_universe = (vu[0], vu[1])
    return rm


# --------------------------------------------------------------------------- decoding


def decode_input(data: bytes) -> tuple[str, str]:
    """Bytes -> (text, codec) with no U+FFFD replacement anywhere: a UTF-16 BOM, then strict
    UTF-8 (a BOM allowed; pre-clean notes it), then cp1252, then latin-1, which cannot fail.
    A browser paste saved as ANSI keeps its NBSP (0xA0), which NFKC in pre-clean turns into a
    space, so keyword matching still works."""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return data.decode("utf-16"), "utf-16"
        except UnicodeDecodeError:
            pass
    try:
        return data.decode("utf-8"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        return data.decode("cp1252"), "cp1252"
    except UnicodeDecodeError:
        return data.decode("latin-1"), "latin-1"


def decoding_note(codec: str) -> Note | None:
    """The content-free note naming a non-UTF-8 codec (CSC-SELF-0003, pre-clean class)."""
    if codec == "utf-8":
        return None
    return Note("CSC-SELF-0003", None, f"input decoded as {codec}")


# --------------------------------------------------------------------------- pre-clean (row i)

_PROMPT_RE = re.compile(
    r"^[A-Za-z0-9._-]+(\([^)]*\))?[#>]\s*(show|sh|conf\w*|term\w*|end|exit|wr\w*|copy)")
_PROMPT_ONLY_RE = re.compile(r"^[A-Za-z0-9._-]+(\([^)]*\))?[#>]\s*$")
_PAGER_RE = re.compile(r"\s?--More--(?:[ \x08]*\x08)?")
_SIZE_RE = re.compile(r"^Current configuration\s*:\s*\d+\s*bytes\s*$")


def _repair(line: str) -> tuple[str, str | None]:
    """One pre-clean decision for one line: (repaired line or "\\0" to drop, artefact class)."""
    if "--More--" in line:
        fixed = _PAGER_RE.sub("", line).replace("\x08", "")
        return (fixed if fixed.strip() else "\0"), "pager artefact"
    st = line.strip()
    if st == "Building configuration...":
        return "\0", "build-banner"
    if _SIZE_RE.match(st):
        return "\0", "size-banner"
    if _PROMPT_RE.match(st) or _PROMPT_ONLY_RE.match(st):
        return "\0", "prompt echo"
    return line, None


def _preclean(text: str) -> tuple[list[str], list[int], list[Note]]:
    notes: list[Note] = []
    if text.startswith("\ufeff"):
        text = text[1:]
        notes.append(Note("CSC-SELF-0003", 1, "bom"))
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    raw_lines = text.split("\n")
    if raw_lines and raw_lines[-1] == "":
        raw_lines.pop()
    kept: list[str] = []
    src: list[int] = []
    for i, ln in enumerate(raw_lines):
        fixed, cls = _repair(ln)
        if cls is not None:
            notes.append(Note("CSC-SELF-0003", i + 1, cls))
        if fixed != "\0":
            normalised = mask.normalise(fixed)          # NFKC, strip Cf/Cc
            if normalised != fixed:
                notes.append(Note("CSC-SELF-0003", i + 1, "input normalised"))
                fixed = normalised
        if fixed != "\0":
            kept.append(fixed)
            src.append(i + 1)
    # trailing end: text after the final `end` (never `end` itself)
    last_end = None
    for j in range(len(kept) - 1, -1, -1):
        if kept[j].rstrip() == "end":
            last_end = j
            break
    if last_end is not None and last_end < len(kept) - 1:
        if any(x.strip() for x in kept[last_end + 1:]):
            notes.append(Note("CSC-SELF-0003", src[last_end + 1], "trailing end"))
        del kept[last_end + 1:]
        del src[last_end + 1:]
    while kept and not kept[-1].strip():
        kept.pop()
        src.pop()
    return kept, src, notes


def _require_cisco(raw_lines: list[str], heads: frozenset[str]) -> None:
    """Exit-2 detection (3.5): runs before masking and quotes nothing."""
    nonblank = 0
    commands = 0
    known = 0
    for ln in raw_lines:
        st = ln.strip()
        if not st:
            continue
        nonblank += 1
        if st.startswith("!"):
            continue
        commands += 1
        if st.split()[0].lower() in heads:
            known += 1
    if commands < 3 or nonblank == 0 or known * 50 < nonblank:
        raise NotACiscoConfigError(len(raw_lines))


# --------------------------------------------------------------------------- Config


def _toks_match(pat: tuple[str, ...], toks: tuple[str, ...]) -> bool:
    if len(pat) > len(toks):
        return False
    if not pat:
        return True
    if pat[0].lower() != toks[0].lower():
        return False
    if (pat[0].lower() == "interface" and len(pat) >= 2 and len(toks) >= 2
            and pat[1].lower() != "range" and toks[1].lower() != "range"):
        if canonical_interface(pat[1]) != canonical_interface(toks[1]):
            return False
        return pat[2:] == toks[2:len(pat)]
    return pat[1:] == toks[1:len(pat)]


_HIDDEN = ("opaque", "opaque-close")


class Config:
    """The masked, parsed configuration. Nothing here holds a raw value."""

    __slots__ = ("platform", "platform_source", "nodes", "notes", "line_count", "role_map",
                 "management_vlan", "defaults", "dialect", "refs", "nesting",
                 "_all", "_lines", "_ifaces", "_iface_by_name", "_vty_universe", "_ranges")

    def __init__(self) -> None:
        self.platform: Platform = "iosxe"
        self.platform_source = "default"
        self.nodes: tuple[Node, ...] = ()
        self.notes: tuple[Note, ...] = ()
        self.line_count = 0
        self.role_map: Mapping[str, Role] = MappingProxyType({})
        self.management_vlan: int | None = None
        self.nesting = "indent"
        self._all: tuple[Node, ...] = ()
        self._lines: tuple[Line, ...] = ()
        self._ifaces: tuple[Interface, ...] = ()
        self._iface_by_name: dict[str, Interface] = {}
        self._vty_universe: tuple[int, int] | None = None
        self._ranges: dict[str, tuple[LineRange, ...]] = {}

    # --- helpers
    def walk(self) -> tuple[Node, ...]:
        """Every node, file order, including opaque bodies."""
        return self._all

    @staticmethod
    def _subtree(node: Node) -> list[Node]:
        out: list[Node] = []
        stack = list(reversed(node.children))
        while stack:
            n = stack.pop()
            out.append(n)
            stack.extend(reversed(n.children))
        return out

    @staticmethod
    def _norm(node: Node) -> str:
        return " ".join(node.line.tokens)

    def _matcher(self, pattern: str, regex: bool):
        if regex:
            rx = re.compile(pattern)
            return lambda n: rx.search(self._norm(n)) is not None
        pat = mask.tokenize(pattern)
        return lambda n: _toks_match(pat, n.line.tokens)

    # --- structural lookup
    def find(self, pattern: str, *, scope: Node | None = None,
             regex: bool = False) -> tuple[Node, ...]:
        pool = self._subtree(scope) if scope is not None else self._all
        ok = self._matcher(pattern, regex)
        return tuple(n for n in pool if n.line.kind not in _HIDDEN and n.line.tokens and ok(n))

    def find_one(self, pattern: str, *, scope: Node | None = None,
                 regex: bool = False) -> Node | None:
        found = self.find(pattern, scope=scope, regex=regex)
        return found[0] if found else None

    def has(self, pattern: str, *, scope: Node | None = None, regex: bool = False) -> bool:
        return bool(self.find(pattern, scope=scope, regex=regex))

    def children_of(self, node: Node, pattern: str | None = None, *,
                    recurse: bool = False, regex: bool = False) -> tuple[Node, ...]:
        pool = self._subtree(node) if recurse else list(node.children)
        if pattern is None:
            return tuple(pool)
        ok = self._matcher(pattern, regex)
        return tuple(n for n in pool if n.line.tokens and ok(n))

    def value_of(self, pattern: str, *, scope: Node | None = None,
                 group: int = 1) -> str | None:
        rx = re.compile(pattern)
        pool = self._subtree(scope) if scope is not None else self._all
        for n in pool:
            if n.line.kind in _HIDDEN:
                continue
            m = rx.search(self._norm(n))
            if m:
                try:
                    return m.group(group)
                except IndexError:
                    return None
        return None

    def lines(self) -> tuple[Line, ...]:
        return self._lines

    # --- domain views
    def interfaces(self, *, role: Role | None = None,
                   kind: str | None = None) -> tuple[Interface, ...]:
        return tuple(i for i in self._ifaces
                     if (role is None or i.role == role) and (kind is None or i.kind == kind))

    def interface(self, name: str) -> Interface | None:
        return self._iface_by_name.get(canonical_interface(name))

    def line_ranges(self, kind: Literal["con", "vty", "aux"]) -> tuple[LineRange, ...]:
        return self._ranges.get(kind, ())

    def vlans(self) -> tuple[int, ...]:
        seen: list[int] = []

        def add(ids: Iterable[int]) -> None:
            for v in ids:
                if 1 <= v <= 4094 and v not in seen:
                    seen.append(v)

        for n in self._all:
            if n.line.kind in _HIDDEN or not n.line.tokens:
                continue
            t = n.line.tokens
            low = [x.lower() for x in t]
            if low[0] == "vlan" and len(t) >= 2 and not n.mode_path:
                add(_vlan_list(t[1]))
            elif low[:3] in (["switchport", "access", "vlan"], ["switchport", "voice", "vlan"]) \
                    and len(t) >= 4:
                add(_vlan_list(t[3]))
            elif low[:4] == ["switchport", "trunk", "native", "vlan"] and len(t) >= 5:
                add(_vlan_list(t[4]))
            elif low[:4] == ["switchport", "trunk", "allowed", "vlan"] and len(t) >= 5:
                arg = t[5] if low[4] in ("add", "remove", "except") and len(t) >= 6 else t[4]
                add(_vlan_list(arg))
            elif low[0] == "interface" and len(t) >= 2 and low[1] != "range":
                c = canonical_interface(t[1])
                if c.startswith("Vlan") and c[4:].isdigit():
                    add([int(c[4:])])
        return tuple(seen)

    def hostname(self) -> str | None:
        n = self.find_one("hostname")
        if n is None or len(n.line.tokens) < 2:
            return None
        return n.line.tokens[1]


def _vlan_list(spec: str) -> list[int]:
    out: list[int] = []
    for part in spec.split(","):
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", part.strip())
        if not m:
            continue
        a = int(m.group(1))
        b = int(m.group(2)) if m.group(2) else a
        if a <= b and b - a < 4095:
            out.extend(range(a, b + 1))
    return out


# --------------------------------------------------------------------------- build


def _canon_element(element: str) -> str:
    if element.startswith("interface ") and not element.startswith("interface range"):
        parts = element.split(" ", 2)
        if len(parts) >= 2:
            return " ".join(["interface", canonical_interface(parts[1])] + parts[2:])
    return element


_DESC_MGMT = re.compile(r"(?i)\b(mgmt|management|oob)\b")
# Explicit uplink words only, whole-word. An earlier, broader
# list (`core`, `dist`, `agg`, `wan`, `to[-_ ]`) made "link to ACC-SW-01" downlinks uplinks, so
# STP-0005 skipped them. Description is still read on trunks, deliberately: without it a real
# uplink described "Uplink to core" and not port-channelled becomes a plain trunk, and the tool
# would advise root guard toward the root bridge - a harmful false positive. The finding stays
# heuristic (role_source "inferred-uplink"); --role-map is the override.
_DESC_UPLINK = re.compile(
    r"(?i)(?<![\w-])(uplink|upstream|to[-_ ]core|to[-_ ]dist(?:ribution)?)\b")


def _infer_platform(nodes: tuple[Node, ...]) -> tuple[Platform, str]:
    texts = [" ".join(n.line.tokens) for n in nodes if n.line.kind not in _HIDDEN]
    for t in texts:
        m = re.match(r"(?i)^version (\d+)\.", t)
        if m:
            major = int(m.group(1))
            if major in (16, 17, 3):
                return "iosxe", "inferred-version"
            if major in (12, 15):
                return "ios", "inferred-version"
    for t in texts:
        if t.lower().startswith("boot system"):
            image = re.split(r"[:/]", t.split()[-1])[-1].lower()
            for pat in ("cat9k*", "cat3k_caa*", "c3850*", "c9?00*", "*.spa.bin"):
                if fnmatch.fnmatchcase(image, pat):
                    return "iosxe", "inferred-image"
            for pat in ("c2960*", "c3560*", "c3750*"):
                if fnmatch.fnmatchcase(image, pat):
                    return "ios", "inferred-image"
    for t in texts:
        low = t.lower()
        if (low.startswith("device-tracking policy") or " portfast edge" in f" {low}"
                or low.startswith("license boot level")
                or low.startswith("ip http secure-active-session-modules")):
            return "iosxe", "inferred-surface"
    return "iosxe", "default"


def _role_for(iface_name: str, kind: str, children: tuple[Node, ...], role_map: Mapping[str, str],
              mgmt_vlan: int | None) -> tuple[str, str]:
    if iface_name in role_map:
        return role_map[iface_name], "role-map"
    toks = [tuple(x.lower() for x in c.line.tokens) for c in children
            if c.line.kind == "command" and c.line.tokens]

    def has(*prefix: str) -> bool:
        return any(t[:len(prefix)] == prefix for t in toks)

    desc = next((" ".join(c.line.tokens[1:]) for c in children
                 if c.line.head == "description"), "")
    trunkish = (has("switchport", "mode", "trunk") or has("switchport", "trunk", "encapsulation")
                or has("switchport", "mode", "dynamic", "desirable"))
    if has("shutdown") and not has("channel-group") and not has("switchport", "mode", "trunk"):
        return "unused", "inferred-shutdown"
    if kind == "svi" and has("ip", "address") and (
            (mgmt_vlan is not None and iface_name == f"Vlan{mgmt_vlan}") or _DESC_MGMT.search(desc)):
        return "management", "inferred-description"
    if has("no", "switchport") or (kind == "physical" and has("ip", "address")):
        return "routed", "inferred-routed"
    if trunkish and (has("channel-group") or _DESC_UPLINK.search(desc)):
        return "uplink", "inferred-uplink"
    if trunkish:
        return "trunk", "inferred-trunk"
    if has("switchport", "voice", "vlan"):
        return "voice-access", "inferred-voice"
    if has("switchport", "mode", "access") or has("switchport", "access", "vlan"):
        return "access", "inferred-access"
    return "unknown", "default"


def _apply_changed(text: str, reds: tuple[Redaction, ...],
                   flags: dict[int, bool]) -> tuple[str, tuple[Redaction, ...]]:
    if not flags:
        return text, reds
    new_reds = tuple(Redaction(r.cls, r.length, r.key, r.extent, flags.get(j, r.changed))
                     for j, r in enumerate(reds))
    counter = iter(range(len(reds)))

    def _sub(m: re.Match[str]) -> str:
        j = next(counter, None)
        if j is not None and flags.get(j):
            return mask.token(m.group("cls"), None if m.group("chars") is None
                              else int(m.group("chars")), changed=True)
        return m.group(0)

    return mask.REDACTION_RE.sub(_sub, text), new_reds


def _build(doc: mask.MaskedDocument, src: list[int], pre_notes: list[Note], *,
           platform: Platform | None, role_map: Mapping[str, str] | None,
           vty_universe: tuple[int, int] | None,
           changed: dict[tuple[int, int], bool] | None) -> Config:
    defaults, dialect = _tables()
    cfg = Config()
    notes: list[Note] = list(pre_notes) + list(doc.notes)
    lines: list[Line] = []
    nodes: list[Node] = []
    top: list[Node] = []
    kids: dict[int, list[Node]] = {}
    last_at_depth: dict[int, Node] = {}
    by_line: dict[int, dict[int, bool]] = {}
    for (li, j), v in (changed or {}).items():
        by_line.setdefault(li, {})[j] = v
    for i, ml in enumerate(doc.lines):
        text = ml.result.text
        reds = ml.result.redactions
        flags = by_line.get(i, {})
        text, reds = _apply_changed(text, reds, flags)
        st = text.strip()
        if ml.opaque_open:
            kind = "opaque-open"
        elif ml.opaque_close:
            kind = "opaque-close"
        elif ml.opaque:
            kind = "opaque"
        elif not st:
            kind = "blank"
        elif st.startswith("!"):
            kind = "comment"
        else:
            kind = "command"
        head = "" if kind in ("blank", "comment") else ml.head
        line = Line(line_no=i + 1, source_line_no=src[i] if i < len(src) else i + 1,
                    text=text, indent=ml.indent, head=head, tokens=mask.tokenize(text),
                    kind=kind, redactions=reds)
        lines.append(line)
        depth = len(ml.mode_path)
        parent = last_at_depth.get(depth - 1) if depth > 0 else None
        node = Node(line=line, mode_path=tuple(_canon_element(e) for e in ml.mode_path),
                    children=(), parent=parent)
        nodes.append(node)
        if parent is None:
            top.append(node)
        else:
            kids.setdefault(id(parent), []).append(node)
        if kind in ("command", "opaque-open") and not head.startswith("exit") and head != "end":
            last_at_depth[depth] = node
        # CSC-SELF-0004: a top-level command that cannot be a command at all
        if kind == "command" and depth == 0 and not st[0].isalpha() and st[0] not in "@":
            notes.append(Note("CSC-SELF-0004", i + 1, "unclassified line"))
        # CSC-SELF-0007: unfilled placeholder
        for tok in line.tokens:
            if mask.is_placeholder(tok):
                notes.append(Note("CSC-SELF-0007", i + 1,
                                  f"unfilled placeholder {tok[len('<REPLACE-ME:'):-1]}"))
    for n in nodes:
        object.__setattr__(n, "children", tuple(kids.get(id(n), ())))

    cfg.nodes = tuple(top)
    cfg._all = tuple(nodes)
    cfg._lines = tuple(lines)
    cfg.line_count = len(lines)
    cfg.nesting = doc.nesting
    cfg.defaults = defaults
    cfg.dialect = dialect

    # platform (3.5.1)
    if platform is not None:
        cfg.platform, cfg.platform_source = platform, "given"
    else:
        cfg.platform, cfg.platform_source = _infer_platform(cfg._all)

    # role map
    rm: dict[str, str] = {}
    mgmt_vlan = None
    if role_map is not None:
        for k, v in role_map.items():
            rm[canonical_interface(str(k))] = v
        mgmt_vlan = getattr(role_map, "management_vlan", None)
        if vty_universe is None:
            vty_universe = getattr(role_map, "vty_universe", None)
    cfg.role_map = MappingProxyType(rm)
    cfg.management_vlan = mgmt_vlan

    # interfaces (3.5 row c, 3.3 dedup rule)
    order: list[str] = []
    ranges_of: dict[str, list[Node]] = {}
    alone_of: dict[str, list[Node]] = {}
    macros: dict[str, str] = {}
    for n in cfg.nodes:
        t = n.line.tokens
        low = [x.lower() for x in t]
        if low[:2] == ["define", "interface-range"] and len(t) >= 4:
            macros[t[2]] = n.line.text.strip().split(None, 3)[3]
            continue
        if not low or low[0] != "interface" or len(t) < 2:
            continue
        if low[1] == "range":
            if len(t) >= 4 and low[2] == "macro":
                spec = macros.get(t[3])
                members = expand_range(spec) if spec is not None else None
            else:
                spec = n.line.text.strip().split(None, 2)[2] if len(t) >= 3 else ""
                members = expand_range(spec)
            if not members:
                notes.append(Note("CSC-SELF-0004", n.line.line_no, "unclassified line"))
                continue
            for m in members:
                if m not in ranges_of and m not in alone_of:
                    order.append(m)
                ranges_of.setdefault(m, []).append(n)
        else:
            raw_name = t[1]
            if t[1].isalpha() and len(t) >= 3 and t[2][:1].isdigit():
                raw_name = t[1] + t[2]
            name = canonical_interface(raw_name)
            if name not in ranges_of and name not in alone_of:
                order.append(name)
            alone_of.setdefault(name, []).append(n)
    ifaces: list[Interface] = []
    applied = 0
    for name in order:
        rnodes = ranges_of.get(name, [])
        anodes = alone_of.get(name, [])
        children = tuple(c for r in rnodes for c in r.children) + tuple(
            c for a in anodes for c in a.children)
        if anodes:
            base = anodes[0]
            from_range = False
            evidence = base.line
        else:
            base = rnodes[0]
            from_range = True
            evidence = base.line
        if len(rnodes) + len(anodes) > 1:
            node = Node(line=base.line, mode_path=base.mode_path, children=children, parent=None)
        else:
            node = base
        kind = interface_kind(name)
        role, source = _role_for(name, kind, children, rm, mgmt_vlan)
        if source == "role-map":
            applied += 1
        ifaces.append(Interface(name=name, kind=kind, node=node, from_range=from_range,
                                evidence_line=evidence, role=role, role_source=source))
    cfg._ifaces = tuple(ifaces)
    cfg._iface_by_name = {i.name: i for i in ifaces}
    if role_map is not None:
        ignored = len([k for k in rm if k not in cfg._iface_by_name])
        notes.append(Note("CSC-SELF-0008", None,
                          f"role-map applied to {applied} interfaces ({ignored} ignored)"))

    # line ranges (3.5 row f)
    universe = {"vty": vty_universe or defaults.vty_universe(cfg.platform)}
    for k in ("con", "aux"):
        universe[k] = defaults.line_universe.get(k)
    for kind in ("con", "vty", "aux"):
        observed: list[tuple[int, int, Node]] = []
        for n in cfg.nodes:
            low = [x.lower() for x in n.line.tokens]
            if low[:2] == ["line", kind] and len(low) >= 3 and low[2].isdigit():
                a = int(low[2])
                b = int(low[3]) if len(low) >= 4 and low[3].isdigit() else a
                observed.append((a, b, n))
        observed.sort(key=lambda x: (x[0], x[1]))
        out: list[LineRange] = []
        u = universe[kind]
        cursor = u[0] if u else None
        for a, b, n in observed:
            if cursor is not None and a > cursor and u is not None and cursor <= u[1]:
                gap_end = min(a - 1, u[1])
                out.append(LineRange(kind, cursor, gap_end, None, False))
            out.append(LineRange(kind, a, b, n, True))
            if cursor is not None:
                cursor = max(cursor, b + 1)
        if u is not None and cursor is not None and cursor <= u[1]:
            out.append(LineRange(kind, cursor, u[1], None, False))
        for r in out:
            if not r.observed:
                notes.append(Note("CSC-SELF-0006", None,
                                  f"assumed line {kind} {r.first} {r.last} present at "
                                  f"platform defaults"))
        cfg._ranges[kind] = tuple(out)
    cfg._vty_universe = universe["vty"]

    cfg.refs = ReferenceIndex.build(cfg)
    notes.append(Note("CSC-SELF-0001", None,
                      f"platform={cfg.platform} source={cfg.platform_source}"))
    first = [x for x in notes if x.code == "CSC-SELF-0001"]
    rest = sorted((x for x in notes if x.code != "CSC-SELF-0001"),
                  key=lambda x: (x.code, x.line_no or 0))
    cfg.notes = tuple(first + rest)
    return cfg


# --------------------------------------------------------------------------- entry points


def parse(text: str, *,
          platform: Platform | None = None,
          role_map: Mapping[str, Role] | None = None,
          vty_universe: tuple[int, int] | None = None) -> Config:
    defaults, _ = _tables()
    raw_lines, src, pre_notes = _preclean(text)
    _require_cisco(raw_lines, defaults.cisco_heads)
    doc = mask.mask_lines(raw_lines)
    del text, raw_lines
    return _build(doc, src, pre_notes, platform=platform, role_map=role_map,
                  vty_universe=vty_universe, changed=None)


def _align(old: mask.MaskedDocument, new: mask.MaskedDocument
           ) -> tuple[dict[tuple[int, int], bool], dict[tuple[int, int], bool]]:
    """Pair Redaction records by key, in list order, and compare salted digests (3.4.7)."""
    def index(doc: mask.MaskedDocument) -> dict[str, list[tuple[int, int, str]]]:
        out: dict[str, list[tuple[int, int, str]]] = {}
        for i, ml in enumerate(doc.lines):
            for j, (r, d) in enumerate(zip(ml.result.redactions, ml.result.digests)):
                out.setdefault(r.key, []).append((i, j, d))
        return out

    a, b = index(old), index(new)
    ch_old: dict[tuple[int, int], bool] = {}
    ch_new: dict[tuple[int, int], bool] = {}
    for key, olds in a.items():
        news = b.get(key)
        if not news:
            continue
        for (oi, oj, od), (ni, nj, nd) in zip(olds, news):
            flag = od != nd
            ch_old[(oi, oj)] = flag
            ch_new[(ni, nj)] = flag
    return ch_old, ch_new


def parse_pair(old_text: str, new_text: str, *,
               platform: Platform | None = None,
               role_map: Mapping[str, Role] | None = None) -> tuple[Config, Config]:
    defaults, _ = _tables()
    raw_old, src_old, notes_old = _preclean(old_text)
    _require_cisco(raw_old, defaults.cisco_heads)
    raw_new, src_new, notes_new = _preclean(new_text)
    _require_cisco(raw_new, defaults.cisco_heads)
    doc_old = mask.mask_lines(raw_old)
    doc_new = mask.mask_lines(raw_new)
    del old_text, new_text, raw_old, raw_new
    ch_old, ch_new = _align(doc_old, doc_new)
    cfg_old = _build(doc_old, src_old, notes_old, platform=platform, role_map=role_map,
                     vty_universe=None, changed=ch_old)
    cfg_new = _build(doc_new, src_new, notes_new, platform=platform, role_map=role_map,
                     vty_universe=None, changed=ch_new)
    del doc_old, doc_new       # the digests go with them
    return cfg_old, cfg_new
