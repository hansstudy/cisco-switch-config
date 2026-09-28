"""The baseline spec: load, validate, apply defaults.

The spec is JSON. It has no field that can carry a secret, and any key whose name looks like
one is rejected with a `SpecError` that names the key, says which `<REPLACE-ME:...>`
placeholder the generator emits instead, and quotes no value. No error raised here ever
contains a value from the spec: messages name keys and state the rule that failed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Mapping

__all__ = ["Spec", "SpecError", "load", "validate", "from_doc", "SECRET_KEY_RE",
           "PLACEHOLDER_FOR_KEY", "HOUSE_BANNER"]


class SpecError(Exception):
    """A spec problem. Carries the offending key and the reason, never a value."""

    def __init__(self, key: str, reason: str, *, hint: str | None = None) -> None:
        self.key = key
        self.reason = reason
        self.hint = hint
        msg = f'spec error: key "{key}" {reason}' if key else f"spec error: {reason}"
        if hint:
            msg += "\n            " + hint
        super().__init__(msg)


# --------------------------------------------------------------------------- secret fields

SECRET_KEY_RE = re.compile(
    r"(?i)(pass|passwd|password|secret|key(?!_id)|psk|token|community|credential|cred)$")

# Structural names that are never secrets, by full dotted path (5.1 carve-out).
_CARVE_OUT = frozenset({"aaa.group_name", "ntp.key_id", "management.acl_name",
                        "snmp.v3_user", "snmp.v3_group"})

# The frozen forbidden-field table (5.1). Keyed by the key's own name, lowercased; a
# (parent, name) entry covers the dotted forms such as `tacacs.key` at any nesting.
# The value is the placeholder name the generator emits, "" for "rejected, no placeholder".
PLACEHOLDER_FOR_KEY: Mapping[str, str] = {
    "tacacs_key": "tacacs-key",
    "radius_key": "radius-key",
    "snmp_auth_password": "snmpv3-auth",
    "snmp_priv_password": "snmpv3-priv",
    "v3_auth": "snmpv3-auth",
    "v3_priv": "snmpv3-priv",
    "ntp_key": "ntp-key-{key_id}",
    "enable_secret": "enable-secret",
    "local_password": "local-admin-secret",
    "local_secret": "local-admin-secret",
    "vtp_password": "vtp-password",
    "archive_password": "",
}
_PARENT_KEY: Mapping[tuple[str, str], str] = {
    ("tacacs", "key"): "tacacs-key",
    ("radius", "key"): "radius-key",
    ("snmp", "v3_auth"): "snmpv3-auth",
    ("snmp", "v3_priv"): "snmpv3-priv",
    ("ntp", "key"): "ntp-key-{key_id}",
}

# URL userinfo, scheme or scheme-less: never accepted in any
# string value, because the masker would redact it and the egress guard would refuse it.
_USERINFO_RE = re.compile(r"[^:/@\s]+:[^@\s]+@\S")

_SAFE_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,39}$")


# Characters no spec string may carry: every C0/C1 control and DEL
# (category Cc), every format character (Cf: bidi embeddings, overrides and isolates,
# LRM/RLM, zero-width space and joiners, BOM, soft hyphen), line and paragraph separators
# (Zl, Zp), surrogates (Cs), and unassigned or private-use code points (Cn, Co). Only the
# banner may carry a line break (LF, or CR LF, which is normalised to LF).
_BAD_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Cn", "Co", "Zl", "Zp"})
_EXPLICIT_BAD = frozenset(
    [chr(c) for c in range(0x80, 0xA0)]                                   # C1 controls
    + [chr(c) for c in range(0x202A, 0x202F)]                             # LRE..RLO
    + [chr(c) for c in range(0x2066, 0x206A)]                             # LRI..PDI
    + [chr(c) for c in (0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0xFEFF)])


def _bad_text_char(text: str, *, newline_ok: bool) -> bool:
    for c in text:
        if newline_ok and c in "\n\r":
            continue
        if c in _EXPLICIT_BAD or unicodedata.category(c) in _BAD_CATEGORIES:
            return True
    return False


_BAD_CHAR_REASON = ("must not contain control, bidirectional-override or invisible formatting "
                    "characters.")


def _shown(path: str) -> str:
    """A key path fit to print: identifier-shaped segments only, anything else elided."""
    out = []
    for seg in path.split("."):
        name, _, idx = seg.partition("[")
        out.append((name if _SAFE_KEY_RE.match(name) else "<key>") + ("[" + idx if idx else ""))
    return ".".join(out)


def _ntp_key_id(doc: Any) -> int:
    try:
        kid = doc["ntp"]["key_id"]
    except (KeyError, TypeError, IndexError):
        return 1
    return kid if isinstance(kid, int) and not isinstance(kid, bool) and 1 <= kid <= 65535 else 1


def _secret_error(path: str, parent: str, name: str, doc: Any) -> SpecError:
    low, plow = name.lower(), parent.lower()
    ph = _PARENT_KEY.get((plow, low), PLACEHOLDER_FOR_KEY.get(low))
    shown = _shown(path)
    if ph == "":
        return SpecError(shown, "is a secret field and is not accepted.",
                         hint="archive.path must be a local path such as flash:archive; "
                              "no placeholder is emitted for a remote archive credential.")
    if ph == "vtp-password":
        return SpecError(shown, "is a secret field and is not accepted.",
                         hint="The baseline runs VTP transparent; if VTP is needed, set "
                              "<REPLACE-ME:vtp-password> on the device.")
    if ph:
        ph = ph.format(key_id=_ntp_key_id(doc))
        return SpecError(shown, "is a secret field and is not accepted.",
                         hint=f"The generated configuration emits <REPLACE-ME:{ph}>; "
                              "fill it on the device.")
    return SpecError(shown, "is a secret field and is not accepted.",
                     hint="The spec never carries a secret; every secret slot in the generated "
                          "configuration is a <REPLACE-ME:...> placeholder filled on the device.")


def _scan_secrets(node: Any, path: str, parent: str, doc: Any) -> None:
    """Reject secret-named keys at any depth, and URL credentials in any string value."""
    if isinstance(node, dict):
        for k, v in node.items():
            sub = f"{path}.{k}" if path else k
            if sub not in _CARVE_OUT:
                low = k.lower()
                if (low in PLACEHOLDER_FOR_KEY or (parent.lower(), low) in _PARENT_KEY
                        or SECRET_KEY_RE.search(k)):
                    raise _secret_error(sub, parent, k, doc)
            _scan_secrets(v, sub, k, doc)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            _scan_secrets(v, f"{path}[{i}]", parent, doc)
    elif isinstance(node, str) and _bad_text_char(node, newline_ok=(path == "banner.motd")):
        raise SpecError(_shown(path) or "(document)", _BAD_CHAR_REASON)
    elif isinstance(node, str) and _USERINFO_RE.search(node):
        hint = ("archive.path must be a local path such as flash:archive; no placeholder is "
                "emitted." if path == "archive.path" else
                "Remove the embedded user:password@ credential; the spec never carries one.")
        raise SpecError(_shown(path) or "(document)", "carries URL credentials and is not accepted.",
                        hint=hint)


# --------------------------------------------------------------------------- records

@dataclass(frozen=True, slots=True)
class Management:
    vlan: int
    address: str            # CIDR, as given
    gateway: str
    acl_name: str
    allowed_sources: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Vlan:
    id: int
    name: str
    kind: str               # data | voice | mgmt | unused | native


@dataclass(frozen=True, slots=True)
class Uplink:
    interface: str
    description: str
    allowed_vlans: tuple[int, ...]
    channel_group: int | None


@dataclass(frozen=True, slots=True)
class AccessPorts:
    range: str
    vlan: int
    voice_vlan: int | None
    description: str


@dataclass(frozen=True, slots=True)
class Stp:
    mode: str
    root_priority: int | None


@dataclass(frozen=True, slots=True)
class Aaa:
    tacacs_hosts: tuple[str, ...]
    radius_hosts: tuple[str, ...]
    group_name: str


@dataclass(frozen=True, slots=True)
class Snmp:
    v3_user: str | None
    v3_group: str


@dataclass(frozen=True, slots=True)
class Ntp:
    servers: tuple[str, ...]
    key_id: int


@dataclass(frozen=True, slots=True)
class Logging:
    hosts: tuple[str, ...]
    trap_level: str


@dataclass(frozen=True, slots=True)
class Banner:
    motd: str


@dataclass(frozen=True, slots=True)
class Features:
    dhcp_snooping: bool
    dai: bool
    port_security: bool
    storm_control: bool
    udld: bool


@dataclass(frozen=True, slots=True)
class Archive:
    path: str


@dataclass(frozen=True, slots=True)
class Spec:
    """One attribute per schema key, defaults applied. Holds no secret by construction."""
    version: int
    hostname: str
    domain_name: str
    platform: str
    role: str
    management: Management
    vlans: tuple[Vlan, ...]
    uplinks: tuple[Uplink, ...]
    access_ports: tuple[AccessPorts, ...]
    unused_ports: tuple[str, ...]
    stp: Stp
    aaa: Aaa
    snmp: Snmp
    ntp: Ntp
    logging: Logging
    banner: Banner
    features: Features
    archive: Archive

    def to_dict(self) -> dict:
        """The defaults-applied spec as plain JSON data, in schema order."""
        m = self.management
        return {
            "version": self.version, "hostname": self.hostname, "domain_name": self.domain_name,
            "platform": self.platform, "role": self.role,
            "management": {"vlan": m.vlan, "address": m.address, "gateway": m.gateway,
                           "acl_name": m.acl_name, "allowed_sources": list(m.allowed_sources)},
            "vlans": [{"id": v.id, "name": v.name, "kind": v.kind} for v in self.vlans],
            "uplinks": [dict({"interface": u.interface, "description": u.description,
                              "allowed_vlans": list(u.allowed_vlans)},
                             **({"channel_group": u.channel_group}
                                if u.channel_group is not None else {}))
                        for u in self.uplinks],
            "access_ports": [dict({"range": a.range, "vlan": a.vlan},
                                  **({"voice_vlan": a.voice_vlan}
                                     if a.voice_vlan is not None else {}),
                                  description=a.description)
                             for a in self.access_ports],
            "unused_ports": list(self.unused_ports),
            "stp": {"mode": self.stp.mode, "root_priority": self.stp.root_priority},
            "aaa": {"tacacs_hosts": list(self.aaa.tacacs_hosts),
                    "radius_hosts": list(self.aaa.radius_hosts),
                    "group_name": self.aaa.group_name},
            "snmp": {"v3_user": self.snmp.v3_user, "v3_group": self.snmp.v3_group},
            "ntp": {"servers": list(self.ntp.servers), "key_id": self.ntp.key_id},
            "logging": {"hosts": list(self.logging.hosts), "trap_level": self.logging.trap_level},
            "banner": {"motd": self.banner.motd},
            "features": {"dhcp_snooping": self.features.dhcp_snooping, "dai": self.features.dai,
                         "port_security": self.features.port_security,
                         "storm_control": self.features.storm_control,
                         "udld": self.features.udld},
            "archive": {"path": self.archive.path},
        }

    def digest(self) -> str:
        """sha256 of the canonicalised defaults-applied spec (5.2). Safe: no secrets."""
        canon = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False)
        return hashlib.sha256(canon.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- field rules

HOUSE_BANNER = ("Authorized access only. This system is the property of its owner and is "
                "monitored;\nall activity may be recorded. By continuing you consent to this "
                "monitoring.\nUnauthorized use is prohibited and may be prosecuted.")

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,62}$")
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                        r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")
_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,31}$")          # ACL, AAA group, SNMP group
_SNMP_USER_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,31}$")
_VLAN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
_IFACE_RE = re.compile(r"^[A-Za-z][A-Za-z-]*[0-9]+(?:/[0-9]+){0,3}$")
_TEXT_RE = re.compile(r"^[\x20-\x7e]{1,200}$")
# The scheme is limited to the switch's own file systems, so a
# remote scheme-less form such as ftp:192.0.2.1/archive can never become the archive path.
_ARCHIVE_RE = re.compile(
    r"^(?:flash(?:-[0-9]+)?|bootflash|usbflash[0-9]*|crashinfo(?:-[0-9]+)?|disk[0-9]*):"
    r"/?[A-Za-z0-9_.-]*(?:/[A-Za-z0-9_.-]+)*$")
_LEVELS = ("emergencies", "alerts", "critical", "errors", "warnings", "notifications",
           "informational", "debugging")
_KINDS = ("data", "voice", "mgmt", "unused", "native")
_RESERVED_VLANS = range(1002, 1006)


def _obj(doc: Any, path: str, allowed: tuple[str, ...], required: tuple[str, ...]) -> dict:
    if not isinstance(doc, dict):
        raise SpecError(path or "(document)", "must be a JSON object.")
    for k in doc:
        if k not in allowed:
            sub = f"{path}.{k}" if path else k
            raise SpecError(_shown(sub), "is not a recognised field.")
    for k in required:
        if k not in doc:
            raise SpecError(f"{path}.{k}" if path else k, "is required.")
    return doc


def _int(v: Any, key: str, lo: int, hi: int) -> int:
    if not isinstance(v, int) or isinstance(v, bool):
        raise SpecError(key, "must be an integer.")
    if not lo <= v <= hi:
        raise SpecError(key, f"must be between {lo} and {hi}.")
    return v


def _bool(v: Any, key: str) -> bool:
    if not isinstance(v, bool):
        raise SpecError(key, "must be true or false.")
    return v


def _str(v: Any, key: str, rx: re.Pattern[str], rule: str) -> str:
    if not isinstance(v, str):
        raise SpecError(key, "must be a string.")
    if not rx.match(v):
        raise SpecError(key, f"must be {rule}.")
    return v


def _enum(v: Any, key: str, choices: tuple[str, ...]) -> str:
    if not isinstance(v, str) or v not in choices:
        raise SpecError(key, "must be one of: " + ", ".join(choices) + ".")
    return v


def _list(v: Any, key: str, *, nonempty: bool = False) -> list:
    if not isinstance(v, list):
        raise SpecError(key, "must be an array.")
    if nonempty and not v:
        raise SpecError(key, "must not be empty.")
    return v


def _ipv4(v: Any, key: str) -> str:
    if not isinstance(v, str):
        raise SpecError(key, "must be a string.")
    try:
        ipaddress.IPv4Address(v)
    except ValueError:
        raise SpecError(key, "must be an IPv4 address such as 192.0.2.10.") from None
    return v


def _hosts(v: Any, key: str, *, nonempty: bool) -> tuple[str, ...]:
    items = _list(v, key, nonempty=nonempty)
    out = [_ipv4(h, f"{key}[{i}]") for i, h in enumerate(items)]
    if len(set(out)) != len(out):
        raise SpecError(key, "must not list the same address twice.")
    return tuple(out)


def _vlan_id(v: Any, key: str) -> int:
    vid = _int(v, key, 2, 4094)
    if vid in _RESERVED_VLANS:
        raise SpecError(key, "must not be a reserved VLAN (1002-1005).")
    return vid


def _banner(v: Any, key: str) -> str:
    if not isinstance(v, str):
        raise SpecError(key, "must be a string.")
    text = v.replace("\r\n", "\n")
    if not text.strip():
        raise SpecError(key, "must not be empty.")
    if len(text) > 2000:
        raise SpecError(key, "must be at most 2000 characters.")
    if "^" in text:
        raise SpecError(key, "must not contain the ^ character (the banner delimiter is ^C).")
    if "\r" in text or _bad_text_char(text, newline_ok=True):
        raise SpecError(key, _BAD_CHAR_REASON)
    return text


def _ranges(spec_text: Any, key: str) -> tuple[str, list[str]]:
    from ciscocheck.parser import expand_range   # the auditor's own grammar (3.5 row c)
    if not isinstance(spec_text, str) or not _TEXT_RE.match(spec_text):
        raise SpecError(key, "must be an interface range such as GigabitEthernet1/0/1 - 24.")
    members = expand_range(spec_text)
    if not members:
        raise SpecError(key, "must be an interface range such as GigabitEthernet1/0/1 - 24.")
    return spec_text, members


def validate(doc: Mapping) -> None:
    """Raise SpecError on the first problem. Secret-named keys are checked before anything."""
    from_doc(doc)


def from_doc(doc: Any) -> Spec:
    """Validate `doc` and build the defaults-applied Spec."""
    try:
        _scan_secrets(doc, "", "", doc)
    except RecursionError:
        raise SpecError("", "the spec is nested too deeply.") from None
    top = _obj(doc, "", ("version", "hostname", "domain_name", "platform", "role", "management",
                         "vlans", "uplinks", "access_ports", "unused_ports", "stp", "aaa",
                         "snmp", "ntp", "logging", "banner", "features", "archive"),
               ("version", "hostname", "domain_name", "management", "vlans", "uplinks",
                "access_ports", "ntp", "logging"))
    version = top["version"]
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise SpecError("version", "must be 1.")
    hostname = _str(top["hostname"], "hostname", _HOSTNAME_RE,
                    "1-63 letters, digits or hyphens, starting with a letter or digit")
    domain = _str(top["domain_name"], "domain_name", _DOMAIN_RE, "a DNS domain name")
    platform = _enum(top.get("platform", "iosxe"), "platform", ("ios", "iosxe"))
    role = _enum(top.get("role", "access"), "role", ("access", "distribution"))

    # management
    m = _obj(top["management"], "management",
             ("vlan", "address", "gateway", "acl_name", "allowed_sources"),
             ("vlan", "address", "gateway", "allowed_sources"))
    mvlan = _vlan_id(m["vlan"], "management.vlan")
    addr = m["address"]
    if not isinstance(addr, str) or "/" not in addr:
        raise SpecError("management.address", "must be an IPv4 address in CIDR form such as "
                                              "10.10.99.11/24.")
    try:
        iface = ipaddress.IPv4Interface(addr)
    except ValueError:
        raise SpecError("management.address", "must be an IPv4 address in CIDR form such as "
                                              "10.10.99.11/24.") from None
    net = iface.network
    if net.prefixlen > 30 or iface.ip in (net.network_address, net.broadcast_address):
        raise SpecError("management.address", "must be a host address in a /30 or larger subnet.")
    gw = ipaddress.IPv4Address(_ipv4(m["gateway"], "management.gateway"))
    if gw not in net or gw == iface.ip or gw in (net.network_address, net.broadcast_address):
        raise SpecError("management.gateway", "must be another host address in the management "
                                              "subnet.")
    acl = _str(m.get("acl_name", "MGMT-ACCESS"), "management.acl_name", _NAME_RE,
               "1-32 letters, digits, hyphens or underscores, starting with a letter")
    srcs = _list(m["allowed_sources"], "management.allowed_sources", nonempty=True)
    sources = []
    for i, s in enumerate(srcs):
        key = f"management.allowed_sources[{i}]"
        if not isinstance(s, str):
            raise SpecError(key, "must be a string.")
        try:
            ipaddress.IPv4Network(s if "/" in s else s + "/32", strict=True)
        except ValueError:
            raise SpecError(key, "must be an IPv4 network in CIDR form with no host bits set.") \
                from None
        sources.append(s)
    if len(set(sources)) != len(sources):
        raise SpecError("management.allowed_sources", "must not list the same network twice.")
    management = Management(mvlan, addr, str(gw), acl, tuple(sources))

    # vlans
    vlans: list[Vlan] = []
    for i, v in enumerate(_list(top["vlans"], "vlans")):
        key = f"vlans[{i}]"
        o = _obj(v, key, ("id", "name", "kind"), ("id", "name", "kind"))
        vlans.append(Vlan(_vlan_id(o["id"], f"{key}.id"),
                          _str(o["name"], f"{key}.name", _VLAN_NAME_RE,
                               "1-32 letters, digits, dots, hyphens or underscores"),
                          _enum(o["kind"], f"{key}.kind", _KINDS)))
    by_id = {}
    for i, v in enumerate(vlans):
        if v.id in by_id:
            raise SpecError(f"vlans[{i}].id", "duplicates an earlier VLAN id.")
        by_id[v.id] = v
    if len({v.name.lower() for v in vlans}) != len(vlans):
        raise SpecError("vlans", "must not reuse a VLAN name.")
    for i, v in enumerate(vlans):
        if v.kind == "mgmt" and v.id != mvlan:
            raise SpecError(f"vlans[{i}].kind", "is mgmt but the id is not management.vlan.")
        if v.id == mvlan and v.kind != "mgmt":
            raise SpecError(f"vlans[{i}].kind", "must be mgmt for the management VLAN.")
    if sum(1 for v in vlans if v.kind == "native") > 1:
        raise SpecError("vlans", "must declare at most one native VLAN.")
    defined = set(by_id) | {mvlan}

    # interfaces
    seen_members: dict[str, str] = {}

    def claim(members: list[str], key: str) -> None:
        for mbr in members:
            if mbr in seen_members:
                raise SpecError(key, "overlaps an interface already used by "
                                     f"{seen_members[mbr]}.")
            seen_members[mbr] = key

    from ciscocheck.parser import canonical_interface
    uplinks: list[Uplink] = []
    groups: dict[int, tuple[int, ...]] = {}
    for i, u in enumerate(_list(top["uplinks"], "uplinks")):
        key = f"uplinks[{i}]"
        o = _obj(u, key, ("interface", "description", "allowed_vlans", "channel_group"),
                 ("interface", "description", "allowed_vlans"))
        name = _str(o["interface"], f"{key}.interface", _IFACE_RE,
                    "a single interface name such as TenGigabitEthernet1/1/1")
        desc = _str(o["description"], f"{key}.description", _TEXT_RE,
                    "1-200 printable ASCII characters")
        allowed = [_vlan_id(x, f"{key}.allowed_vlans[{j}]")
                   for j, x in enumerate(_list(o["allowed_vlans"], f"{key}.allowed_vlans",
                                               nonempty=True))]
        for j, x in enumerate(allowed):
            if x not in defined:
                raise SpecError(f"{key}.allowed_vlans[{j}]", "names a VLAN the spec does not "
                                                             "define.")
        if len(set(allowed)) != len(allowed):
            raise SpecError(f"{key}.allowed_vlans", "must not list a VLAN twice.")
        cg = o.get("channel_group")
        if cg is not None:
            cg = _int(cg, f"{key}.channel_group", 1, 128)
            if cg in groups and groups[cg] != tuple(allowed):
                raise SpecError(f"{key}.allowed_vlans", "must match the other members of its "
                                                        "channel group.")
            groups[cg] = tuple(allowed)
        claim([canonical_interface(name)], f"{key}.interface")
        uplinks.append(Uplink(name, desc, tuple(allowed), cg))

    access: list[AccessPorts] = []
    for i, a in enumerate(_list(top["access_ports"], "access_ports")):
        key = f"access_ports[{i}]"
        o = _obj(a, key, ("range", "vlan", "voice_vlan", "description"),
                 ("range", "vlan", "description"))
        rng, members = _ranges(o["range"], f"{key}.range")
        vid = _vlan_id(o["vlan"], f"{key}.vlan")
        if vid not in by_id or by_id[vid].kind != "data":
            raise SpecError(f"{key}.vlan", "must name a VLAN of kind data.")
        voice = o.get("voice_vlan")
        if voice is not None:
            voice = _vlan_id(voice, f"{key}.voice_vlan")
            if voice not in by_id or by_id[voice].kind != "voice":
                raise SpecError(f"{key}.voice_vlan", "must name a VLAN of kind voice.")
        desc = _str(o["description"], f"{key}.description", _TEXT_RE,
                    "1-200 printable ASCII characters")
        claim(members, f"{key}.range")
        access.append(AccessPorts(rng, vid, voice, desc))

    unused: list[str] = []
    for i, r in enumerate(_list(top.get("unused_ports", []), "unused_ports")):
        rng, members = _ranges(r, f"unused_ports[{i}]")
        claim(members, f"unused_ports[{i}]")
        unused.append(rng)

    # stp
    s = _obj(top.get("stp", {}), "stp", ("mode", "root_priority"), ())
    mode = _enum(s.get("mode", "rapid-pvst"), "stp.mode", ("rapid-pvst", "mst"))
    prio = s.get("root_priority")
    if prio is not None:
        prio = _int(prio, "stp.root_priority", 0, 61440)
        if prio % 4096:
            raise SpecError("stp.root_priority", "must be a multiple of 4096.")

    # aaa
    a = _obj(top.get("aaa", {}), "aaa", ("tacacs_hosts", "radius_hosts", "group_name"), ())
    tacacs = _hosts(a.get("tacacs_hosts", []), "aaa.tacacs_hosts", nonempty=False)
    radius = _hosts(a.get("radius_hosts", []), "aaa.radius_hosts", nonempty=False)
    if not tacacs and not radius:
        raise SpecError("aaa", "must list at least one TACACS+ or RADIUS server address; a "
                               "hardened baseline authenticates and accounts centrally.")
    group = _str(a.get("group_name", "ISE"), "aaa.group_name", _NAME_RE,
                 "1-32 letters, digits, hyphens or underscores, starting with a letter")

    # snmp
    sn = _obj(top.get("snmp", {}), "snmp", ("v3_user", "v3_group"), ())
    user = sn.get("v3_user")
    if user is not None:
        user = _str(user, "snmp.v3_user", _SNMP_USER_RE,
                    "1-32 letters, digits, dots, hyphens or underscores, starting with a letter")
    sgroup = _str(sn.get("v3_group", "RO-GROUP"), "snmp.v3_group", _NAME_RE,
                  "1-32 letters, digits, hyphens or underscores, starting with a letter")

    # ntp, logging
    n = _obj(top["ntp"], "ntp", ("servers", "key_id"), ("servers",))
    ntp = Ntp(_hosts(n["servers"], "ntp.servers", nonempty=True),
              _int(n.get("key_id", 1), "ntp.key_id", 1, 65535))
    lg = _obj(top["logging"], "logging", ("hosts", "trap_level"), ("hosts",))
    logging_ = Logging(_hosts(lg["hosts"], "logging.hosts", nonempty=True),
                       _enum(lg.get("trap_level", "informational"), "logging.trap_level", _LEVELS))

    b = _obj(top.get("banner", {}), "banner", ("motd",), ())
    banner = Banner(_banner(b.get("motd", HOUSE_BANNER), "banner.motd"))

    f = _obj(top.get("features", {}), "features",
             ("dhcp_snooping", "dai", "port_security", "storm_control", "udld"), ())
    features = Features(*(_bool(f.get(k, True), f"features.{k}")
                          for k in ("dhcp_snooping", "dai", "port_security", "storm_control",
                                    "udld")))
    if features.dai and not features.dhcp_snooping:
        raise SpecError("features.dai", "requires features.dhcp_snooping: Dynamic ARP "
                                        "Inspection validates against the snooping table.")

    ar = _obj(top.get("archive", {}), "archive", ("path",), ())
    apath = ar.get("path", "flash:archive")
    if isinstance(apath, str) and ("@" in apath or "//" in apath):
        raise SpecError("archive.path", "is a URL and is not accepted.",
                        hint="archive.path must be a local path such as flash:archive.")
    apath = _str(apath, "archive.path", _ARCHIVE_RE,
                 "a path on the switch's own file system (flash, bootflash, usbflash<n>, "
                 "crashinfo or disk<n>), such as flash:archive")

    return Spec(version, hostname, domain, platform, role, management, tuple(vlans),
                tuple(uplinks), tuple(access), tuple(unused), Stp(mode, prio),
                Aaa(tacacs, radius, group), Snmp(user, sgroup), ntp, logging_, banner, features,
                Archive(apath))


# --------------------------------------------------------------------------- loading

def _no_dupes(pairs: list[tuple[str, Any]]) -> dict:
    out: dict = {}
    for k, v in pairs:
        if k in out:
            raise SpecError(_shown(k), "appears twice in one JSON object.")
        out[k] = v
    return out


def _no_constant(_name: str) -> Any:
    raise SpecError("", "the spec must not contain NaN or Infinity.")


_MAX_INT_DIGITS = 18       # every numeric field is bounded far below this (largest: 65535)


def _parse_int(literal: str) -> int:
    if len(literal.lstrip("-")) > _MAX_INT_DIGITS:
        raise SpecError("", "the spec contains an integer too large for any field.")
    return int(literal)


def parse_text(text: str) -> Any:
    """Parse JSON spec text. The error names a position, never content."""
    try:
        return json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_no_constant,
                          parse_int=_parse_int)
    except json.JSONDecodeError as exc:
        raise SpecError("", f"the spec is not valid JSON (line {exc.lineno}, column "
                            f"{exc.colno}).") from None
    except (ValueError, OverflowError):     # e.g. the interpreter's int-digit limit (F19)
        raise SpecError("", "the spec contains a number too large to process.") from None
    except RecursionError:
        raise SpecError("", "the spec is nested too deeply.") from None


def decode_bytes(data: bytes) -> str:
    """Strict UTF-8, an optional leading BOM allowed. Never
    produces U+FFFD: invalid bytes are a SpecError naming a byte offset, not content."""
    try:
        return data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise SpecError("", f"the spec is not valid UTF-8 (invalid byte at offset "
                            f"{exc.start}); save it as UTF-8.") from None


def load(path_or_text: str) -> Spec:
    """Load a spec from JSON text (anything starting with `{`) or from a file path."""
    if path_or_text.lstrip().startswith("{"):
        text = path_or_text
    else:
        try:
            with open(path_or_text, "rb") as fh:
                data = fh.read()
        except OSError:
            raise SpecError("", "the spec file cannot be read.") from None
        text = decode_bytes(data)
    return from_doc(parse_text(text))
