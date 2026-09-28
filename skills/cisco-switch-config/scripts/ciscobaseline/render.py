"""Render a validated Spec into an ordered IOS / IOS-XE configuration.

`string.Template` substitution only (`$name`, `$$` for a literal dollar). Templates hold no
loops and no conditionals: repetition and optional fragments are decided here, one template
call per item. Same spec in, same lines out: no clock, no randomness, no set or dict
ordering, and spec collections are iterated in the order given. Every secret slot is a
literal `<REPLACE-ME:name>` in a template; no value is generated or copied into one.

This module never writes. `gen_baseline.py` sends the result through `ciscocheck.report`.
"""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from string import Template
from typing import Callable, Mapping

from ciscocheck import SKILL_VERSION

from .sections import BaselineBuildError, Section, data_dir, load_sections, load_template
from .spec import Spec

__all__ = ["render", "render_json", "placeholders", "operator_notes", "PLACEHOLDER_RE", "SECTION_NAMES"]

PLACEHOLDER_RE = re.compile(r"<REPLACE-ME:[a-z0-9-]+>")

# The frozen section order (5.2). A build whose sections.json differs is unusable: a missing
# section would silently drop a hardening block.
SECTION_NAMES = ("00-header", "05-services", "10-users-aaa", "15-lines", "20-ssh", "25-snmp",
                 "30-ntp", "35-logging", "40-vlans", "45-stp", "50-l2-security", "55-uplinks",
                 "60-access-ports", "65-unused-ports", "70-management", "75-mgmt-acl",
                 "80-boot-resilience", "99-footer")

_PLATFORM_KEYS = ("portfast", "bpduguard_default", "ntp_algorithm", "ssh_encryption", "ssh_mac",
                  "ssh_kex", "boot_image", "redundancy_sso", "device_tracking")


# --------------------------------------------------------------------------- build data

def _platform_table(base: Path, platform: str) -> Mapping[str, object]:
    path = base / "platforms.json"
    try:
        with open(path, "rb") as fh:
            doc = json.loads(fh.read().decode("utf-8"))
        row = doc["platforms"][platform]
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
        raise BaselineBuildError("baseline build file missing or malformed: platforms.json") \
            from None
    if not isinstance(row, dict) or set(row) != set(_PLATFORM_KEYS):
        raise BaselineBuildError("baseline build file missing or malformed: platforms.json")
    return row


def _fill(tmpl: Template, mapping: Mapping[str, object], where: str) -> list[str]:
    """Substitute line by line. A template line that had content and renders to nothing
    but whitespace is an omitted optional fragment and is dropped."""
    out: list[str] = []
    for tline in tmpl.template.split("\n"):
        try:
            text = Template(tline).substitute(mapping)
        except (KeyError, ValueError):
            raise BaselineBuildError(f"baseline template {where} names an unknown field") \
                from None
        if tline.strip() and not text.strip():
            continue
        out.extend(text.split("\n"))
    return out


# --------------------------------------------------------------------------- derived data

class _Plan:
    """Everything render needs that is computed from the spec, computed once, in order."""

    def __init__(self, spec: Spec, plat: Mapping[str, object]) -> None:
        self.spec = spec
        self.plat = plat
        m = spec.management
        iface = ipaddress.IPv4Interface(m.address)
        self.mgmt_vlan = m.vlan
        self.mgmt_address = str(iface.ip)
        self.mgmt_mask = str(iface.netmask)

        # VLANs emitted: the spec's, in order, then any the baseline must add.
        used_ids = {v.id for v in spec.vlans} | {m.vlan}
        used_names = {v.name.lower() for v in spec.vlans}
        self.vlans: list[tuple[int, str]] = [(v.id, v.name) for v in spec.vlans]

        def add(vid: int, name: str) -> None:
            if name.lower() in used_names:
                name = f"{name}-{vid}"
            used_names.add(name.lower())
            used_ids.add(vid)
            self.vlans.append((vid, name))

        def free_id() -> int:
            for vid in range(999, 1, -1):
                if vid not in used_ids:
                    return vid
            raise BaselineBuildError("no free VLAN id below 1000 for a baseline VLAN")

        if m.vlan not in {v.id for v in spec.vlans}:
            add(m.vlan, "MGMT")
        self.parking = next((v.id for v in spec.vlans if v.kind == "unused"), None)
        if self.parking is None and spec.unused_ports:
            self.parking = free_id()
            add(self.parking, "PARKING")
        self.native = next((v.id for v in spec.vlans if v.kind == "native"), None)
        if self.native is None and spec.uplinks:
            self.native = free_id()
            add(self.native, "NATIVE-UNUSED")

        self.snoop_vlans = [v.id for v in spec.vlans if v.kind in ("data", "voice")]
        self.has_voice = any(a.voice_vlan is not None for a in spec.access_ports)

        # AAA server groups: TACACS+ first when both are given.
        a = spec.aaa
        self.groups: list[tuple[str, str, str, tuple[str, ...], str]] = []
        if a.tacacs_hosts:
            self.groups.append(("tacacs+", a.group_name, "tacacs", a.tacacs_hosts, "TACACS-"))
        if a.radius_hosts:
            gname = a.group_name if not a.tacacs_hosts else f"{a.group_name}-RADIUS"
            self.groups.append(("radius", gname, "radius", a.radius_hosts, "RADIUS-"))
        chain = " ".join(f"group {g[1]}" for g in self.groups)
        self.login_methods = f"{chain} local"
        self.enable_methods = f"{chain} enable"
        self.exec_methods = f"{chain} local if-authenticated"
        self.acct_methods = f"group {self.groups[0][1]}"

    @staticmethod
    def vlan_list(ids: list[int] | tuple[int, ...]) -> str:
        return ",".join(str(i) for i in ids)


# --------------------------------------------------------------------------- section renderers

Parts = Mapping[str, Template]
Renderer = Callable[[_Plan, Parts, list[str]], Mapping[str, object]]


def _items(parts: Parts, part: str, rows: list[Mapping[str, object]]) -> str:
    return "\n".join("\n".join(_fill(parts[part], row, part)) for row in rows)


def _s_header(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    s = p.spec
    return {"hostname": s.hostname, "domain_name": s.domain_name, "platform": s.platform,
            "role": s.role, "skill_version": SKILL_VERSION, "spec_digest": s.digest()}


def _s_services(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    return {"cdp_global": "" if p.has_voice else "no cdp run"}


def _s_aaa(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    servers, groups = [], []
    for proto, gname, src, hosts, prefix in p.groups:
        part = "tacacs-server" if proto == "tacacs+" else "radius-server"
        names = [f"{prefix}{i}" for i in range(1, len(hosts) + 1)]
        servers.append(_items(parts, part, [{"name": n, "address": h}
                                            for n, h in zip(names, hosts)]))
        members = _items(parts, "member", [{"name": n} for n in names])
        groups.append(_items(parts, "group", [{"protocol": proto, "group": gname,
                                                "members": members, "source_protocol": src,
                                                "mgmt_vlan": p.mgmt_vlan}]))
    return {"aaa_servers": "\n".join(servers), "aaa_groups": "\n".join(groups),
            "login_methods": p.login_methods, "enable_methods": p.enable_methods,
            "exec_methods": p.exec_methods, "acct_methods": p.acct_methods}


def _s_lines(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    return {"banner_body": p.spec.banner.motd, "acl_name": p.spec.management.acl_name}


def _s_ssh(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    kex = p.plat["ssh_kex"]
    return {"mgmt_vlan": p.mgmt_vlan, "ssh_encryption": p.plat["ssh_encryption"],
            "ssh_mac": p.plat["ssh_mac"],
            "ssh_kex": f"ip ssh server algorithm kex {kex}" if kex else ""}


def _s_snmp(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    sn = p.spec.snmp
    user = "" if sn.v3_user is None else \
        _items(parts, "user", [{"user": sn.v3_user, "v3_group": sn.v3_group}])
    return {"v3_group": sn.v3_group, "acl_name": p.spec.management.acl_name, "snmp_user": user}


def _s_ntp(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    n = p.spec.ntp
    return {"key_id": n.key_id, "ntp_algorithm": p.plat["ntp_algorithm"],
            "mgmt_vlan": p.mgmt_vlan,
            "ntp_servers": _items(parts, "server", [{"address": h, "key_id": n.key_id}
                                                    for h in n.servers])}


def _s_logging(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    lg = p.spec.logging
    return {"trap_level": lg.trap_level, "mgmt_vlan": p.mgmt_vlan,
            "archive_path": p.spec.archive.path,
            "logging_hosts": _items(parts, "host", [{"address": h} for h in lg.hosts])}


def _s_vlans(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    return {"vlans": _items(parts, "vlan", [{"id": i, "name": n} for i, n in p.vlans])}


def _s_stp(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    st = p.spec.stp
    prio = ""
    if st.root_priority is not None:
        prio = (f"spanning-tree mst 0 priority {st.root_priority}" if st.mode == "mst" else
                f"spanning-tree vlan {p.vlan_list([i for i, _ in p.vlans])} priority "
                f"{st.root_priority}")
    return {"stp_mode": st.mode, "bpduguard_default": p.plat["bpduguard_default"],
            "root_priority": prio, "udld_global": "udld enable" if p.spec.features.udld else ""}


def _s_l2(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    f = p.spec.features
    vl = p.vlan_list(p.snoop_vlans)
    snoop = "" if not f.dhcp_snooping else _items(parts, "dhcp-snooping", [
        {"snoop_vlan_line": f"ip dhcp snooping vlan {vl}" if vl else ""}])
    dai = "" if not f.dai else _items(parts, "dai", [
        {"dai_vlan_line": f"ip arp inspection vlan {vl}" if vl else ""}])
    return {"dhcp_snooping": snoop, "dai": dai,
            "device_tracking": p.plat["device_tracking"] or ""}


def _trunk_common(p: _Plan, allowed: tuple[int, ...]) -> dict[str, object]:
    f = p.spec.features
    return {"native_vlan": p.native, "allowed_vlans": p.vlan_list(allowed),
            "dhcp_trust": "ip dhcp snooping trust" if f.dhcp_snooping else "",
            "dai_trust": "ip arp inspection trust" if f.dai else ""}


def _s_uplinks(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    rows, channels, seen = [], [], set()
    for u in p.spec.uplinks:
        row = _trunk_common(p, u.allowed_vlans)
        row.update(interface=u.interface, description=u.description,
                   udld_port="udld port aggressive" if p.spec.features.udld else "",
                   channel_group="" if u.channel_group is None else
                   f"channel-group {u.channel_group} mode active")
        rows.append(row)
        if u.channel_group is not None and u.channel_group not in seen:
            seen.add(u.channel_group)
            ch = _trunk_common(p, u.allowed_vlans)
            ch.update(group=u.channel_group, description=u.description)
            channels.append(ch)
    return {"uplinks": _items(parts, "uplink", rows),
            "port_channels": _items(parts, "port-channel", channels)}


def _s_access(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    f = p.spec.features
    rows = []
    for a in p.spec.access_ports:
        voice = a.voice_vlan is not None
        rows.append({
            "range": a.range, "description": a.description, "vlan": a.vlan,
            "voice_vlan": f"switchport voice vlan {a.voice_vlan}" if voice else "",
            "portfast": p.plat["portfast"],
            "port_security": "" if not f.port_security else
            _items(parts, "port-security", [{"maximum": 3 if voice else 2}]),
            "storm_control": "" if not f.storm_control else _items(parts, "storm-control", [{}]),
            "dhcp_rate": "ip dhcp snooping limit rate 15" if f.dhcp_snooping else "",
            "cdp_port": "no cdp enable" if p.has_voice and not voice else "",
        })
    return {"access_ranges": _items(parts, "range", rows)}


def _s_unused(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    return {"unused_ranges": _items(parts, "range", [
        {"range": r, "parking_vlan": p.parking,
         "cdp_port": "no cdp enable" if p.has_voice else ""} for r in p.spec.unused_ports])}


def _s_management(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    gw = "gateway-distribution" if p.spec.role == "distribution" else "gateway-access"
    return {"mgmt_vlan": p.mgmt_vlan, "mgmt_address": p.mgmt_address, "mgmt_mask": p.mgmt_mask,
            "gateway": _items(parts, gw, [{"gateway_address": p.spec.management.gateway}])}


def _s_acl(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    entries = []
    for src in p.spec.management.allowed_sources:
        net = ipaddress.IPv4Network(src if "/" in src else src + "/32")
        if net.prefixlen == 32:
            entries.append(_items(parts, "host", [{"address": net.network_address}]))
        else:
            entries.append(_items(parts, "network", [{"network": net.network_address,
                                                      "wildcard": net.hostmask}]))
    return {"acl_name": p.spec.management.acl_name, "acl_entries": "\n".join(entries)}


def _s_boot(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    return {"boot_image": p.plat["boot_image"],
            "redundancy": _items(parts, "redundancy", [{}]) if p.plat["redundancy_sso"] else ""}


def _s_footer(p: _Plan, parts: Parts, done: list[str]) -> Mapping[str, object]:
    return {"placeholder_list": _items(parts, "placeholder", [
                {"placeholder": ph} for ph in placeholders(done)]),
            "operator_note_list": _items(parts, "operator-note", [
                {"note": n} for n in operator_notes(p.spec)])}


_RENDERERS: Mapping[str, Renderer] = {
    "00-header": _s_header, "05-services": _s_services, "10-users-aaa": _s_aaa,
    "15-lines": _s_lines, "20-ssh": _s_ssh, "25-snmp": _s_snmp, "30-ntp": _s_ntp,
    "35-logging": _s_logging, "40-vlans": _s_vlans, "45-stp": _s_stp, "50-l2-security": _s_l2,
    "55-uplinks": _s_uplinks, "60-access-ports": _s_access, "65-unused-ports": _s_unused,
    "70-management": _s_management, "75-mgmt-acl": _s_acl, "80-boot-resilience": _s_boot,
    "99-footer": _s_footer,
}

_PREDICATES: Mapping[str, Callable[[Spec], bool]] = {
    "uplinks": lambda s: bool(s.uplinks),
    "access_ports": lambda s: bool(s.access_ports),
    "unused_ports": lambda s: bool(s.unused_ports),
}


# --------------------------------------------------------------------------- public API

# Operator steps that are not configuration. `switch N priority P`
# is privileged EXEC on Catalyst 9300 and is stored outside running-config, so it is never
# written as a configuration line; it travels here, as guidance for the operator.
STACK_MEMBER = 1
STACK_PRIORITY = 15


def operator_notes(spec: Spec) -> list[str]:
    """Guidance the operator must act on outside configuration mode, in a fixed order."""
    return [f"Run in privileged EXEC on the stack: switch {STACK_MEMBER} priority "
            f"{STACK_PRIORITY}"]


def placeholders(lines: list[str] | tuple[str, ...]) -> list[str]:
    """Every distinct `<REPLACE-ME:...>` in `lines`, in order of first appearance."""
    seen: list[str] = []
    for line in lines:
        for m in PLACEHOLDER_RE.finditer(line):
            if m.group(0) not in seen:
                seen.append(m.group(0))
    return seen


def render(spec: Spec, *, base: str | None = None) -> tuple[str, ...]:
    """The configuration, one line per element, in the frozen section order."""
    root = Path(base) if base else data_dir()
    sections: tuple[Section, ...] = load_sections(str(root / "sections.json"))
    if tuple(s.name for s in sections) != SECTION_NAMES:
        raise BaselineBuildError("baseline sections.json does not list the frozen sections")
    plan = _Plan(spec, _platform_table(root, spec.platform))
    lines: list[str] = []
    for sec in sections:
        if sec.when is not None and not _PREDICATES[sec.when](spec):
            continue
        renderer = _RENDERERS.get(sec.name)
        if renderer is None:                                  # pragma: no cover - guarded above
            raise BaselineBuildError(f"baseline section has no renderer: {sec.name}")
        parts = {k: load_template(v, root) for k, v in sec.parts}
        mapping = renderer(plan, parts, lines)
        lines.extend(_fill(load_template(sec.template, root), mapping, sec.template))
    return tuple(lines)


def render_json(spec: Spec, *, base: str | None = None) -> str:
    lines = render(spec, base=base)
    doc = {"lines": list(lines), "placeholders": placeholders(lines),
           "operator_notes": operator_notes(spec), "spec_digest": spec.digest()}
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
