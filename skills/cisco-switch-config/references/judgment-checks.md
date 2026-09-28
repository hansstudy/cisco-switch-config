# Judgment checks

Some questions cannot be answered from one switch's configuration text. The engine reports
them as `manual-review` findings carrying extracted evidence, or as `heuristic` findings that
rest on an inferred role. This file says, for each one, what the evidence gives you, what to
ask the user, and what a good answer looks like. The credential rules in `SKILL.md` apply
throughout.

## Contents

1. How to work a judgment check
2. Show commands that are safe to request
3. CSC-SNMP-0010 — SNMPv3 user inventory
4. CSC-SSH-0009 — management trustpoint
5. CSC-STP-0009 — root bridge placement
6. Is this port really user-facing? (the role question behind most heuristic findings)
7. Uplink diversity
8. AAA, syslog and NTP servers: reachable and correctly keyed
9. The boot image
10. Control-plane policing (CoPP) adequacy
11. ACL content against the address plan
12. uRPF mode (CSC-IFC-0006)
13. The parking VLAN (CSC-L2-0009)
14. VLAN and segmentation design
15. Licence tier and feature availability
16. Login banner wording (CSC-VTY-0011)

## 1. How to work a judgment check

1. Quote the finding's `CSC-*` id, title and extracted evidence as the script printed it.
2. Say in one sentence why the configuration alone cannot decide it.
3. Ask the smallest set of questions, or request the one `show` command, that would decide it.
4. Give a verdict in the user's terms: fine as is, change recommended (with the change), or
   still undecidable (and what would decide it).
5. Never turn a judgment call into a `deterministic` claim, and never ask for a credential to
   settle one. None of these questions needs a credential value.

## 2. Show commands that are safe to request

These commands print state, not credential values, so you may ask the user to run them and
paste the output:

| Question | Command |
|---|---|
| SNMPv3 users and their security level | `show snmp user` |
| Trustpoints and certificate validity | `show crypto pki trustpoints status`, `show crypto pki certificates` |
| Which switch is root, per VLAN | `show spanning-tree root`, `show spanning-tree bridge` |
| What each port connects to | `show cdp neighbors`, `show lldp neighbors`, `show interfaces status` |
| Image, release and licence | `show version`, `show license summary` |
| Control-plane policing | `show policy-map control-plane` |

Never request `show running-config all`, `show tech-support` or any other capture that
includes the configuration's credential lines for a judgment question. If pasted output does
contain a credential anyway, apply rule 3: do not repeat it.

## 3. CSC-SNMP-0010 — SNMPv3 user inventory

**Why it is manual.** `snmp-server user` lines are not displayed in `show running-config`, so
no verdict about SNMPv3 users can come from a running-config. Any tool that claims one is
guessing.

**What the evidence gives you.** The SNMPv3 groups that *are* displayed, with their security
level (`noauth`, `auth`, `priv`).

**Ask.** For the output of `show snmp user`, which lists each user, its group, and its
authentication and privacy protocols without any key.

**A good answer.** Every user belongs to a `priv` group, uses SHA-family authentication and
AES privacy, and is still needed. Users in `noauth` or `auth`-only groups, users with MD5 or
DES, and leftover users are changes to recommend. Recommend recreating the user with new
keys typed on the device. Never ask for the keys.

## 4. CSC-SSH-0009 — management trustpoint

**Why it is manual.** Whether a trustpoint is acceptable depends on the organisation's PKI
and the certificate's validity, and neither is in the configuration.

**What the evidence gives you.** The trustpoint lines relevant to management (for example a
`crypto pki trustpoint` whose name marks it as self-signed, and the HTTPS server's
trustpoint binding). Certificate body lines between the opener and `quit` are masked as an
opaque block. A truncated body with no `quit` runs to the end of the file and is masked
there. Certificate data is public material in any case, not a credential.

**Ask.** Is HTTPS, RESTCONF or another web management interface in use at all? If yes: does
the organisation issue device certificates from its own CA? What do
`show crypto pki certificates` validity dates and issuer show?

**A good answer.** If no web management is used and the HTTP servers are disabled, the
trustpoint is harmless (say so, and point to CSC-MGT-0001 and CSC-MGT-0003 if those servers
are on). If web management is used, a certificate from the organisation's CA with a current
validity period is the target. A self-signed certificate is acceptable only as a documented
interim, and an expired issuer is a change to recommend.

## 5. CSC-STP-0009 — root bridge placement

**Why it is manual.** Whether *this* switch should be root for a VLAN is a topology question.

**What the evidence gives you.** The spanning-tree mode and the per-VLAN priority lines
(`spanning-tree vlan <list> priority <n>` or `root primary|secondary`), or their absence.

**Ask.** Is this an access, distribution or core switch? Which switches are intended as the
primary and secondary root for each VLAN? Where is each VLAN's default gateway (HSRP or VRRP
active)? If unsure, ask for `show spanning-tree root`.

**A good answer.** The distribution or core pair holds explicit primary and secondary root
priorities, and the primary root for each VLAN is the switch where that VLAN's gateway is
active. Access switches never win an election: their priority is left at the default or set
higher. An access switch carrying `root primary` is a change to recommend. So is a network
where no switch sets a priority (see also CSC-STP-0008), because root then goes to the lowest
MAC address.

## 6. Is this port really user-facing?

Most `heuristic` findings depend on an inferred interface role. Examples: PortFast and BPDU
Guard (CSC-STP-0002, CSC-STP-0004), Root Guard (CSC-STP-0005), DHCP snooping trust and rate
limits (CSC-DHCP-0004, CSC-DHCP-0005), DAI trust (CSC-DHCP-0009), trunk hygiene
(CSC-L2-0005, CSC-L2-0006), unused ports (CSC-L2-0008, CSC-L2-0009), port security
(CSC-L2-0010), storm control (CSC-L2-0012), and interface hygiene (CSC-IFC-0002,
CSC-IFC-0006, CSC-IFC-0008).

**Ask.** For the ports named in these findings: what is connected (users, phones, access
points, servers, another switch, a router or firewall)? `show cdp neighbors` and
`show lldp neighbors` answer most of it.

**A good answer** becomes a role map (`audit-workflow.md` section 7). Re-run with it, and the
affected findings become `deterministic`. Ports to another switch are `uplink` or `trunk`, and
want Root Guard (downstream) or DHCP snooping trust (toward the DHCP server), not BPDU Guard.
Ports to end hosts are `access` or `voice-access`. A port to an access point in FlexConnect
or local-switching mode is usually a trunk. Say which.

## 7. Uplink diversity

**Why it is manual.** Two uplinks in one EtherChannel look redundant in the configuration
but may share a line card, a stack member, a fibre path or an upstream switch.

**Ask.** Do the uplink members sit on different stack members or line cards? Do they land on
different upstream switches (for example a distribution pair using StackWise Virtual, VSS or
vPC)? Do the fibres take different paths?

**A good answer.** Members are spread across stack members and upstream chassis, the bundle
uses LACP (`mode active`) rather than `mode on`, and UDLD protects fibre links (CSC-STP-0010).

## 8. AAA, syslog and NTP servers: reachable and correctly keyed

**Why it is manual.** The configuration names servers and binds keys (all masked). It cannot
show that the servers answer, or that the keys match the servers' side.

**Ask.** Does login via TACACS+ or RADIUS work today, and does the local fallback work (test
from the console)? Do syslog messages from this switch arrive? Does `show ntp associations`
show a synchronised peer?

**A good answer** is operational evidence of each, not a configuration statement. If a key
mismatch is suspected, the fix is to set the key again on both ends from the organisation's
secret store. You never see either value.

## 9. The boot image

**Why it is manual.** A `boot system` line names a file. It cannot show that the file exists
in flash, or that the release is supported and free of known issues.

**Ask.** For `show version` (the running release) and, if needed, `dir flash:`. Compare the
release with Cisco's recommended and supported releases for that platform, which the user
checks with Cisco. Do not fetch them yourself (rule 6).

**A good answer.** The boot statement points at an image that exists, matches the running
release, and is a release the organisation has approved. On IOS-XE in install mode, the boot
target is `packages.conf` (see `platform-notes.md`).

## 10. Control-plane policing (CoPP) adequacy

**Why it is manual.** Adequate CoPP rates depend on the platform, the release's default
policy and the traffic the switch legitimately handles.

**Ask.** For the platform and release, and the output of `show policy-map control-plane`
(drop counters matter more than the rates).

**A good answer.** The platform's default CoPP policy is in place and unmodified unless there
is a documented reason. No class shows sustained drops of legitimate traffic (routing
protocols, management). Recommend tuning from Cisco's platform guidance, never a number you
invented.

## 11. ACL content against the address plan

**Why it is manual.** The engine checks that management ACLs *exist* and are *referenced*
(CSC-VTY-0002, CSC-VTY-0003, CSC-SNMP-0004, CSC-SNMP-0005, CSC-MGT-0002). Whether their
entries permit the right sources is a question about the address plan.

**Ask.** Which networks hold the management stations, jump hosts, NMS and monitoring
systems?

**A good answer.** Each management ACL permits exactly those networks and ends in an explicit
deny, ideally with `log`. `permit any` and entries for networks the user cannot name are
changes to recommend. Warn that tightening a vty ACL can lock out the operator: apply it from
a permitted host, with a console fallback.

## 12. uRPF mode (CSC-IFC-0006)

**Why it is manual.** Strict uRPF drops legitimate traffic on paths with asymmetric routing.

**Ask.** Is the routed interface a single-homed edge (strict mode is safe), or can return
traffic arrive on another interface (use loose mode, or none)?

**A good answer** matches the mode to the routing: strict on single-homed edges, loose or
none where paths are asymmetric.

## 13. The parking VLAN (CSC-L2-0009)

**Why it is manual.** A parking ("black-hole") VLAN is only safe if it is genuinely unused
everywhere, with no SVI, not allowed on any trunk, and not used on another switch.

**Ask.** Is the VLAN chosen for unused ports carried on any trunk or used elsewhere in the
campus?

**A good answer.** A dedicated VLAN, with no SVI, pruned from every trunk, and unused ports
shut down as well as parked.

## 14. VLAN and segmentation design

**Why it is manual.** Whether users, voice, management and devices are separated
appropriately depends on the organisation's policy.

**Ask.** What each VLAN is for, and which must not reach which.

**A good answer.** Management sits in its own VLAN (never VLAN 1). The native VLAN on trunks
is an unused VLAN (CSC-L2-0001, CSC-L2-0002). Voice and data are separate. Inter-VLAN
filtering happens where the policy says it should. Point out that enforcing that policy is
outside one switch's configuration.

## 15. Licence tier and feature availability

**Why it is manual.** Some features depend on the installed licence level (for example
Network Essentials versus Network Advantage on IOS-XE Catalyst), which the configuration may
not show.

**Ask.** For `show version` or `show license summary`.

**A good answer.** Each remediation you recommend is available at the installed tier. Where
it is not, say so and offer the nearest alternative.

## 16. Login banner wording (CSC-VTY-0011)

**Why it is judgment.** The check looks for consent, monitoring and authorised-use wording by
keyword. The right text depends on the organisation's legal policy, and US DoD systems need
their mandated notice. A banner line containing a word such as `password` or `key` is masked
from that word on, so the check may miss wording after it.

**Ask.** Does the organisation have approved banner text?

**A good answer** uses the organisation's approved text. Without one, suggest wording that
states the system is for authorised use only and that use may be monitored, and recommend
legal review. Never present your wording as legally sufficient.
