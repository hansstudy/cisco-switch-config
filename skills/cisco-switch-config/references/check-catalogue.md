# Check catalogue

Catalogue version: `2026.09`. 121 checks.

## Table of contents

- [AAA](#aaa)
- [DHCP](#dhcp)
- [IFC](#ifc)
- [L2](#l2)
- [LOG](#log)
- [MGT](#mgt)
- [NTP](#ntp)
- [RES](#res)
- [SNMP](#snmp)
- [SSH](#ssh)
- [STP](#stp)
- [VTY](#vty)

## AAA

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-AAA-0001 | `aaa new-model` not enabled | high | security | deterministic |
| CSC-AAA-0002 | No `aaa authentication login` method list | high | security | deterministic |
| CSC-AAA-0003 | Login method list has no local fallback | medium | reliability | deterministic |
| CSC-AAA-0004 | `aaa authentication enable default` absent | medium | security | deterministic |
| CSC-AAA-0005 | `aaa authorization exec` absent | medium | security | deterministic |
| CSC-AAA-0006 | `aaa authorization console` absent | medium | security | deterministic |
| CSC-AAA-0007 | `aaa accounting commands` absent for privilege 15 | high | security | deterministic |
| CSC-AAA-0008 | Fewer than two TACACS+/RADIUS servers configured | medium | reliability | deterministic |
| CSC-AAA-0009 | AAA method list names an undefined server group | high | reliability | deterministic |
| CSC-AAA-0010 | Local user at privilege 15 with a type 0 or type 7 password | critical | security | deterministic |
| CSC-AAA-0011 | `enable-password` present, or `enable-secret` uses type 5 or weaker | high | security | deterministic |
| CSC-AAA-0012 | `service password-encryption` not enabled | medium | security | deterministic |

## DHCP

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-DHCP-0001 | `ip dhcp snooping` not enabled globally | high | security | deterministic |
| CSC-DHCP-0002 | DHCP snooping enabled but no VLAN list | high | security | deterministic |
| CSC-DHCP-0003 | An access VLAN is not covered by the snooping VLAN list | high | security | deterministic |
| CSC-DHCP-0004 | `ip dhcp snooping trust` missing on an uplink | high | reliability | heuristic |
| CSC-DHCP-0005 | `ip dhcp snooping limit rate` not set on access ports | low | reliability | heuristic |
| CSC-DHCP-0006 | `ip dhcp snooping database` not configured | low | reliability | deterministic |
| CSC-DHCP-0007 | `ip dhcp snooping information option` left enabled without `allow-untrusted` handling | low | reliability | deterministic |
| CSC-DHCP-0008 | Dynamic ARP Inspection not enabled on snooped VLANs | high | security | deterministic |
| CSC-DHCP-0009 | DAI `validate src-mac dst-mac ip` not configured, or trust misplaced | medium | security | heuristic |

## IFC

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-IFC-0001 | Hard-coded `speed` or `duplex` on a copper access port | medium | reliability | deterministic |
| CSC-IFC-0002 | Trunk or uplink has no `description` | low | reliability | heuristic |
| CSC-IFC-0003 | `ip proxy-arp` not disabled on a routed interface | medium | security | deterministic |
| CSC-IFC-0004 | `ip redirects` / `ip unreachables` not disabled on a routed interface | low | security | deterministic |
| CSC-IFC-0005 | `ip directed-broadcast` enabled | high | security | deterministic |
| CSC-IFC-0006 | `ip verify unicast source reachable-via rx` absent on a routed edge | low | security | heuristic |
| CSC-IFC-0007 | CDP left enabled globally | low | security | deterministic |
| CSC-IFC-0008 | CDP disabled on a switch carrying `switchport voice vlan` | medium | reliability | heuristic |

## L2

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-L2-0001 | Native VLAN on a trunk is VLAN 1 | high | security | deterministic |
| CSC-L2-0002 | Native VLAN equals an access VLAN in use | high | security | deterministic |
| CSC-L2-0003 | Access port assigned to VLAN 1 | medium | security | deterministic |
| CSC-L2-0004 | `interface Vlan1` not shut down | medium | security | deterministic |
| CSC-L2-0005 | Trunk allowed-VLAN list is `all` rather than explicit | medium | security | heuristic |
| CSC-L2-0006 | DTP not disabled (`switchport nonegotiate` absent on a trunk) | medium | security | heuristic |
| CSC-L2-0007 | Port left at DTP dynamic (no explicit `switchport mode`) | medium | security | deterministic |
| CSC-L2-0008 | Unused port not shut down | medium | security | heuristic |
| CSC-L2-0009 | Unused port not parked in an unused VLAN | low | security | heuristic |
| CSC-L2-0010 | Port security not configured on an access port | medium | security | heuristic |
| CSC-L2-0011 | Port security `maximum` above 3, or violation mode not restrict/shutdown | low | security | deterministic |
| CSC-L2-0012 | Storm control not configured on an access port | medium | reliability | heuristic |
| CSC-L2-0013 | VTP mode is server or client rather than transparent/off | medium | reliability | deterministic |
| CSC-L2-0014 | VTP domain configured without a VTP password | medium | security | deterministic |

## LOG

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-LOG-0001 | No `logging host` configured | high | security | deterministic |
| CSC-LOG-0002 | Fewer than two syslog destinations | low | reliability | deterministic |
| CSC-LOG-0003 | `logging trap` level below `informational` | medium | security | deterministic |
| CSC-LOG-0004 | `service timestamps log datetime msec localtime show-timezone` absent | medium | reliability | deterministic |
| CSC-LOG-0005 | `logging buffered` absent or below 16 KB | low | reliability | deterministic |
| CSC-LOG-0006 | `logging source-interface` not set to a stable interface | low | reliability | deterministic |
| CSC-LOG-0007 | `archive` / `log config` not enabled | medium | security | deterministic |
| CSC-LOG-0008 | `archive log config` missing `hidekeys` | high | security | deterministic |
| CSC-LOG-0009 | `logging console` left enabled at a verbose level | low | reliability | deterministic |

## MGT

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-MGT-0001 | HTTP server enabled (`ip http server`) | high | security | deterministic |
| CSC-MGT-0002 | HTTPS server not restricted by `ip http access-class` | high | security | deterministic |
| CSC-MGT-0003 | `ip http secure-server` disabled while `ip http server` is enabled | medium | security | deterministic |
| CSC-MGT-0004 | `service pad` enabled | low | security | deterministic |
| CSC-MGT-0005 | TCP/UDP small servers enabled | medium | security | deterministic |
| CSC-MGT-0006 | `ip bootp server` enabled | low | security | deterministic |
| CSC-MGT-0007 | `ip finger` / `service finger` enabled | low | security | deterministic |
| CSC-MGT-0008 | `ip source-route` enabled | medium | security | deterministic |
| CSC-MGT-0009 | `service config` (network autoload) enabled | medium | security | deterministic |
| CSC-MGT-0010 | `vstack` (Smart Install client) not disabled | critical | security | deterministic |
| CSC-MGT-0011 | `service call-home` enabled (phones home to Cisco) | medium | security | deterministic |
| CSC-MGT-0012 | `netconf-yang` or `restconf` enabled without an access restriction | high | security | deterministic |
| CSC-MGT-0013 | `ip domain-lookup` enabled with no `ip name-server` | low | reliability | deterministic |
| CSC-MGT-0014 | Configuration references an undefined object | medium | reliability | deterministic |

## NTP

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-NTP-0001 | No `ntp server` configured | medium | reliability | deterministic |
| CSC-NTP-0002 | Fewer than two NTP sources | low | reliability | deterministic |
| CSC-NTP-0003 | `ntp authenticate` not enabled | medium | security | deterministic |
| CSC-NTP-0004 | An `ntp server` has no `key` binding | medium | security | deterministic |
| CSC-NTP-0005 | An `ntp server ... key N` has no matching `ntp trusted-key N` | medium | security | deterministic |
| CSC-NTP-0006 | NTP authentication key uses MD5 rather than SHA1/SHA2 | low | security | deterministic |
| CSC-NTP-0007 | `ntp source` not set to a stable interface | low | reliability | deterministic |

## RES

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-RES-0001 | No `boot system` statement, or a non-deterministic boot order | medium | reliability | deterministic |
| CSC-RES-0002 | `boot system` names an image over a network URL | high | security | deterministic |
| CSC-RES-0003 | `errdisable recovery cause` not configured for the common causes | medium | reliability | deterministic |
| CSC-RES-0004 | `errdisable recovery interval` below 300 seconds | low | reliability | deterministic |
| CSC-RES-0005 | Stack member priority cannot be verified from a config file (`switch N priority`) | medium | reliability | manual-review |
| CSC-RES-0006 | Stack MAC persistence not configured (`stack-mac persistent timer`) | medium | reliability | deterministic |
| CSC-RES-0007 | `redundancy mode sso` absent on a stack-capable platform | low | reliability | deterministic |
| CSC-RES-0008 | `ip device tracking` probe defaults left in place (duplicate-IP symptoms) | medium | reliability | deterministic |

## SNMP

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-SNMP-0001 | SNMPv1/v2c community string configured | high | security | deterministic |
| CSC-SNMP-0002 | Community string is read-write (`RW`) | critical | security | deterministic |
| CSC-SNMP-0003 | Community string matches a known default | critical | security | deterministic |
| CSC-SNMP-0004 | Community string not restricted by an ACL | high | security | deterministic |
| CSC-SNMP-0005 | Community ACL is referenced but undefined | high | security | deterministic |
| CSC-SNMP-0006 | No SNMPv3 group with `priv` configured | high | security | deterministic |
| CSC-SNMP-0007 | A configured SNMP trap/inform target uses v1/v2c instead of SNMPv3 | high | security | deterministic |
| CSC-SNMP-0008 | No `snmp-server enable traps` for link/config/auth events | low | reliability | deterministic |
| CSC-SNMP-0009 | `snmp ifmib ifindex persist` not configured | medium | reliability | deterministic |
| CSC-SNMP-0010 | SNMPv3 user inventory cannot be audited from a running-config | info | security | manual-review |

## SSH

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-SSH-0001 | `ip ssh version 2` not enforced | high | security | deterministic |
| CSC-SSH-0002 | No RSA/EC key generated (`crypto key` / `ip domain-name` prerequisites absent) | high | reliability | deterministic |
| CSC-SSH-0003 | `ip ssh dh min size` below 2048 | medium | security | deterministic |
| CSC-SSH-0004 | `ip ssh server algorithm encryption` permits a CBC or weak cipher | high | security | deterministic |
| CSC-SSH-0005 | `ip ssh server algorithm mac` permits HMAC-SHA1 or MD5 | medium | security | deterministic |
| CSC-SSH-0006 | `ip ssh server algorithm kex` permits a group-1/group-14-sha1 exchange | medium | security | deterministic |
| CSC-SSH-0007 | `ip ssh authentication-retries` above 3 | low | security | deterministic |
| CSC-SSH-0008 | `ip ssh time-out` above 60 seconds | low | security | deterministic |
| CSC-SSH-0009 | Self-signed or expired-issuer trustpoint used for management | info | security | manual-review |

## STP

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-STP-0001 | `spanning-tree mode` is PVST rather than Rapid-PVST or MST | medium | reliability | deterministic |
| CSC-STP-0002 | PortFast not enabled on access ports | medium | reliability | heuristic |
| CSC-STP-0003 | BPDU Guard is not enabled by default on PortFast ports | high | reliability | deterministic |
| CSC-STP-0004 | BPDU Guard missing on an individual access port | high | security | heuristic |
| CSC-STP-0005 | Root Guard absent on ports facing another switch | medium | reliability | heuristic |
| CSC-STP-0006 | Loop Guard not enabled by default | medium | reliability | deterministic |
| CSC-STP-0007 | `spanning-tree bpdufilter` enabled (hides loops) | high | reliability | deterministic |
| CSC-STP-0008 | No explicit root bridge priority set for any VLAN | medium | reliability | deterministic |
| CSC-STP-0009 | Root bridge placement cannot be judged from one config | info | reliability | manual-review |
| CSC-STP-0010 | UDLD not enabled (`udld enable` / per-port aggressive) | medium | reliability | deterministic |

## VTY

| id | title | severity | category | confidence |
|---|---|---|---|---|
| CSC-VTY-0001 | A vty line accepts a non-SSH transport | critical | security | deterministic |
| CSC-VTY-0002 | A vty line has no `access-class` restriction | high | security | deterministic |
| CSC-VTY-0003 | `access-class` names an undefined ACL | high | security | deterministic |
| CSC-VTY-0004 | A vty line has `exec-timeout 0 0` or a timeout above 10 minutes | medium | security | deterministic |
| CSC-VTY-0005 | A line carries a local `password` instead of using AAA | high | security | deterministic |
| CSC-VTY-0006 | `line aux 0` not disabled (`no exec` / `transport input none`) | high | security | deterministic |
| CSC-VTY-0007 | `line con 0` has no `exec-timeout` or `logging synchronous` | medium | reliability | deterministic |
| CSC-VTY-0008 | `transport output` not restricted | low | security | deterministic |
| CSC-VTY-0009 | `login block-for` / `login quiet-mode` not configured | medium | security | deterministic |
| CSC-VTY-0010 | Login banner absent | medium | security | deterministic |
| CSC-VTY-0011 | Login banner content is trivial or omits the required elements | low | security | heuristic |
