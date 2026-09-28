# Baseline generator: spec, section order, and design choices

`gen_baseline.py` turns a JSON spec into a hardened IOS or IOS-XE switch configuration. The
model's job is to interview the user and build the spec. The script's job is to render it,
the same way every time. This file is the reference for both.

## Contents

1. Running the generator
2. The spec, field by field
3. Secrets: what the spec refuses, and the placeholders
4. Cross-field rules
5. Section order, and why
6. Defaults and house conventions
7. Platform differences
8. What the baseline does not decide for you
9. Checking the result

## 1. Running the generator

```
gen_baseline.py <spec-path|-> [--format cli|json] [--out <path>]
```

- `--format cli` (the default) prints the configuration, ready to paste in configuration mode.
- `--format json` prints `{"lines": [...], "placeholders": [...], "operator_notes": [...],
  "spec_digest": "..."}`. `operator_notes` lists steps that are not configuration (below).
  `spec_digest` is the sha256 of the defaults-applied spec, canonicalised.
- `--out <path>` writes exactly that file and nothing else.
- Exit codes: 0 generated; 2 the spec is unreadable or invalid (the message names the key and
  the rule, never a value); 3 a template or build file is missing; 4 internal error; 5 the
  egress guard found an unmasked secret shape in the output, and the output was suppressed.

The same spec always gives the same bytes: no timestamps, no random values, and every list
is rendered in the order the spec gives it.

## 2. The spec, field by field

The schema is `data/schema/spec.schema.json` (JSON Schema draft 2020-12). No object accepts
a key it does not list.

| Key | Required | Default | Notes |
|---|---|---|---|
| `version` | yes | - | must be `1` |
| `hostname` | yes | - | letters, digits, hyphens; at most 63 characters |
| `domain_name` | yes | - | needed to generate the SSH host key |
| `platform` | no | `iosxe` | `ios` or `iosxe` |
| `role` | no | `access` | `access` or `distribution` |
| `management.vlan` | yes | - | 2-4094, never 1, never 1002-1005 |
| `management.address` | yes | - | CIDR, such as `10.10.99.11/24`; a host address, /30 or larger |
| `management.gateway` | yes | - | another host in the management subnet |
| `management.acl_name` | no | `MGMT-ACCESS` | the standard ACL used by vty and SNMP |
| `management.allowed_sources` | yes | - | CIDRs allowed to manage the switch |
| `vlans` | yes | - | `{id, name, kind}`; kind is `data`, `voice`, `mgmt`, `unused` or `native` |
| `uplinks` | yes | - | `{interface, description, allowed_vlans, channel_group?}` |
| `access_ports` | yes | - | `{range, vlan, voice_vlan?, description}` |
| `unused_ports` | no | `[]` | interface ranges, parked and shut down |
| `stp.mode` | no | `rapid-pvst` | `rapid-pvst` or `mst` |
| `stp.root_priority` | no | `null` | a multiple of 4096, 0-61440 |
| `aaa.tacacs_hosts` | no | `[]` | IPv4 addresses only |
| `aaa.radius_hosts` | no | `[]` | IPv4 addresses only |
| `aaa.group_name` | no | `ISE` | the server group the method lists use |
| `snmp.v3_user` | no | `null` | the user **name** only |
| `snmp.v3_group` | no | `RO-GROUP` | |
| `ntp.servers` | yes | - | IPv4 addresses only |
| `ntp.key_id` | no | `1` | |
| `logging.hosts` | yes | - | IPv4 addresses only |
| `logging.trap_level` | no | `informational` | a syslog level name |
| `banner.motd` | no | house text | plain text, may span lines, no `^` |
| `features.*` | no | `true` | `dhcp_snooping`, `dai`, `port_security`, `storm_control`, `udld` |
| `archive.path` | no | `flash:archive` | on the switch's own file system: `flash`, `bootflash`, `usbflash<n>`, `crashinfo`, `disk<n>`; a URL or a remote scheme such as `ftp:` is rejected |

Interface ranges use the auditor's grammar: `GigabitEthernet1/0/1 - 24`,
`Gi1/0/1-4, Gi1/0/10-12`. Descriptions are printable ASCII, at most 200 characters.
Addresses are IPv4 only in this version. The spec must be UTF-8 (a leading BOM is allowed);
any other encoding is exit 2, naming the byte offset.

## 3. Secrets: what the spec refuses, and the placeholders

The spec has no field for a secret. Any key, at any depth, whose name ends in `pass`,
`passwd`, `password`, `secret`, `key`, `psk`, `token`, `community`, `credential` or `cred`
is rejected with exit 2. The structural names `aaa.group_name`, `ntp.key_id`,
`management.acl_name`, `snmp.v3_user` and `snmp.v3_group` are allowed. The error names the
key and the placeholder the output uses instead, and never quotes the value:

```
spec error: key "aaa.tacacs_key" is a secret field and is not accepted.
            The generated configuration emits <REPLACE-ME:tacacs-key>; fill it on the device.
```

| Rejected key | Placeholder in the output |
|---|---|
| `tacacs_key`, `tacacs.key` | `<REPLACE-ME:tacacs-key>` |
| `radius_key`, `radius.key` | `<REPLACE-ME:radius-key>` |
| `snmp_auth_password`, `snmp.v3_auth` | `<REPLACE-ME:snmpv3-auth>` |
| `snmp_priv_password`, `snmp.v3_priv` | `<REPLACE-ME:snmpv3-priv>` |
| `ntp_key`, `ntp.key` | `<REPLACE-ME:ntp-key-N>`, N being `ntp.key_id` |
| `enable_secret` | `<REPLACE-ME:enable-secret>` |
| `local_password`, `local_secret` | `<REPLACE-ME:local-admin-secret>` |
| `vtp_password` | none: the baseline runs VTP transparent |
| `archive_password`, or `user:pw@` in `archive.path` | none: the archive path must be local |

A `user:password@host` shape in **any** string value is also rejected, because the masker
would redact it and the egress guard would refuse the output.

The placeholders sit in exactly the slots the masker treats as value slots, so the auditor
passes them through untouched and lists each one as a `CSC-SELF-0007` note. Type-bearing
slots carry the algorithm on the line (`enable algorithm-type scrypt secret
<REPLACE-ME:enable-secret>`), so the strength is visible without a value. For
`ios`, `boot system` also carries `<REPLACE-ME:image-file>`, because the image name cannot
be guessed. The footer lists every placeholder, in order of first use, then the operator
notes: steps that are not configuration mode commands, printed as comments so a paste
never executes them.

## 4. Cross-field rules

These are enforced by the generator, beyond the schema:

- A VLAN whose id is `management.vlan` must have kind `mgmt`, and a `mgmt` VLAN must be the
  management VLAN. At most one `native` VLAN. VLAN ids and names are unique.
- An access range's `vlan` must be a `data` VLAN, and its `voice_vlan` a `voice` VLAN.
- An uplink's `allowed_vlans` must be VLANs the spec defines (or the management VLAN).
  Uplinks sharing a `channel_group` must allow the same VLAN list.
- No interface may appear in more than one uplink, access range or unused range.
- At least one TACACS+ or RADIUS server is required: a hardened baseline authenticates and
  accounts centrally, with a local fallback.
- `features.dai` requires `features.dhcp_snooping`.

## 5. Section order, and why

The sections are pasted in this order, which is also an order the switch accepts:

| Section | Contents |
|---|---|
| `00-header` | hostname, domain name, a comment block (platform, role, spec digest) |
| `05-services` | legacy services off: HTTP/HTTPS, pad, small servers, bootp, finger, source routing, Smart Install, call-home; `no cdp run` when no voice VLAN |
| `10-users-aaa` | `enable algorithm-type scrypt secret`, one local admin, `aaa new-model`, servers, server group, method lists, accounting |
| `15-lines` | login hardening, the banner, console, aux, vty 0 15 |
| `20-ssh` | RSA 4096 host key, SSH v2, timeouts, algorithms |
| `25-snmp` | an SNMPv3 `priv` group bound to the management ACL, the user line, traps |
| `30-ntp` | authenticated NTP: key, trusted key, source, servers |
| `35-logging` | timestamps, buffer, console level, syslog hosts, the config archive with `hidekeys` |
| `40-vlans` | VTP transparent, then the VLANs |
| `45-stp` | mode, BPDU Guard by default, Loop Guard, root priority, UDLD |
| `50-l2-security` | DHCP snooping, DAI, error-disable recovery |
| `55-uplinks` | trunks: native VLAN, allowed list, no DTP, snooping and DAI trust |
| `60-access-ports` | `interface range`: access VLAN, voice VLAN, PortFast, BPDU Guard, port security, storm control, snooping rate limit |
| `65-unused-ports` | `interface range`: parking VLAN, shut down |
| `70-management` | `interface Vlan1` shut, the management SVI, default gateway |
| `75-mgmt-acl` | the standard ACL the vty lines and SNMP group use |
| `80-boot-resilience` | boot image, SSO, persistent stack MAC (`stack-mac persistent timer 0`) |
| `99-footer` | the placeholder list, the operator notes as comments, then `end` |

AAA comes before the lines so that `login authentication default` has a method list to use.
The ACL comes late, but IOS accepts a reference to an ACL defined later in the same paste.
Every child line is indented one space under its parent, as IOS prints it. The banner uses
the multi-line `^C` form. Both keep the round trip into the auditor independent of its
fallback parsing rules.

## 6. Defaults and house conventions

- **VLAN ids repeat across access switches, subnets do not.** Data VLAN 10 means the same
  thing on every access switch; each switch's management address differs.
- **VLANs the baseline adds.** If the management VLAN is not in `vlans`, it is added as
  `MGMT`. If there are unused ports and no `unused` VLAN, a parking VLAN is added. If there
  are uplinks and no `native` VLAN, a dedicated native VLAN named `NATIVE-UNUSED` is added
  and left out of every allowed list, so untagged frames on a trunk go nowhere. An added
  VLAN takes the highest free id at or below 999.
- **Port security**: at most 3 MAC addresses with a voice VLAN (phone plus PC), 2 without;
  violation `restrict`; inactivity aging of 2 minutes.
- **Storm control**: broadcast 1%, multicast 5%, action `trap`.
- **CDP**: IP phones need it, so with any voice VLAN CDP stays on globally and is disabled
  per port on non-voice and unused ports. Without voice VLANs, `no cdp run`.
- **DHCP snooping and DAI** cover the `data` and `voice` VLANs. The management VLAN is not
  inspected, because its hosts use static addresses. Uplinks are trusted.
- **AAA**: TACACS+ is preferred for device administration. With both TACACS+ and RADIUS
  hosts, the RADIUS group is named `<group_name>-RADIUS` and is tried second. Accounting
  goes to the first group.
- **Timeouts**: exec 10 minutes; SSH 60 seconds and 3 retries; login blocked for 120
  seconds after 3 failures in 60.
- **Distribution role**: routing is enabled and the gateway becomes a static default route.
  An access switch uses `ip default-gateway`.

## 7. Platform differences

| Item | `iosxe` | `ios` |
|---|---|---|
| PortFast keyword | `spanning-tree portfast edge` | `spanning-tree portfast` |
| NTP key algorithm | `hmac-sha2-256` | `md5` (the only one IOS 15 offers) |
| SSH ciphers | `aes256-gcm aes256-ctr` | `aes256-ctr aes192-ctr aes128-ctr` |
| SSH key exchange | ECDH P-384/P-256 | not set (older releases lack the command) |
| Boot image | `flash:packages.conf` | `flash:<REPLACE-ME:image-file>` |
| `redundancy` / `mode sso` | emitted | not emitted |
| Device tracking | not emitted | `ip device tracking probe delay 10` |

The per-platform values live in `data/baseline/platforms.json`.

## 8. What the baseline does not decide for you

- Which ports face other switches. Put them in `uplinks` (trunks). Access ranges get
  PortFast and BPDU Guard, which shut a port that hears a BPDU.
- Root bridge placement across the network. Set `stp.root_priority` deliberately.
- Stack membership. `switch N priority P` is a privileged EXEC command on Catalyst 9300 and
  is stored outside running-config, so the baseline never writes it as configuration. It is
  an **operator note** instead: `operator_notes` in `--format json`, and a comment block in
  the footer of `--format cli` reading "Run in privileged EXEC on the stack: switch 1
  priority 15". Adjust the member and priority for the stack. The persistent stack MAC
  (`stack-mac persistent timer 0`) is configuration and stays in section 80.
- Any value in a `<REPLACE-ME:...>` slot. Never fill one from the conversation.

Turning a `features` flag off is allowed, and the audit then reports the missing control.
That is the trade-off made visible, not a generator defect.

## 9. Checking the result

```
gen_baseline.py spec.json | audit_config.py - --platform iosxe
```

The audit should report no `critical` or `high` findings, and one `CSC-SELF-0007` note for
each unfilled placeholder slot.
