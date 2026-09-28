# Remediation patterns

Every `remediation` in the catalogue is a list of literal IOS/IOS-XE configuration lines.
A line may contain `{name}` placeholders using `str.format_map` syntax; `{{` and `}}` are the
literal-brace escapes, and a bare `$` is never special here (that syntax belongs to the
baseline generator's spec templates, not to remediation text). The engine's Finding factory
substitutes these when it builds the finding; reporters only ever see substituted text.

## The closed variable vocabulary

Exactly eight names may appear in a remediation template. A template naming anything else
fails the catalogue build (`test_template_vars`).

| Variable | Meaning | Example rule that supplies it |
|---|---|---|
| `interface` | Canonical interface name | CSC-STP-0004 (BPDU Guard missing on a port) |
| `vlan` | A VLAN id | CSC-L2-0002 (native VLAN equals an access VLAN) |
| `acl_name` | A named or numbered ACL, as a string | CSC-VTY-0002 (vty `access-class`) |
| `acl_number` | A numbered ACL, reserved for rules that specifically need the numeric form | — |
| `host` | An IP address or hostname | CSC-LOG-0001 (`logging host`) |
| `group` | An AAA server-group or SNMPv3 group name | CSC-AAA-0009, CSC-SNMP-0006 |
| `key_id` | An NTP or similar numeric key id | CSC-NTP-0004, CSC-NTP-0005 |
| `line_range` | A `line vty <first> <last>` range | CSC-VTY-0002, CSC-VTY-0004 |

A rule that cannot supply a variable it names never crashes the run: the engine renders the
gap as `<TODO:name>` and raises an informational `CSC-SELF-0002` note instead of a literal
`{name}` or a `KeyError`.

## Secret positions are never a `{name}` variable

Wherever a remediation line has to hold a value the operator must choose and the tool cannot
safely print — a new password, a PSK, a shared secret — the template spells it as
`<REPLACE-ME:...>`, never as a `{name}` placeholder and never as unbracketed free text such as
`<community>`. `mask.is_placeholder()` recognises this exact shape and the parser treats it as
an intentional stand-in rather than a value to redact. Examples in this catalogue:
`<REPLACE-ME:snmp-community>`, `<REPLACE-ME:enable-secret>`, `<REPLACE-ME:local-user-secret>`,
`<REPLACE-ME:vtp-password>`, `<REPLACE-ME:ntp-key>`, `<REPLACE-ME:management-subnet>`.

## Patterns grouped by theme

**Disabling an unnecessary global service** (CSC-MGT-0001, 0004-0009, 0011; CSC-IFC-0007) —
a single `no <feature>` or `no service <feature>` line, no variables needed.

**Scoping a management listener to a subnet** (CSC-MGT-0002, CSC-VTY-0002, CSC-SNMP-0004) —
`{acl_name}` names an ACL the operator is expected to already have, or to create alongside the
fix; CSC-VTY-0003 and CSC-SNMP-0005 show the paired "define the ACL" remediation for when that
ACL turns out not to exist.

**Per-port hygiene** (CSC-L2-0001..0012, CSC-DHCP-0004..0005, CSC-IFC-0001..0006, CSC-STP-0004,
0005) — `interface {interface}` as the first remediation line, then the specific
`switchport`/`spanning-tree`/`ip` sub-command; several also take `{vlan}` when the fix pins a
VLAN id (CSC-L2-0002, 0003, 0009).

**AAA and central services** (CSC-AAA-0008, 0009; CSC-LOG-0001, 0002; CSC-NTP-0001, 0002, 0004)
— `{host}` for a server address, `{group}` for the AAA/SNMPv3 group name, `{key_id}` for an
NTP key id. These are deliberately left as one-line templates rather than full worked
examples, since the operator's actual server addresses and group names are the point of the
finding.

**Not-effectively-set global posture** (CSC-SSH-0001, 0003-0008; CSC-STP-0001, 0003, 0006, 0010;
CSC-IFC-0003, 0004, 0007) — a single global command with no variables; the finding fires
because the setting resolves to a platform default rather than because a bad value is present.
