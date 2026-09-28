# Platform notes: IOS and IOS-XE

The command-language differences an operator meets between classic IOS Catalyst switches and
IOS-XE Catalyst switches, and how the engine decides which platform it is looking at. Read
this when a finding seems to ignore a command that is present, when the inferred platform
looks wrong, or when a remediation line uses a form the user's switch rejects.

## Contents

1. How the platform is inferred
2. How dialect differences are handled
3. PortFast and BPDU Guard: `portfast` vs `portfast edge`
4. Device tracking: `ip device tracking` vs `device-tracking policy`
5. Smart Install: `vstack`
6. `boot system` forms
7. Credential types and password encryption
8. Other IOS-XE-only surface forms
9. Interface names and abbreviations
10. Implicit defaults, and what "absent" means
11. Getting a clean capture

## 1. How the platform is inferred

`--platform ios|iosxe` overrides everything. Without it, the first rule that matches wins:

| Step | Signal | Result | `platform_source` |
|---|---|---|---|
| 1 | A `version` line: `16.x`, `17.x` or `3.x` | `iosxe` | `inferred-version` |
| 1 | A `version` line: `12.x` or `15.x` | `ios` | `inferred-version` |
| 2 | `boot system` image name: `cat9k*`, `cat3k_caa*`, `c3850*`, `c9?00*`, or any `*.SPA.bin` | `iosxe` | `inferred-image` |
| 2 | `boot system` image name: `c2960*`, `c3560*`, `c3750*` | `ios` | `inferred-image` |
| 3 | IOS-XE-only forms anywhere: `device-tracking policy`, `portfast edge`, `spanning-tree portfast edge`, `license boot level`, `ip http secure-active-session-modules` | `iosxe` | `inferred-surface` |
| 4 | Nothing matched | `iosxe` | `default` |

Every run names the result in a `CSC-SELF-0001` note, for example
`platform=iosxe source=inferred-version`. To explain an inference, point at the signal: "the
`version 17.9` line on line 4 identifies IOS-XE". A `default` result means the file had no
version line, no recognisable boot image and no IOS-XE-only command. Fragments often look
like this. Ask the user which platform it is and re-run with `--platform`.

Why it matters: the platform selects the defaults table (what an absent command means) and
the dialect table (which spellings count). A 2960 audited as IOS-XE, or a 9300 audited as
IOS, gives wrong absence verdicts and wrong remediation spellings.

## 2. How dialect differences are handled

Checks look for an *intent* (for example "BPDU Guard on by default for PortFast ports"), not
one spelling. The shipped dialect table lists the spellings each platform accepts for each
intent, so a hardened IOS-XE switch using the newer form is not told the feature is missing.
Remediation is chosen per platform from the same table, so the `fix:` line uses the form
that platform expects. If a user reports that a `fix:` line was rejected by their switch,
check the platform first, then the release (some forms need a minimum release).

## 3. PortFast and BPDU Guard: `portfast` vs `portfast edge`

| Intent | Classic IOS | IOS-XE |
|---|---|---|
| PortFast on one access port | `spanning-tree portfast` | `spanning-tree portfast edge` |
| PortFast on all access ports | `spanning-tree portfast default` | `spanning-tree portfast edge default` |
| BPDU Guard on all PortFast ports | `spanning-tree portfast bpduguard default` | `spanning-tree portfast edge bpduguard default` (the older spelling is also recognised) |
| PortFast on a trunk to a host (server, hypervisor) | `spanning-tree portfast trunk` | `spanning-tree portfast edge trunk` |

On IOS-XE, `spanning-tree portfast network` marks a port as a switch-to-switch link (Bridge
Assurance), not an edge port. Do not suggest it for access ports. Loop Guard
(`spanning-tree loopguard default`) and PortFast should not both apply to the same port.

## 4. Device tracking: `ip device tracking` vs `device-tracking policy`

Classic IOS 15.x uses IP Device Tracking (IPDT), enabled with `ip device tracking` and often
turned on implicitly by features that need it (802.1X, IP Source Guard). IPDT probes hosts
with ARP. With default probe settings, some hosts report a duplicate-address conflict right
after link-up. CSC-RES-0008 flags the defaults. The usual mitigation is a probe delay
(`ip device tracking probe delay 10`) or auto-source probing, as the release supports.

IOS-XE 16.x and later replace IPDT with Switch Integrated Security Features (SISF). A
`device-tracking policy <name>` is defined and attached per interface with
`device-tracking attach-policy <name>`. The presence of `device-tracking policy` is itself
one of the IOS-XE surface signals in section 1. Legacy `ip device tracking` lines on an
IOS-XE switch are usually migration leftovers. Check the release documentation before
advising on them.

## 5. Smart Install: `vstack`

Smart Install is a zero-touch deployment feature whose client listens on TCP 4786 and has a
long history of abuse. It is present on many IOS and early IOS-XE releases and absent from
others. `no vstack` disables the client. CSC-MGT-0010 is `critical` because an enabled client
lets an unauthenticated party change or copy the configuration. Where a release has no
Smart Install, `no vstack` is simply rejected, and the finding does not apply. Confirm with
`show vstack config` if in doubt.

## 6. `boot system` forms

| Form | Where you see it | Meaning |
|---|---|---|
| `boot system flash:c2960x-universalk9-mz.<release>.bin` | Classic IOS | Boot this image file |
| `boot system switch all flash:<image>.bin` | IOS stacks | The same, for every stack member |
| `boot system flash:packages.conf` | IOS-XE install mode | Boot the installed package set. The recommended mode on Catalyst 9000 |
| `boot system flash:cat9k_iosxe.<release>.SPA.bin` | IOS-XE bundle mode | Boot a monolithic bundle |
| `boot system tftp://...`, `ftp://...`, `http://...` | Either | Boot over the network. CSC-RES-0002 flags this |

Several `boot system` lines form an ordered fallback list (CSC-RES-0001 checks there is a
deterministic order). A network URL carrying `user:password@` has the password masked on
ingest (`url-password` class). The rest of the URL is kept. Whether the named file exists
and is an approved release is a judgment question (`judgment-checks.md` section 9).

## 7. Credential types and password encryption

The type marker before a credential survives masking, so the checks can read it.

| Marker | Meaning | Posture |
|---|---|---|
| `0` or none (on `password` forms) | Cleartext | Replace. Rotate if it was ever shared |
| `7` | Reversible obfuscation (`service password-encryption`) | Treat as cleartext. Rotate, never decode |
| `5` | MD5-based hash | Weak. Move to 8 or 9 |
| `6` | AES-encrypted, reversible with the device's master key (`password encryption aes`) | Acceptable for secrets the device must recover, such as keys it sends |
| `8` | PBKDF2-SHA-256 hash | Good |
| `9` | scrypt hash | Good. The generator's choice (`algorithm-type scrypt`) |

`enable secret` and `username ... secret` take types 5, 8 and 9. `enable password` and
`username ... password` take 0 and 7 and should be replaced (CSC-AAA-0010, CSC-AAA-0011).
Support for `algorithm-type` and types 8 and 9 depends on the release. On an older IOS
release that lacks them, say so and recommend the strongest type available plus an upgrade
plan. `service password-encryption` (CSC-AAA-0012) only hides type 0 lines as type 7. It is
a shoulder-surfing control, not encryption.

## 8. Other IOS-XE-only surface forms

`license boot level ...` (licence level at boot), `ip http secure-active-session-modules`,
`netconf-yang` and `restconf` (programmable management, checked by CSC-MGT-0012), and the
`ip ssh server algorithm encryption|mac|kex` lists (CSC-SSH-0004 to CSC-SSH-0006) are IOS-XE
forms, though some SSH algorithm commands also appear on late IOS 15.x releases. A command
the user's release rejects is a release question, not an audit error. Say so rather than
insisting.

## 9. Interface names and abbreviations

The engine canonicalises interface names for lookups and role maps, so `Gi1/0/1`,
`Gig1/0/1` and `GigabitEthernet1/0/1` are the same port. Evidence lines still show the text
exactly as the user wrote it. Longest prefix wins, so `Twe` is `TwentyFiveGigE` while `Tw` is
`TwoGigabitEthernet`, and `Te` is `TenGigabitEthernet` while `Tu` is `Tunnel`.

Numbering differs by platform: fixed classic IOS switches use `Gi0/1`, while stacks and
IOS-XE Catalyst 9000 use `<member>/<module>/<port>` such as `Gi1/0/1` or `Te1/1/1`. IOS-XE
Catalyst 9000 also shows `TwoGigabitEthernet` (mGig ports) and `AppGigabitEthernet` (the
application-hosting port). Leave `AppGigabitEthernet` alone unless the user uses application
hosting.

## 10. Implicit defaults, and what "absent" means

`show running-config` omits most commands that are at their default. So a missing line does
not always mean a missing feature: `cdp run`, for example, is on by default and never shown.
The engine therefore resolves absence through a per-platform defaults table. A finding whose
verdict came from a default rather than a visible line says so. Explain it as "not
configured, so the platform default applies, and that default is X".

The same applies to terminal lines. Both platforms are assumed to have vty lines `0` to `15`.
If the file shows only `line vty 0 4`, lines `5` to `15` are evaluated at their defaults, and
a `CSC-SELF-0006` note says so. The usual cause of a vty finding on a "hardened" switch is
exactly this: `0 4` was hardened and `5 15` was never configured. A role map's
`vty_universe` changes the assumed range.

## 11. Getting a clean capture

- Ask for `show running-config` captured with `terminal length 0` first, so `--More--`
  pager breaks do not appear. The engine strips them anyway, noting `pager artefact`.
- Prefer the file itself (a saved capture, a backup from the NMS, or an archive copy) over a
  paste, so no credential is typed into the conversation.
- `show running-config all` includes every default and is much longer. It is not needed.
  `show startup-config` audits what will load at the next reload, which can differ from what
  is running.
- An authored configuration with no indentation is handled (the engine follows `exit`
  lines and notes `nesting=exit-driven`), but a real capture is more reliable.
