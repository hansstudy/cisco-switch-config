# Audit workflow

How to run a full audit with `scripts/audit_config.py`, read what it prints, correct its
interface-role inference, and use it in CI. The credential rules in `SKILL.md` apply to
everything here.

## Contents

1. The procedure, end to end
2. Flags and when to use them
3. Severity
4. Confidence, and how a role map changes it
5. Evidence, line numbers and redaction tokens
6. Profiles: `campus` and `stig`
7. Interface roles and `--role-map`
8. Engine notes (`CSC-SELF-*`)
9. Exit codes, operationally
10. JSON output
11. SARIF and CI
12. Prioritising findings for the operator

## 1. The procedure, end to end

1. Run the audit on the user's file (or stdin, `-`) with `--format table`. Do not read the
   configuration yourself first.
2. Check the footer. It names the platform and how it was inferred (`inferred-version`,
   `inferred-image`, `inferred-surface`, `default`, or `given`). If the platform is wrong,
   re-run with `--platform`, because a wrong platform selects the wrong defaults and dialect
   tables and produces false positives. `default` means nothing in the file identified the
   platform, so ask the user which it is.
3. Check the notes (section 8) for anything that changes how to read the results: an
   unterminated block, a flat paste, or assumed vty lines.
4. Look at `heuristic` findings. Each rests on an inferred interface role. If the roles look
   wrong (for example an uplink treated as an access port), build a role map (section 7) and
   re-run.
5. Answer `manual-review` findings with the user, using `judgment-checks.md`.
6. Report and prioritise (section 12).

## 2. Flags and when to use them

| Flag | Default | Use it when |
|---|---|---|
| `--format table\|json\|sarif` | `table` | `table` in conversation; `json` to compute over findings; `sarif` for CI and code scanning |
| `--platform ios\|iosxe` | inferred | The inferred platform is wrong or `default` |
| `--profile campus\|stig` | `campus` | The user must meet the DISA STIG profile |
| `--severity-min info\|low\|medium\|high\|critical` | `info` | The user wants only the serious items |
| `--category security\|reliability\|all` | `all` | The user asked about one concern |
| `--role-map <path>` | none | Role inference is wrong for some interfaces |
| `--fail-on high\|critical\|none` | `none` | A pipeline must fail on serious findings |
| `--no-notes` | notes shown | Hiding engine notes (keep them when diagnosing) |
| `--out <path>` | stdout | The user named a file for the report. It is the only file any script writes |

`-` as the input path reads stdin.

## 3. Severity

`critical`, `high`, `medium`, `low`, `info`. Severity is fixed per check in the catalogue.
It is not a risk score for this network: a `medium` on a switch facing untrusted users can
matter more than a `high` on a lab switch. That weighting is your job (section 12).
Findings are sorted by severity, then check id, then line.

## 4. Confidence, and how a role map changes it

| Confidence | Meaning | How to present it |
|---|---|---|
| `deterministic` | Decided from the configuration text alone | As a fact about the configuration |
| `heuristic` | Depends on an inferred interface role or a keyword judgment | As likely, naming the role or signal it assumed |
| `manual-review` | Cannot be decided from a running-config; the finding carries extracted evidence and a question | As an open question for the user (`judgment-checks.md`) |

Each finding carries two fields. `catalogue_confidence` is the worst case, without a role
map. `confidence` is as evaluated on this run. A `heuristic` finding on an interface whose
role came from `--role-map` is promoted to `deterministic`, because the role is then a fact
the user supplied. That is the only promotion.

## 5. Evidence, line numbers and redaction tokens

- **Line numbers** refer to the user's own file as submitted, so they match what the user
  sees in their editor.
- **Anchors.** A finding's evidence is anchored to one line (`line`), to an `interface range`
  line when the port was configured through a range (`range-line`: the finding applies to a
  member of that range), or it is an **absence** finding (`absent`): no line exists because
  the problem is that something is missing. In the table an absence finding has no line
  number. In SARIF it anchors at line 1 and its message begins `Not configured: `.
- **Evidence text is masked.** A redaction token reads `[REDACTED <class>, <N> chars]`, or
  `[REDACTED unknown-secret, span]` for the default-deny class. Quote tokens as they are. Name
  the class ("an SNMP community", "a local user secret"), never a value. Classes ending
  `-weak` (for example `snmp-community-weak`) mean the value matched a known-default list.
  Only that verdict is carried, never the value.
- **Remediation** (`fix:`) lines are paste-ready, with interface, VLAN and ACL names already
  filled in. Secret slots are always `<REPLACE-ME:...>` placeholders for the operator to fill
  on the device. `<TODO:name>` in a fix line means the rule did not supply that value. Tell
  the user to fill it from their own design, and see the `CSC-SELF-0002` note.

## 6. Profiles: `campus` and `stig`

`--profile` selects which catalogue checks apply. Each catalogue entry lists the profiles it
belongs to, and may give a different severity per profile. Use `stig` when the user must
meet the DISA STIG profile, and `campus` otherwise. The JSON `run.checks_evaluated` count
shows how many checks ran under the chosen profile. Compare the two runs when the user asks
what the STIG profile adds. Neither profile is a compliance attestation.

## 7. Interface roles and `--role-map`

Roles decide which interface checks apply (BPDU Guard on access ports, DHCP snooping trust
on uplinks, and so on). The vocabulary is closed: `access`, `voice-access`, `trunk`,
`uplink`, `management`, `routed`, `unused`, `unknown`.

Inference, first match wins, per interface:

1. The role map names the interface.
2. `shutdown`, with no `channel-group` and no `switchport mode trunk`: `unused`.
3. An SVI with `ip address` whose VLAN is the role map's `management_vlan`, or whose
   description contains `mgmt`, `management` or `oob`: `management`.
4. `no switchport`, or `ip address` on a physical port: `routed`.
5. Trunking (`switchport mode trunk`, `switchport trunk encapsulation` or
   `switchport mode dynamic desirable`) together with a `channel-group`, or a description
   containing `uplink`, `core`, `dist`, `distribution`, `agg`, `aggregation`, `wan`, or
   `to` followed by `-`, `_` or a space: `uplink`.
6. Trunking alone: `trunk`.
7. `switchport voice vlan`: `voice-access`.
8. `switchport mode access` or `switchport access vlan`: `access`.
9. Otherwise: `unknown`.

When the user tells you a port's real role, or the descriptions are uninformative, write a
role map. It is JSON (never YAML), and the user decides where it is saved:

```json
{
  "version": 1,
  "roles":  { "Gi1/0/1": "uplink", "GigabitEthernet1/0/2": "access" },
  "ranges": { "Gi1/0/3 - 24": "access", "Te1/1/1 - 2": "uplink" },
  "management_vlan": 99,
  "vty_universe": [0, 15]
}
```

- `version` is required and must be `1`.
- Keys may use any standard abbreviation (`Gi`, `Te`, `Po`, ...). They are canonicalised
  before matching. `ranges` keys use the `interface range` grammar.
- A key naming an interface the configuration does not contain is ignored and counted in the
  `CSC-SELF-0008` note. A role outside the vocabulary is exit 2, naming the key and the value.
- `vty_universe` overrides how many vty lines the platform is assumed to have. The default
  is `0`-`15`.

## 8. Engine notes (`CSC-SELF-*`)

Notes are diagnostics from the engine, not catalogue checks. They are rendered as `info`,
never count toward `--fail-on`, and never carry configuration text.

| Code | Emitted when | What to do |
|---|---|---|
| `CSC-SELF-0001` | Every run: the platform and its source | Confirm the platform (section 1) |
| `CSC-SELF-0002` | A remediation line needed a value the rule did not supply (`<TODO:name>`) | Fill it from the user's design; mention it as a skill defect if it recurs |
| `CSC-SELF-0003` | A paste artefact was stripped (`build-banner`, `size-banner`, `pager artefact`, `prompt echo`, `trailing end`, `bom`) | Usually nothing. A `pager artefact` means the paste had `--More--` breaks; suggest `terminal length 0` before the next capture |
| `CSC-SELF-0004` | A line could not be classified, or a rule raised an error | Results for that area may be incomplete; say so. A rule error is a skill defect |
| `CSC-SELF-0005` | A banner, macro or certificate/key block was not closed before end of file | The file is probably truncated. Ask for a complete capture |
| `CSC-SELF-0006` | vty/con/aux lines were assumed at platform defaults because the file does not show them | Findings on those lines describe defaults. Confirm with the user |
| `CSC-SELF-0007` | An unfilled `<REPLACE-ME:...>` placeholder is present | Expected in a generated baseline. List what must be filled on the device |
| `CSC-SELF-0008` | A role map was applied | Check the count matches what the user intended |
| `CSC-SELF-0009` | Every run: `nesting=indent` or `nesting=exit-driven` | `exit-driven` means a flat, unindented paste. Results are valid but worth a sanity check |

## 9. Exit codes, operationally

| Code | Meaning | Operationally |
|---|---|---|
| 0 | Ran; nothing at or above `--fail-on` | With the default `--fail-on none`, every successful run is 0 |
| 1 | Ran; findings at or above `--fail-on` | Only when `--fail-on` is set. A CI gate, not an error |
| 2 | Input not usable: empty, not a Cisco configuration, invalid role map or spec, usage error | For a configuration: it had fewer than three real lines or too few recognisable IOS commands. Ask for the full `show running-config` as a file. For a role map or spec: fix the key the message names |
| 3 | Build not usable: rule package or catalogue missing | The installation is incomplete. Reinstall the skill. Never substitute a hand audit presented as a result |
| 4 | Internal error | A defect. Report it with the command and exit code. The message never includes a traceback, by design |
| 5 | Egress guard tripped | A defect: masking missed a credential and output was suppressed to stop it being printed. Report it. Do not re-run with other flags to get past it, and do not paste or reconstruct any partial output |

## 10. JSON output

`--format json` prints one object: `schema_version`; `tool` (name, `skill_version`,
`catalogue_version`); `run` (platform, platform source, profile, filters, whether a role map
was applied, `checks_evaluated`); `counts` by severity plus `total`; `findings[]`; and
`notes[]`. Each finding carries `check_id`, `severity`, `category`, `confidence`,
`catalogue_confidence`, `title`, `rationale`, `evidence` (`line_no`, `source_line_no`,
`text`, `masked`, `redactions`, `anchor`), `remediation` (list of lines), `refs`, `params`,
and the platform, profile and version stamps. Use it to group findings by interface
(`params`) or to count by family. Present results in prose or a short table, not as raw
JSON.

## 11. SARIF and CI

`--format sarif` emits SARIF 2.1.0 for GitHub code scanning and similar systems. The tool
driver carries the skill version (`semanticVersion`) and catalogue version (`version`). Each
result carries the `CSC-*` id, a level (`critical`/`high` are `error`, `medium`/`low` are
`warning`, `info` is `note`), the masked evidence as its snippet, and a stable fingerprint
computed over the masked text. Every snippet is masked, which matters because SARIF is the
format most likely to reach a third-party system.

A typical CI step (the user chooses the paths):

```bash
python scripts/audit_config.py configs/sw01.cfg --format sarif \
    --fail-on high --out reports/sw01.sarif
```

Exit 1 fails the job on a `high` or `critical` finding. Exits 2 to 5 should also fail it,
since each means the audit did not complete. Store configurations in CI only as the user's
own policy on credentials allows. The tool never needs them unmasked in a report.

## 12. Prioritising findings for the operator

The script ranks by severity. You rank by consequence for this network:

1. **Exposure first.** Anything that lets an unauthenticated or remote party in or out:
   non-SSH vty transport, Smart Install (`vstack`), read-write or default SNMP communities,
   cleartext or type 7 credentials (recommend rotation, rule 5), unrestricted management
   access.
2. **Then outage risk.** Spanning-tree guards on user-facing ports, BPDU filtering, DTP left
   dynamic, errdisable recovery, a single uplink or single NTP or syslog source.
3. **Then visibility.** Logging, timestamps, NTP authentication, configuration archive.
4. **Group fixes that touch the same block** (one `interface range`, one `line vty`) so the
   operator makes one change, and flag fixes that can cut off management access. Examples:
   applying an `access-class` before the ACL permits the admin's own network, or
   `transport input ssh` before SSH keys exist (CSC-SSH-0002). Tell the user to keep a
   console session or a scheduled `reload in` as a fallback.
5. Say plainly what the audit cannot see. It covers one device's configuration text, not
   topology, reachability, the installed image, or runtime state.
