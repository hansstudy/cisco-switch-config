# Fixture attribution

Per-file source, licence, and what was changed, for every file under `tests/fixtures/`.
This file is maintained independently from `docs/content-provenance.md` and `NOTICE`
(which are compiled separately) and is reconciled against what was actually committed
here.

## `synthetic/**` — hand-authored for this project, Apache-2.0 with the rest of the repository

Every file in this directory is written from scratch, from command-reference syntax, never
copied or adapted from any CIS Benchmark, any GPL tool (`ccat`, `cisco-config-auditor`,
`nipper-ng`, `ciscoconfparse`/`ciscoconfparse2`), or any Cisco documentation example (such
examples are used only as syntax reference, never copied verbatim). All addressing is RFC
5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) or RFC 1918; all names use
`example.invalid`. Every secret-shaped value uses the frozen canary vocabulary described
below (see "Canary-vocabulary and scanner-allowlist note") or an obvious `CANARY...`
derivative of it.

| File | What it is for |
|---|---|
| `minimal.cfg` | Smallest possible parseable input: hostname, one interface, `end` |
| `hardened-reference.cfg` | Catalyst 9300 / IOS-XE 17.9, hardened against the full catalogue; AC6's zero-`critical`/zero-`high` case |
| `deliberately-bad.cfg` | Catalyst-class access switch with the hardening controls deliberately absent or wrong; AC6's >= 25-findings, both-categories case |
| `campus-access-multivlan.cfg` | 48-port access switch, mixed hardening posture, data/voice/mgmt VLANs — a realistic middle case |
| `ios15-catalyst.cfg` | Classic IOS 15.2(4)E dialect, Catalyst 2960-X — exercises the IOS (not IOS-XE) surface forms of the dialect table |
| `canary-secrets.cfg` | AC15's primary fixture: one canary in real context for every secret-bearing construct the masker recognises, one canary in every placement mode the masker handles, the default-deny/`reference`/`no-value` three-way split, and the placeholder exemption pair |
| `canary-secrets-rotated.cfg` | Mechanically derived from `canary-secrets.cfg` by appending `ROT` to every secret-shaped value (script-generated, not hand-edited, so every non-secret token — mode structure, ACL numbers, addresses, comments, the fixture's own hostname — is byte-identical). Proves `parse_pair()`'s `changed: true` without either file holding a "real" secret |
| `canary-malformed.cfg` | Deliberately unparseable: a `--More--` pager artefact with real backspace bytes spliced into a canary-bearing `snmp-server community` line; an unclassifiable `username` line; an unterminated banner (never closed) whose body swallows a canary and a truncated `crypto pki certificate chain` block. Exercises the "never crash, never leak, note the class not the content" failure policy in one file |
| `canary-flat-noexit.cfg` | A wholly unindented file (one `exit`, one mode-opening head) that must trigger exit-driven nesting, with global-mode secret-bearing lines after the `exit` that must resolve to `mode_path=()`, not stay nested under the preceding block |
| `subject-coverage.cfg` | One real line for every catalogue `subject` token-prefix no other fixture exercises (`speed`, `duplex`, `cdp run`, `netconf-yang`, `restconf`, `crypto key generate`, `login on-failure`, `login on-success`), so `tests/test_contract_reconciliation.py` can detect a rotted subject list. No secrets |
| `traps/trap-a-banners.cfg` | Both banner delimiter forms (single-line closing on the same line; multi-line), `enable password` inside a banner body, a `0x03` delimiter variant, and one properly-unterminated banner |
| `traps/trap-b-blobs.cfg` | `crypto pki certificate chain` through `quit`, a truncated chain, `crypto key pubkey-chain rsa` `key-string` |
| `traps/trap-c-ranges.cfg` | `interface range` dash-list and comma-list forms (with and without spacing around `-`), `interface range macro`, a range member that also has its own standalone block |
| `traps/trap-d-defaults.cfg` | Absent `exec-timeout`, absent `cdp run`, absent explicit `switchport mode` — the implicit-defaults path |
| `traps/trap-e-dialect.cfg` | `portfast edge bpduguard default` on IOS-XE 17.9 — the dialect table's positive form |
| `traps/trap-f-lines.cfg` | `line vty 0 4` hardened, `line vty 5 15` left at defaults — the all-lines/`line_ranges()` universe |
| `traps/trap-g-refs.cfg` | `access-class` naming an undefined ACL, an SNMP community ACL naming an undefined ACL, an NTP key with no matching `trusted-key`, a native VLAN equal to an access VLAN in use |
| `traps/trap-h-snmpuser.cfg` | `snmp-server group ... v3 priv` present, no `snmp-server user` line at all — the "cannot be audited from a running-config" case |
| `traps/trap-i-paste.cfg` | `Building configuration...`, `--More--` with backspaces, prompt echo, CRLF line endings, trailing `end`, a UTF-8 BOM |

## `third-party/**` — verbatim imports, each carrying its own upstream licence

`ciscoconfparse`/`ciscoconfparse2` sample configs are **GPL-3.0 and were not used**, not even
for wording inspiration, per the clean-room rule. CIS Benchmark text was not used in any
form.

### `third-party/batfish/`

- Repository: <https://github.com/batfish/batfish> — Apache-2.0 (`LICENSE` in this directory)
- Commit pinned at retrieval: `5e8ecd02b080467470509710a7fe4be50b72bd46`, retrieved 2026-09-24
- Base path: `projects/batfish/src/test/resources/org/batfish/grammar/cisco/testconfigs/`
- Files (embedded verbatim, byte-for-byte, no changes): `ios_banner.cfg` (from `ios_banner`),
  `ios-line.cfg` (from `ios-line`), `ios-aaa-group-server.cfg` (from `ios-aaa-group-server`),
  `ios-crypto.cfg` (from `ios-crypto`), `ios-ntp.cfg` (from `ios-ntp`),
  `ios-snmp-community-string.cfg` (from `ios-snmp-community-string`)
- See `third-party/batfish/SOURCE.md` for the full note.

### `third-party/napalm/`

- Repository: <https://github.com/napalm-automation/napalm> — Apache-2.0 (`LICENSE` in this
  directory)
- Commit pinned at retrieval: `d98ddfe746aff94bca41f51e1604266d4e181a7e`, retrieved 2026-09-24
- Upstream path: `test/ios/mocked_data/test_get_config/normal/show_running_config.txt`
- File: `show_running_config.txt`, embedded verbatim, byte-for-byte, no changes. A full
  IOS-XE CSR1000v `show running-config` capture from NAPALM's own test suite; retains that
  project's own placeholder lab credentials (`enable password cisco`).
- See `third-party/napalm/SOURCE.md` for the full note.

### `third-party/ntc-templates/`

- Repository: <https://github.com/networktocode/ntc-templates> — Apache-2.0 (`LICENSE` in
  this directory; trust the LICENSE file text over GitHub's repo-level "Other/NOASSERTION"
  API classification, which does not reflect the actual license terms)
- Commit pinned at retrieval: `d86d09fa105ee2a432795022e7df04737c65dd28`, retrieved 2026-09-24
- Upstream path:
  `tests/cisco_ios/show_crypto_pki_certificates/cisco_ios_show_crypto_pki_certificates_1.raw`
- File: `show_crypto_pki_certificates.raw`, embedded verbatim, byte-for-byte, no changes.
  `show` command **operational** output (not config-mode text), used only for PKI
  certificate/issuer/subject field shapes; already fully templated by the upstream project
  (`cn=CommonName`, etc).
- See `third-party/ntc-templates/SOURCE.md` for the full note.

## `leak-template.tmpl`

Hand-authored for this project. Used **only** by `tests/test_masking_invariant.py` assertion
13(b) to prove the egress guard fails the build on a template that leaks a real-shaped secret
in a placeholder position. It is never wired into `gen_baseline.py`'s real
`data/baseline/*.tmpl` set.

## Canary-vocabulary and scanner-allowlist note

Every secret-shaped string in this directory is drawn from, or is an obvious derivative of,
the frozen canary vocabulary described above, and is covered by the repository's
`.gitleaks.toml` and `.github/secret_scanning.yml` path exclusions (scoped to
`tests/fixtures/**` and `evals/**`) so the first push raises no false alert.

## `CANARY` vs `LAB`

`CANARY` is reserved for secret-shaped *values* the masker must redact, everywhere under
`tests/fixtures/`, not only in the three files the oracle reads. `test_masking_invariant.py`'s
independent oracle collects every `CANARY...` string appearing in `canary-secrets.cfg`,
`canary-secrets-rotated.cfg`, `canary-malformed.cfg` and `canary-flat-noexit.cfg`, and asserts
none of them survives to any output; it does not, and must not, know which construct rows the
masker recognises (an oracle that reads the masking table stops being independent). That
means every *non-secret identifier* — a hostname, a `call-home profile` name, an EEM applet
name, an EIGRP process/VRF name, an RSA `named-key` name, a WLAN profile/SSID, or descriptive
prose inside a banner body that carries no trigger keyword before it — must NOT start with
`CANARY`, because those are correctly left in clear by design and a `CANARY`-prefixed
identifier would read as a false "leak" the moment another test (e.g. the differ) echoes it
back, or would simply be misleading to a reader who does not re-derive which construct rows
apply. Such identifiers use
the disjoint `LAB-` prefix instead: `LAB-SW01`, `LAB-PROFILE`, `LAB-APPLET`, `LAB-EIGRP-VRF`,
`LAB-NAMEDKEY`, `LAB-WLAN`, `LAB-WLAN-SSID`, `LAB-MALFORMED-01`, `LAB-FLAT-NOEXIT-01` (all in
the oracle-collected files), and `traps/trap-a-banners.cfg`'s two banner-body markers
(`LAB-TRAPA-0X03-01`, `LAB-TRAPA-UNTERM-01` — plain prose, no trigger keyword precedes either,
so nothing masks them) and `traps/trap-b-blobs.cfg`'s `LAB-TRAPB-NAMEDKEY` (an RSA key *name*,
not its body). The convention holds even outside the oracle's literal file list, so a reader
sweeping any fixture for `CANARY` never has to guess whether one particular instance is
special-cased. `canary-secrets-rotated.cfg` keeps every `LAB-...` identifier byte-identical to
the unrotated file (only `CANARY...` secret values are rotated), which is what lets the differ
align the two configs by structure and report identifiers as unchanged.
