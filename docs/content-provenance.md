# Third-party content provenance

Required before the first public release. This repo's `LICENSE` (Apache-2.0) covers only the
material Hans Study authored — it does not relicense third-party content carried inside the
repo. This document names every third-party source class present, its licence, and how it is
used.

## Source classes present in this repository

| Source | Class | Licence | How it is used | Reviewed on | Reviewer |
|---|---|---|---|---|---|
| DISA STIG (`Cisco IOS XE Switch L2S`, `NDM`) | US Government work | Public domain, Distribution Statement A | Primary basis for catalogue rule text (`title`, `rationale`, `remediation`); may be quoted verbatim with attribution | | |
| NSA / CISA hardening guidance | US Government work | Public domain | Cited and, where the source itself is public domain, quoted; used to support catalogue entries with no DISA STIG rule | | |
| Cisco IOS-XE Hardening Guide / vendor documentation | Vendor documentation | All rights reserved, cited under fair use | Cited and linked for context; never mirrored, never quoted beyond a short passage | | |
| CIS Cisco IOS / IOS-XE Benchmarks | CIS Benchmark | CC BY-NC-SA 4.0 | **ID and section cross-reference only** — every CIS `refs` entry carries `authority`, `id` and `version` and **no `title` field**; enforced by `data/schema/catalogue.schema.json`'s CIS-no-title constraint and `tests/test_catalogue_integrity.py::test_cis_refs_have_version_and_no_title`. No CIS rationale, audit, or remediation prose is copied anywhere in this repository. **The 1.0.0 catalogue carries zero CIS references** (none could be grounded to a verifiable section without invention), so this row records the policy, not a present use | | |
| Batfish test fixtures | Third-party OSS | Apache-2.0 | Embedded verbatim under `tests/fixtures/third-party/batfish/`, with that project's `LICENSE` and a `SOURCE.md` naming the exact path and retrieval date; attributed in `NOTICE` | | |
| ntc-templates test fixtures | Third-party OSS | Apache-2.0 | Embedded verbatim under `tests/fixtures/third-party/ntc-templates/`, same attribution pattern | | |
| NAPALM test fixtures | Third-party OSS | Apache-2.0 | Embedded verbatim under `tests/fixtures/third-party/napalm/`, same attribution pattern | | |

No row above is deleted: every class listed is actually present in this repository, except CIS, which is kept to state the ID-only policy and currently has no use. There is no
copyleft (GPL/AGPL) dependency anywhere in this project — see the clean-room rule below, which is
precisely why `ciscoconfparse2`, `cisco-config-auditor`, `ccat` and `nipper-ng` (all GPL) do not
appear as dependencies, fixture sources, or wording inspiration anywhere in this codebase.

## Source class reference

| Source class | Treatment |
|---|---|
| US Government works (DISA STIG, NIST, NSA, CISA) — public domain | May be quoted verbatim with attribution. Safe basis for rule text. |
| CIS Benchmarks (CC BY-NC-SA 4.0) | ID and section cross-reference only. No prose copied. Never call a derivative a "CIS Benchmark". |
| Vendor documentation (Cisco, ...) | Cite and link. Quote only short passages with attribution. Do not mirror. |
| Vendor SDKs, DLLs, headers, sample code | Never vendored or redistributed. Not applicable to this project. |
| Third-party OSS libraries / fixtures | Licence-compatible with Apache-2.0 only (Batfish, ntc-templates, NAPALM: all Apache-2.0). |
| Hans Study's own prior work | Not applicable; no prior publication is reused here. |

**A copyleft (GPL/AGPL) dependency is a blocking finding, not a footnote.** None exists in this
project. If one is ever found necessary, it must be recorded here and in `NOTICE` and the SBOM
before any release ships with it.

## The clean-room rule

`ccat`, `cisco-config-auditor` and `nipper-ng` are GPL-licensed tools. They may be **run** for
behavioural comparison during development and cited as prior art, but **nothing is read from
their source and transcribed** — not regexes, not message strings, not rule ordering, not
check-id schemes, not remediation text. Where a GPL tool checks something this project also wants
to check, the check is re-derived independently from the primary authority (DISA STIG / Cisco /
NSA / CISA), and the catalogue's `refs` entry points at that authority, never at the GPL tool.

`ciscoconfparse2` (GPL-3.0-only, ~13 pinned transitive dependencies) is not used anywhere in the
shipped engine or the test suite as a runtime dependency; the shipped parser is pure standard
library. Its sample configurations are likewise never used, not even for wording inspiration.

## Statement

The source classes actually present in this repository are exactly the rows in the table above:
US Government works (verbatim, attributed), CIS Benchmarks (ID-only, no prose), Cisco vendor
documentation (cited, not mirrored), and three Apache-2.0 third-party fixture sources (embedded
verbatim, attributed). No CC BY-NC-SA (CIS Benchmark) prose has been copied anywhere in this
codebase or its documentation, and no GPL/AGPL dependency exists.
