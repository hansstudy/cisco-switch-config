# Catalogue sources and licensing posture

This catalogue draws on five authority families. Every check's `refs` array names the exact
document and, where the source defines one, the exact rule id — never a paraphrase of the
family, and never a copy of another tool's check text.

## What is reproduced verbatim (US Government works)

**DISA STIG** rule text (`CISC-L2-*`, `CISC-ND-*`) is a US Government work distributed under
Distribution Statement A (public domain, unlimited distribution). Rule text may be embedded
verbatim; attribution is courtesy, not a licence condition. This catalogue does not embed
STIG rule prose — only the STIG-ID and benchmark version as a citation — but verbatim
reproduction would be permitted if a future revision needed it.

**NSA and CISA guidance** (Cybersecurity Technical Reports, hardening guides, alerts) are
likewise US Government works distributed without licence restriction.

## What is ID-only (CIS)

CIS Benchmark content is licensed: reproducing rationale, audit or remediation prose from a
CIS Benchmark outside SecureSuite membership is prohibited, but citing a control **ID** as a
cross-reference alongside independently written check text is the accepted pattern (CIS,
*Terms of Use for Non-Member CIS Products*). This build does not carry any CIS cross-
references: none could be grounded in a verifiable section number without access to the
current CIS Benchmark for Cisco IOS-XE, so none were fabricated. `catalogue.schema.json`
still enforces the constraint (`authority: CIS` requires `version` and forbids `title`) so a
future revision that does add CIS references cannot regress it silently.

## What is independently written (Cisco guidance and every rationale)

Cisco's own hardening guides (*Guide to Harden Cisco IOS Devices*, the *IOS XE Software
Hardening Guide*) and Cisco's Catalyst best-practice and high-availability design guides are
vendor documentation, cited and linked rather than mirrored. **Every `rationale` field in
this catalogue is written independently** — describing what the setting does, what goes
wrong without it, and on what kind of port or plane it matters — and is never transcribed
from any of the above sources or from a GPL tool.

## The clean-room rule

`ccat`, `cisco-config-auditor` and `nipper-ng` are GPL-licensed. They were not read as part of
authoring this catalogue. Nothing was transcribed from their source: not a regex, not a
message string, not a check-id scheme, not remediation text. Where this catalogue checks
something a GPL tool also checks, the check was derived from the primary authority listed in
its `refs`, never from the tool.

## Authority id conventions used by non-STIG refs

STIG refs cite the real `STIG-ID` (`CISC-L2-xxxxxx`, `CISC-ND-xxxxxx`) and benchmark version
(`V2R5` for the IOS-XE Switch L2S STIG, `V3R5` for the IOS-XE Switch NDM STIG). Cisco,
NSA and CISA documents do not use a comparable formal rule-id scheme, so their `refs[].id` is
a short, stable slug for the specific document (for example
`guide-to-harden-cisco-ios-devices`, `ctr-network-infrastructure-security-guide`), paired
with the document's real, resolvable URL in `refs[].url`. No numeric id was invented to make
a non-STIG reference look like a STIG rule id.
