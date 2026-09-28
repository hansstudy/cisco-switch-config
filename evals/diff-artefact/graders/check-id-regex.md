---
type: regex
target: last_message
pattern: "CSC-[A-Z]{2,5}-\\d{4}"
scored: true
---

`diff-artefact` keeps the `CSC-` id regex, unlike `generate-explicit`/`explain-oblique`: naming
which specific hardening check a change crosses (here, the removed `spanning-tree bpduguard
enable`, which BPDU Guard checks such as `CSC-STP-0001` cover) is exactly what the diff
capability claims to do.
