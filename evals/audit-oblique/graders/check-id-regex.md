---
type: regex
target: last_message
pattern: "CSC-[A-Z]{2,5}-\\d{4}"
scored: true
---

The no-plugin arm has no catalogue and cannot produce a `CSC-<FAMILY>-<NNNN>` id; the
with-plugin arm should.
