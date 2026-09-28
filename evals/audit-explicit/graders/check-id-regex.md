---
type: regex
target: last_message
pattern: "CSC-[A-Z]{2,5}-\\d{4}"
scored: true
---

The catalogue check-id pattern. The no-plugin arm has no catalogue and cannot produce one; the
with-plugin arm should cite at least one finding by its `CSC-<FAMILY>-<NNNN>` id.
