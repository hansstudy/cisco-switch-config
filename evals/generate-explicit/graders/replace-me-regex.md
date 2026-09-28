---
type: regex
target: last_message
pattern: "<REPLACE-ME:"
scored: true
---

`generate-explicit` cannot naturally emit a `CSC-` check id (there is nothing to audit yet), so
its scored grader is this skill's own placeholder vocabulary instead. A baseline generator has no
reason to invent secret values, and a competent unaided model has no reason to produce this exact
token either — so its presence is a strong with-plugin-only signal.
