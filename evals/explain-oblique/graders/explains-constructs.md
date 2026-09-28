---
type: llm
scored: true
---

Does the answer correctly name and explain the specific IOS constructs in the pasted fragment —
trunk mode, the allowed-VLAN list, the native VLAN and why a native VLAN of 999 (off the allowed
list, non-default) is a deliberate hardening choice, `spanning-tree portfast trunk` on a trunk
port carrying an EtherChannel member, and `channel-group 1 mode active` (LACP)? Score 1 if the
answer engages with these specific constructs and what each one does; score 0 if the answer is
generic, wrong, or only paraphrases the config lines without explaining their effect.

This is an `llm` rubric rather than a `CSC-` id regex on purpose: explaining a config section
correctly does not require citing a catalogue check id, so an id-regex grader would score a
genuinely working "explain" capability under the 0.8 threshold.
