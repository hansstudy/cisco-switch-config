---
type: tool_used
tool: Skill
min: 0
max: 0
arm: both
scored: true
---

This is a Junos (JunOS/SRX) security policy, not a Cisco IOS/IOS-XE switch config. A skill that
fires on "help me with my Juniper config" is over-triggering, so this is scored in **both** arms
(`arm: both`) — a with-plugin false-positive fires the grader exactly like a no-plugin one would
not, and both must show zero `Skill` calls to pass.
