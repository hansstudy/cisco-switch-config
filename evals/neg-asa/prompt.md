---
allowed_tools: ["Read", "Glob", "Grep", "Skill"]
---

Review this Cisco ASA access-list for shadowed rules:

```
access-list OUTSIDE_IN extended permit tcp any any eq 443
access-list OUTSIDE_IN extended permit tcp any host 10.0.0.5 eq 443
access-list OUTSIDE_IN extended deny ip any any
```
