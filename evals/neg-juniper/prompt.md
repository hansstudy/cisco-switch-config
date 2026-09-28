---
allowed_tools: ["Read", "Glob", "Grep", "Skill"]
---

Help me fix this Juniper SRX security policy:

```
security {
    policies {
        from-zone trust to-zone untrust {
            policy allow-all {
                match {
                    source-address any;
                    destination-address any;
                    application any;
                }
                then {
                    permit;
                }
            }
        }
    }
}
```
