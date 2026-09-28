---
allowed_tools: ["Read", "Glob", "Grep", "Skill"]
---

Here is the old config:

```
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
 spanning-tree bpduguard enable
!
snmp-server community CANARY-COMMUNITY-01 RO
```

Here is the new config:

```
interface GigabitEthernet1/0/5
 switchport mode access
 switchport access vlan 20
 spanning-tree portfast
!
snmp-server community CANARY-COMMUNITY-03 RO
```

What changed and does it matter?
