---
allowed_tools: ["Read", "Glob", "Grep", "Skill"]
---

What does this section of my Catalyst config actually do?

```
interface GigabitEthernet1/0/24
 switchport mode trunk
 switchport trunk allowed vlan 10,20,99
 switchport trunk native vlan 999
 spanning-tree portfast trunk
 channel-group 1 mode active
```
