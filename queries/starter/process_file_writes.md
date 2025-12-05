---
tags:
  - ATTACK/Collection
  - Telemetry/Sysmon
  - Surface/File
  - Surface/Process
---
Purpose: Identifies processes generating unusually high numbers of file writes, indicating staging, encryption, or mass modification.
```
index=sysmon EventCode=11 earliest=-1h
| stats count by host, Image, User
| where count > 50
| sort - count
```
