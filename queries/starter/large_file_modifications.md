---
tags:
  - ATTACK/Impact
  - Telemetry/Sysmon
  - Surface/File
  - Surface/Process
---
Purpose: Detects high-volume file write activity potentially associated with ransomware or bulk data manipulation.
```
index=sysmon EventCode=11 earliest=-1h
| stats count by host Image User
| where count > 100
| sort - count
```
