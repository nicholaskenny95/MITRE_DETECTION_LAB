---
tags:
  - ATTACK/PrivilegeEscalation
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/Identity
---
Purpose: Highlights unexpectedly elevated processes.
```
index=sysmon EventCode=1 earliest=-1h
| search IntegrityLevel="High" OR IntegrityLevel="System"
| table _time host Image ParentImage CommandLine User IntegrityLevel
```
