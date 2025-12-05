---
tags:
  - ATTACK/PrivilegeEscalation
  - Telemetry/Sysmon
  - Surface/Registry
  - Surface/Process
---
Purpose: Detects service misconfiguration attempts used for escalation.
```
index=sysmon EventCode=13 earliest=-1h
| search registry_key_path="*\Services\*" AND Details="*ImagePath*"
| table _time host Image registry_key_path Details User
```
