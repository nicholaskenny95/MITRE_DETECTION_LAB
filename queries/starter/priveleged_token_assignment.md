---
tags:
  - ATTACK/PrivilegeEscalation
  - Telemetry/WindowsEvent
  - Surface/Identity
  - Surface/Process
---
Purpose: Detects users receiving elevated privileges (high-fidelity escalation signal).
```
index=windows EventCode=4672 earliest=-1h
| table _time host SubjectUserName Privileges
```