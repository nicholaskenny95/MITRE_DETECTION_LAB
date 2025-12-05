---
tags:
  - ATTACK/Persistence
  - Telemetry/WindowsEvent
  - Surface/Process
  - Surface/Identity
---
Purpose: Detects new scheduled tasks created for persistence.
```
index=windows EventCode=4698 earliest=-1h
| table _time host TaskName Author
```
