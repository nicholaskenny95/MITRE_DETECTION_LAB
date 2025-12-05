---
tags:
  - ATTACK/Persistence
  - Telemetry/WindowsEvent
  - Surface/Process
  - Surface/Identity
  - Surface/Registry
---
Purpose: Monitors for potential malicious service installs.
```
index=windows EventCode=4697 earliest=-1h
| table _time host ServiceName ServiceFileName Account_Name
```
