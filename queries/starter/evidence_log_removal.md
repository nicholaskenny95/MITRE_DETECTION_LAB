---
tags:
  - ATTACK/DefenseEvasion
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/File
---
Purpose: Identifies attempts to clear Windows event logs.
```
index=sysmon EventCode=1 earliest=-1h
| search CommandLine="*wevtutil*" OR CommandLine="*Clear-EventLog*"
| table _time host Image CommandLine User
```
