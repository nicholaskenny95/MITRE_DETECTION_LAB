---
tags:
  - ATTACK/Impact
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/File
---
Purpose: Detects attempts to delete or modify system shadow copies, often associated with ransomware or destructive activity.
```
index=sysmon EventCode=1 earliest=-1h
| search CommandLine="*vssadmin*" AND CommandLine="*delete*"
        OR CommandLine="*wmic shadowcopy*"
| table _time host Image ParentImage CommandLine User
```
