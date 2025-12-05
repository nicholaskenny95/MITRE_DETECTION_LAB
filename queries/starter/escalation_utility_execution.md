---
tags:
  - ATTACK/PrivilegeEscalation
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/Identity
---
Purpose: Identifies common tools and methods used to elevate privileges.
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*psexec.exe*" OR Image="*runas.exe*" OR CommandLine="*bypass*" 
| table _time host Image ParentImage CommandLine User
```
