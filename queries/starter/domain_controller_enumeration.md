---
tags:
  - ATTACK/Discovery
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/Network
---
Purpose: Detects enumeration of domain controllers or domain trusts.
```
index=sysmon EventCode=1 earliest=-1h
| search CommandLine="*nltest*" OR CommandLine="*/dclist*" OR CommandLine="*/domain_trusts*"
| table _time host Image CommandLine User
```
