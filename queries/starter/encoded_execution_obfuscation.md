---
tags:
  - ATTACK/DefenseEvasion
  - Telemetry/Sysmon
  - Surface/Process
---
Purpose: Flags encoding/obfuscation commonly used to hide malicious commands. 
```
index=sysmon EventCode=1 earliest=-1h
| search CommandLine="*-enc*" OR CommandLine="*Base64*" OR CommandLine="*Hidden*"
| table _time host Image ParentImage CommandLine User
```
