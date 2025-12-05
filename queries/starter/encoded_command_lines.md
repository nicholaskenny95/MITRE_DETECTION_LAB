---
tags:
  - ATTACK/Execution
  - Telemetry/Sysmon
  - Surface/Process
---
Purpose: Targets suspicious use of encoded payloads with PowerShell or CMD.
```
index=sysmon EventCode=1 earliest=-1h
| search CommandLine="*-enc*" OR CommandLine="*EncodedCommand*" OR CommandLine="*Base64*"
| table _time host Image ParentImage CommandLine User
```
