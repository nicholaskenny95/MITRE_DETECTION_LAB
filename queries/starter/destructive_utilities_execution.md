---
tags:
  - ATTACK/Impact
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/File
---
Purpose: Identifies execution of built-in Windows utilities capable of wiping, encrypting, or removing data.
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*cipher.exe*" OR Image="*format.exe*" OR CommandLine="*Remove-Item*"
| table _time host Image ParentImage CommandLine User
```
