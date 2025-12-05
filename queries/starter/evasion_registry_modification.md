---
tags:
  - ATTACK/DefenseEvasion
  - Telemetry/Sysmon
  - Surface/Registry
  - Surface/Process
---
Purpose: Detects defender or logging policy tampering.
```
index=sysmon EventCode=13 earliest=-1h
| search registry_key_path="*Windows Defender*" 
        OR registry_key_path="*\EventLog\*"
| table _time host Image registry_key_path Details User
```
