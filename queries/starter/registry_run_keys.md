---
tags:
  - ATTACK/Persistence
  - Telemetry/Sysmon
  - Surface/Registry
  - Surface/Process
---
Purpose: Detects persistence through autorun registry keys.
```
index=sysmon EventCode=13 earliest=-1h
| search registry_key_path="*\Run*" OR registry_key_path="*\RunOnce*" 
| table _time host Image registry_key_path Details User
```