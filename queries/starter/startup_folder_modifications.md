---
tags:
  - ATTACK/Persistence
  - Telemetry/Sysmon
  - Surface/File
  - Surface/Process
---
Purpose: Identifies files placed in user startup locations.
```
index=sysmon EventCode=11 earliest=-1h
| search TargetFilename="*\Startup\*" 
        OR TargetFilename="*AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup*"
| table _time host Image TargetFilename User
```
