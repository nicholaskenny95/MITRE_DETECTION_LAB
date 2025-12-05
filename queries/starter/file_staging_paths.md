---
tags:
  - ATTACK/ResourceDevelopment
  - Telemetry/Sysmon
  - Surface/File
  - Surface/Process
---
Purpose: Identifies tool staging in common download locations.
```
index=sysmon EventCode=11 earliest=-1h
| search TargetFilename="*\Downloads\*" OR TargetFilename="*\Temp\*"
| table _time host Image TargetFilename User
```
