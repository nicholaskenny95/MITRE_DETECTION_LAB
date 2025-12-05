---
tags:
  - ATTACK/ResourceDevelopment
  - Telemetry/Sysmon
  - Surface/File
  - Surface/Process
---
Purpose: Highlights compressed toolkits or payload packages extracted to disk.
```
index=sysmon EventCode=11 earliest=-1h
| search TargetFilename="*.zip" OR TargetFilename="*.7z" OR TargetFilename="*.rar"
| table _time host Image TargetFilename User
```