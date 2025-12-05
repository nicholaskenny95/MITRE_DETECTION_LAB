---
tags:
  - ATTACK/Collection
  - Telemetry/Sysmon
  - Surface/File
  - Surface/Process
---
Purpose: Detects creation of compressed archives that may indicate data staging or packaging of tooling.
```
index=sysmon EventCode=11 earliest=-1h
| search TargetFilename="*.zip" OR TargetFilename="*.7z" OR TargetFilename="*.rar"
| table _time host Image TargetFilename User
```
