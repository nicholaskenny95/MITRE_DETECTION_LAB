---
tags:
  - ATTACK/Collection
  - Telemetry/Sysmon
  - Surface/File
  - Surface/Process
---
Purpose: Identifies access to common user-data directories often targeted for collection or staging prior to exfiltration.
```
index=sysmon EventCode=11 earliest=-1h
| search TargetFilename="*Documents*" OR TargetFilename="*Desktop*" OR TargetFilename="*Downloads*"
| table _time host Image TargetFilename User
```
