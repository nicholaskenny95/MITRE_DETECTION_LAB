---
tags:
  - ATTACK/Impact
  - Telemetry/Sysmon
  - Surface/File
  - Surface/Process
---
Purpose: Detects creation of file extensions commonly associated with ransomware encryption.
```
index=sysmon EventCode=11 earliest=-1h
| search TargetFilename="*.locked" OR TargetFilename="*.encrypted" OR TargetFilename="*.enc"
| table _time host Image TargetFilename User
```
