---
tags:
  - ATTACK/CredentialAccess
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/Identity
---
Purpose: Detects attempts to access LSASS memory (high-fidelity indicator of dumping).
```
index=sysmon EventCode=10 earliest=-1h
| search TargetImage="*lsass.exe*"
| table _time host SourceImage TargetImage GrantedAccess
```
