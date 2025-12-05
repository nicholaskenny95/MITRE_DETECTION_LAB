---
tags:
  - ATTACK/CredentialAccess
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/Identity
---
Purpose: Identifies tools commonly used for credential theft.
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*procdump*" OR Image="*mimikatz*" OR CommandLine="*lsass*"
| table _time host Image ParentImage CommandLine User
```
