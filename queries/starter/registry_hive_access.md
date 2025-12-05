---
tags:
  - ATTACK/CredentialAccess
  - Telemetry/Sysmon
  - Surface/Registry
  - Surface/Process
  - Surface/Identity
---
Purpose: Detects attempts to read or export credential-related registry hives.
```
index=sysmon EventCode=13 earliest=-1h
| search registry_key_path="*\SAM" OR registry_key_path="*\SYSTEM" OR registry_key_path="*\SECURITY"
| table _time host Image registry_key_path Details User
```
