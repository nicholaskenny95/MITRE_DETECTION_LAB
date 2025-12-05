---
tags:
  - ATTACK/InitialAccess
  - Telemetry/WindowsEvent
  - Surface/Identity
  - Surface/Network
---
Purpose: Logs successful logons which may indicate stolen credential use.
```
index=windows EventCode=4624 earliest=-1h
| table _time host Account_Name Logon_Type IpAddress
```

