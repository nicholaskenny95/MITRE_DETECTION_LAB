---
tags:
  - ATTACK/LateralMovement
  - Telemetry/WindowsEvent
  - Surface/Identity
  - Surface/Network
---
Purpose: Finds successful or failed remote logons (LogonType 3 and 10).
```
index=windows earliest=-1h
| search EventCode=4624 OR EventCode=4625
| table _time host Account_Name Logon_Type IpAddress
```
