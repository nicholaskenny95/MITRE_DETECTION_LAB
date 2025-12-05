---
tags:
  - ATTACK/LateralMovement
  - Telemetry/WindowsEvent
  - Surface/Network
  - Surface/Identity
---
Purpose: Indicates enumeration or movement using ADMIN$ or similar administrative shares.
```
index=windows EventCode=5140 earliest=-1h
| search Share_Name="\\*ADMIN$" OR Share_Name="\\*C$" OR Share_Name="\\*IPC$"
| table _time host Share_Name Relative_Target_Name Account_Name
```
