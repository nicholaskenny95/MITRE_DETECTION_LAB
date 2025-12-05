---
tags:
  - ATTACK/LateralMovement
  - Telemetry/Sysmon
  - Surface/Network
  - Surface/Process
---
Purpose: Identifies remote protocols commonly used for lateral movement.
```
index=sysmon EventCode=3 earliest=-1h
| search DestinationPort=445 OR DestinationPort=3389 
        OR DestinationPort=5985 OR DestinationPort=5986
| table _time host Image DestinationIp DestinationPort
```
