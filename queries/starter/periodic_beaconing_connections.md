---
tags:
  - ATTACK/CommandAndControl
  - Telemetry/Sysmon
  - Surface/Network
  - Surface/Process
---
Purpose: Detects repeated outbound network connections occurring at regular intervals.
```
index=sysmon EventCode=3 earliest=-1h
| bin _time span=1m
| stats count by _time, DestinationIp, DestinationPort
| where count > 1
```
