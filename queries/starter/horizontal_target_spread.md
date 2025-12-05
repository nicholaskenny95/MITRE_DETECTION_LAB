---
tags:
  - ATTACK/Reconnaissance
  - Telemetry/Sysmon
  - Surface/Network
  - Surface/Process
---
Purpose: Detects hosts that initiate connections to an unusually large number of internal targets.
```
index=sysmon EventCode=3 earliest=-1h
| stats dc(DestinationIp) as unique_targets by host, Image
| where unique_targets > 10
```
