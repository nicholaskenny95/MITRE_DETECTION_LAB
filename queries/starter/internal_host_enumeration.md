---
tags:
  - ATTACK/Discovery
  - Telemetry/Sysmon
  - Surface/Network
  - Surface/Process
---
Purpose: Captures processes querying multiple internal hosts.
```
index=sysmon EventCode=3 earliest=-1h
| stats dc(DestinationIp) as unique_targets by host, Image
| where unique_targets > 5
```
