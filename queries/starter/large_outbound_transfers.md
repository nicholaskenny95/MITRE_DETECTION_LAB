---
tags:
  - ATTACK/Exfiltration
  - Telemetry/Sysmon
  - Surface/Network
  - Surface/Process
---
Purpose: Identifies significant outbound data flows that may indicate exfiltration attempts.
```
index=sysmon EventCode=3 earliest=-1h
| stats count by DestinationIp DestinationPort Image host
| sort - count
```
