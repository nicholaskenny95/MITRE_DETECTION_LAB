---
tags:
  - ATTACK/CommandAndControl
  - Telemetry/Sysmon
  - Surface/Network
  - Surface/Process
---
Purpose: Identifies outbound network connections to non-lab IP ranges.
```
index=sysmon EventCode=3 earliest=-1h
| search DestinationIp!="10.10.*"
| table _time host Image DestinationIp DestinationPort
```
