---
tags:
  - ATTACK/Exfiltration
  - Telemetry/Sysmon
  - Surface/Network
  - Surface/Process
---
Purpose: Highlights outbound connections to external IPs that may represent data transfer or exfiltration activity.
```
index=sysmon EventCode=3 earliest=-1h
| search DestinationIp!="10.10.*"
| table _time host Image DestinationIp DestinationPort
```
