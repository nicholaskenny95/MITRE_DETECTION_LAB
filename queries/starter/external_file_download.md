---
tags:
  - ATTACK/ResourceDevelopment
  - Telemetry/Sysmon
  - Surface/Network
  - Surface/Process
  - Telemetry/WindowsEvent
---
Purpose: Detect outbound connections to non-lab IPs, often used to fetch tooling.
```
index=sysmon EventCode=3 earliest=-1h
| search DestinationIp!="10.10.*"
| table _time host Image DestinationIp DestinationPort
```
