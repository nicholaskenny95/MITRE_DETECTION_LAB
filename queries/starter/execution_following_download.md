---
tags:
  - ATTACK/InitialAccess
  - Telemetry/Sysmon
  - Surface/Network
  - Surface/Process
---
Purpose: Highlights external downloads that commonly precede execution.
```
index=sysmon EventCode=3 earliest=-1h
| search DestinationIp!="10.10.*"
| join host [_internal]
```


