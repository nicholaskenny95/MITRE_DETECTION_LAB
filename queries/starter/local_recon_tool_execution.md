---
tags:
  - ATTACK/Reconnaissance
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/Network
---
Purpose: Detects execution of local enumeration or scanning utilities commonly used during reconnaissance.
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*nmap*" OR Image="*masscan*" OR Image="*netcat*"
        OR CommandLine="*scan*" OR CommandLine="*Test-NetConnection*"
| table _time host Image ParentImage CommandLine User
```
