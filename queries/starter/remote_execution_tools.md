---
tags:
  - ATTACK/LateralMovement
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/Network
---
Purpose: Detects common remote execution utilities and PowerShell remoting.
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*psexec*" OR Image="*wmic.exe*" 
        OR CommandLine="*Invoke-Command*" OR CommandLine="*Enter-PSSession*"
| table _time host Image ParentImage CommandLine User
```
