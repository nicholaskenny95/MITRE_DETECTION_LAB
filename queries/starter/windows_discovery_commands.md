---
tags:
  - ATTACK/Discovery
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/Network
---
Purpose: Detects most built-in Windows discovery commands.
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*\net.exe" OR Image="*\nltest.exe" OR Image="*\ipconfig.exe" 
        OR Image="*\wmic.exe" OR Image="*\whoami.exe"
| table _time host Image ParentImage CommandLine User
```
