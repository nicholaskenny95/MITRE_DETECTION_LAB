---
tags:
  - ATTACK/Execution
  - Telemetry/Sysmon
  - Surface/Process
---
Purpose: Shows the main execution engines often abused by attackers.
```
index=sysmon EventCode=1 earliest=-30m
| search Image="*powershell.exe*" OR Image="*cmd.exe*" OR Image="*wscript.exe*" 
        OR Image="*cscript.exe*" OR Image="*mshta.exe*" OR Image="*rundll32.exe*"
| table _time host Image ParentImage CommandLine User
```

