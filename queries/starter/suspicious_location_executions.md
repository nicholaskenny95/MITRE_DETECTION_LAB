---
tags:
  - ATTACK/Execution
  - Telemetry/Sysmon
  - Surface/Process
  - Surface/File
---
Purpose: Identifies binaries or scripts launching from common attacker staging paths.
```
index=sysmon EventCode=1 earliest=-1h
| search Image="*\Temp\*" OR Image="*\AppData\*" OR Image="*\Downloads\*"
| table _time host Image ParentImage CommandLine User
```

