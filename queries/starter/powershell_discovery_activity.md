---
tags:
  - ATTACK/Discovery
  - Telemetry/PowerShell
  - Surface/Process
  - Surface/Network
---
Purpose: Identifies PowerShell-based domain and system enumeration.
```
index=powershell earliest=-1h
| search ScriptBlockText="*Get-AD*" OR ScriptBlockText="*Get-WmiObject*" 
        OR ScriptBlockText="*Get-NetIPAddress*" OR ScriptBlockText="*Get-Process*"
| table _time host User ScriptBlockText
```
