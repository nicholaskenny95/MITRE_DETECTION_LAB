---
tags:
  - ATTACK/CommandAndControl
  - Telemetry/PowerShell
  - Surface/Network
  - Surface/Process
---
Purpose: Detects PowerShell scripts establishing outbound web callbacks consistent with C2 communication.
```
index=powershell earliest=-1h
| search ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*Invoke-RestMethod*"
| table _time host User ScriptBlockText
```
