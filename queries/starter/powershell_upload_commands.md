---
tags:
  - ATTACK/Exfiltration
  - Telemetry/PowerShell
  - Surface/Network
  - Surface/Process
---
Purpose: Detects PowerShell commands that perform HTTP uploads or POST requests.
```
index=powershell earliest=-1h
| search ScriptBlockText="*Invoke-WebRequest*" AND ScriptBlockText="*POST*"
       OR ScriptBlockText="*Invoke-RestMethod*"
| table _time host User ScriptBlockText
```
