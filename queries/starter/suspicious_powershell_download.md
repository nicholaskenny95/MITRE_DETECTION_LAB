---
tags:
  - ATTACK/ResourceDevelopment
  - Telemetry/PowerShell
  - Surface/Network
  - Surface/Process
---
Purpose: Detects PowerShell-based download commands commonly used for staging.
```
index=powershell earliest=-1h
| search ScriptBlockText="*Invoke-WebRequest*" OR ScriptBlockText="*curl*" OR ScriptBlockText="*wget*"
| table _time host User ScriptBlockText
```
