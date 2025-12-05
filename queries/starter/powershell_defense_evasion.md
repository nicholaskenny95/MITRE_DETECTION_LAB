---
tags:
  - ATTACK/DefenseEvasion
  - Telemetry/PowerShell
  - Surface/Process
  - Surface/Registry
---
Purpose: Detects attempts to disable Defender or security scanning.
```
index=powershell earliest=-1h
| search ScriptBlockText="*Set-MpPreference*" 
        OR ScriptBlockText="*DisableRealtimeMonitoring*"
        OR ScriptBlockText="*Add-MpPreference*"
| table _time host User ScriptBlockText
```
