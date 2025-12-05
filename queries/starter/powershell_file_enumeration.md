---
tags:
  - ATTACK/Collection
  - Telemetry/PowerShell
  - Surface/File
  - Surface/Process
---
Purpose: Identifies PowerShell commands that enumerate, read, or copy files.
```
index=powershell earliest=-1h
| search ScriptBlockText="*Get-ChildItem*" OR ScriptBlockText="*Copy-Item*" 
        OR ScriptBlockText="*Get-Content*"
| table _time host User ScriptBlockText
```
