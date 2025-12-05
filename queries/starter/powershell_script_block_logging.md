---
tags:
  - ATTACK/Execution
  - Telemetry/PowerShell
  - Surface/Process
---
Purpose: Reveals the actual PowerShell content, including malicious logic, even when obfuscated on the command line.
```
index=powershell EventCode=4104 earliest=-1h
| table _time host User ScriptBlockText
```

