---
tags:
  - Index
---
# Tag Registry

This registry defines the complete, approved tag set for the repository.  
Only the tags listed below should be used.

---

# 1. Technique Tags  
Used to connect tactic files, query files, and reports for the same MITRE technique.

Format: `Technique/<ID>`

Examples:
- Technique/T1059
- Technique/T1003
- Technique/T1087
- Technique/T1046

---

# 2. MITRE ATT&CK Tactic Tags  
Used only in `/tactics/`.

Format: `ATTACK/<Tactic>`

- ATTACK/Reconnaissance
- ATTACK/Resource_Development
- ATTACK/Initial_Access
- ATTACK/Execution
- ATTACK/Persistence
- ATTACK/Privilege_Escalation
- ATTACK/Defense_Evasion
- ATTACK/Credential_Access
- ATTACK/Discovery
- ATTACK/Lateral_Movement
- ATTACK/Collection
- ATTACK/Command_and_Control
- ATTACK/Exfiltration
- ATTACK/Impact

---

# 3. Surface Tags  
Used in tactics and reports to describe visibility domains.

Format: `Surface/<Domain>`

- Surface/Process
- Surface/Network
- Surface/File
- Surface/Registry
- Surface/Identity

---

# 4. Telemetry Source Tags  
Used only when the detection or analysis uses that telemetry source.

- Telemetry/Sysmon
- Telemetry/PowerShell
- Telemetry/WindowsEvent
- Telemetry/Suricata
- Telemetry/pfSense

---
