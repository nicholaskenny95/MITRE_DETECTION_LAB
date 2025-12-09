---
tags:
  - ATTACK/PrivilegeEscalation
  - Surface/Process
  - Surface/Registry
  - Surface/File
  - Surface/Identity
  - Telemetry/Sysmon
  - Telemetry/WindowsEvent
---
# Privilege Escalation (TA0004)

Privilege Escalation involves techniques that adversaries use to gain higher-level permissions on a system or network. While they may start with limited access, they often need elevated privileges to fully carry out their objectives. This can include exploiting system weaknesses, misconfigurations, or vulnerabilities to achieve access such as system/root level, local administrator, or specialized accounts with admin-like access. These techniques often overlap with Persistence, as elevated access may be used to maintain foothold on the system.

---

## Common Sub-Techniques

**T1055 – Process Injection**  
Injecting into privileged processes to inherit permissions.

**T1548 – Abuse Elevation Control Mechanisms**  
UAC bypass, token manipulation, or misuse of “runas” functionality.

**T1543 – Create or Modify System Process**  
Leveraging services or scheduled tasks configured with elevated permissions.

---

## Expected Surfaces

**Process** – elevated processes, unusual parent/child chains  
**Registry** – modified services or configuration keys enabling escalation  
**File System** – replacement of service executables or DLL hijacking  
**Identity** – logons with elevated privileges or special tokens

---

## What to Look For

### Process Indicators
- PowerShell or CMD running with elevated tokens unexpectedly  
- Low-privilege processes spawning high-privilege children  
- `runas.exe`, `psexec.exe`, or UAC bypass tools appearing  
- Mismatched integrity levels (medium → high transitions)

### Registry Indicators
- Changes to service configuration paths (`ImagePath`)  
- Modifications under:
  - `HKLM\SYSTEM\CurrentControlSet\Services\*`
  - `HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`

### Identity Indicators
- EventCode **4672** (special privileges assigned)  
- Administrative logons from non-admin endpoints  
- Privileged logons occurring shortly before suspicious process activity

### Behavioral Patterns
- Registry/service modification → elevated process starts  
- Process injection followed by unexpected network traffic  
- Rapid privilege change followed by credential access or lateral movement

---

## Starter Splunk Queries

- [High-Privilege Token Assignment](priveleged_token_assignment.md)
- [Suspicious Elevated Process Execution](suspicious_process_execution.md)
- [Service Configuration Modification](service_configuration_modification.md)
- [Execution of Known Escalation Utilities](escalation_utility_execution.md)

---

## Enhancements

### Telemetry Notes
- EventCode **4672** is reliable for privilege assignment detection.  
- Sysmon does not natively log token manipulation—look for indirect signals (parent/child chain anomalies, integrity jumps).  
- Service modification detection relies on EventCodes 12/13; ensure registry monitoring is active.

### Detection Engineering Tips
- Pair elevated process creation with preceding registry modifications for high-confidence escalation detection.  
- Track which binaries normally run elevated and alert on deviations.  
- Watch for privilege escalation immediately followed by credential access or lateral movement.

---

